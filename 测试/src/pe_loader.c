// pe_loader.c -- 手写「内存 PE 加载器」(教学件)
//   演示: 把原始 PE 文件字节在内存里展开并执行 -- 不经过 LoadLibrary, 不经过系统加载器。
//   步骤: 拷贝头 -> 拷区段 -> 应用重定位(.reloc) -> 用 INT 表修 IAT -> 设区段保护 -> 调 DllMain -> 调导出
//   仅用于加载良性 PE; 不含任何反调试/反沙箱/混淆等免杀特性。
// 用法: pe_loader.exe [某个PE路径]   默认 bin\payload_dll.dll
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv)
{
    const char* path = (argc > 1) ? argv[1] : "bin\\payload_dll.dll";

    /* ---------- 0. 读入原始 PE 字节 ---------- */
    FILE* f = fopen(path, "rb");
    if (!f) { printf("[!] fopen(%s) failed: %lu\n", path, GetLastError()); return 1; }
    fseek(f, 0, SEEK_END); long fsz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* buf = (unsigned char*)malloc(fsz);
    if (fread(buf, 1, fsz, f) != (size_t)fsz) { printf("[!] read failed\n"); return 1; }
    fclose(f);
    printf("[*] file  : %s (%ld bytes)\n", path, fsz);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { printf("[!] not a PE (bad MZ)\n"); return 1; }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { printf("[!] not a PE (bad NT)\n"); return 1; }

    ULONGLONG prefBase = nt->OptionalHeader.ImageBase;
    DWORD sizeOfImage   = nt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    DWORD entryRva      = nt->OptionalHeader.AddressOfEntryPoint;
    printf("[*] prefer base   = 0x%llX\n", prefBase);
    printf("[*] SizeOfImage   = 0x%X   SizeOfHeaders = 0x%X   EntryRVA = 0x%X\n",
           sizeOfImage, sizeOfHeaders, entryRva);

    /* ---------- 1. 分配内存 (故意不落在首选基址, 以演示重定位) ---------- */
    BYTE* img = (BYTE*)VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!img) { printf("[!] VirtualAlloc failed: %lu\n", GetLastError()); return 1; }
    ULONGLONG delta = (ULONGLONG)img - prefBase;
    printf("[*] mapped base   = %p   (delta = 0x%llX)\n", img, delta);

    /* ---------- 2. 拷贝 PE 头 ---------- */
    memcpy(img, buf, sizeOfHeaders);

    /* ---------- 3. 拷贝各区段 ---------- */
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    printf("[*] sections:\n");
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData)
            memcpy(img + sec[i].VirtualAddress, buf + sec[i].PointerToRawData, sec[i].SizeOfRawData);
        printf("    %-8s VA=0x%-6X vsize=0x%-6X raw=0x%X\n",
               sec[i].Name, sec[i].VirtualAddress, sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
    }

    /* ---------- 4. 应用基址重定位 ---------- */
    unsigned long relocCount = 0;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY rd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rd.Size) {
            IMAGE_BASE_RELOCATION* rel = (IMAGE_BASE_RELOCATION*)(img + rd.VirtualAddress);
            BYTE* relEnd = (BYTE*)rel + rd.Size;
            while ((BYTE*)rel < relEnd && rel->SizeOfBlock) {
                DWORD n = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* e = (WORD*)((BYTE*)rel + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD j = 0; j < n; j++) {
                    int type = e[j] >> 12;
                    int off  = e[j] & 0x0FFF;
                    if (type == IMAGE_REL_BASED_DIR64) {          // x64
                        ULONGLONG* p = (ULONGLONG*)(img + rel->VirtualAddress + off);
                        *p += delta;
                        relocCount++;
                    }
                }
                rel = (IMAGE_BASE_RELOCATION*)((BYTE*)rel + rel->SizeOfBlock);
            }
        }
    }
    printf("[*] relocations applied = %lu\n", relocCount);

    /* ---------- 5. 用 INT 表修复 IAT ---------- */
    IMAGE_DATA_DIRECTORY id = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (id.Size) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(img + id.VirtualAddress);
        printf("[*] imports:\n");
        for (; imp->Name; imp++) {
            char* dll = (char*)(img + imp->Name);
            HMODULE h = LoadLibraryA(dll);
            printf("    %s -> %p\n", dll, (void*)h);
            if (!h) continue;

            /* 优先用 INT 表 (OriginalFirstThunk), 否则退回 IAT 表 */
            ULONGLONG* ref = (ULONGLONG*)(img + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                                         : imp->FirstThunk));
            ULONGLONG* iat = (ULONGLONG*)(img + imp->FirstThunk);
            for (; *ref; ref++, iat++) {
                if (*ref & IMAGE_ORDINAL_FLAG64) {
                    *iat = (ULONGLONG)GetProcAddress(h, (LPCSTR)(*ref & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME* bn = (IMAGE_IMPORT_BY_NAME*)(img + *ref);
                    *iat = (ULONGLONG)GetProcAddress(h, (char*)bn->Name);
                }
            }
        }
    }

    /* ---------- 6. 按区段特性设置内存保护 ---------- */
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD ch = sec[i].Characteristics, old;
        DWORD prot = PAGE_READONLY;
        if (ch & IMAGE_SCN_MEM_EXECUTE)
            prot = (ch & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        VirtualProtect(img + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, prot, &old);
    }

    /* ---------- 7. 若是 DLL, 调 DllMain ---------- */
    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        typedef BOOL (WINAPI *DllMain_t)(HMODULE, DWORD, LPVOID);
        DllMain_t dmain = (DllMain_t)(img + entryRva);
        printf("[*] DllMain @ %p ...\n", (void*)dmain);
        printf("    returned %d\n", dmain((HMODULE)img, DLL_PROCESS_ATTACH, NULL));
    }

    /* ---------- 8. 解析导出表, 调 RunMe ---------- */
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ed.Size) {
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(img + ed.VirtualAddress);
        DWORD* nameRva = (DWORD*)(img + exp->AddressOfNames);
        WORD*  nameOrd = (WORD*)(img + exp->AddressOfNameOrdinals);
        DWORD* funcRva = (DWORD*)(img + exp->AddressOfFunctions);
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            char* nm = (char*)(img + nameRva[i]);
            if (strcmp(nm, "RunMe") == 0) {
                void (*fn)(void) = (void(*)(void))(img + funcRva[nameOrd[i]]);
                printf("[*] calling export %s @ %p ...\n", nm, (void*)fn);
                fn();
                printf("[+] export returned (sleeping 5s so the window stays visible)\n");
                Sleep(5000);
                break;
            }
        }
    }

    printf("[+] done (manual map succeeded)\n");
    return 0;
}
