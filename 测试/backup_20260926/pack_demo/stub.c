// stub.c -- 壳（CodeLoader + PeLoader 合体, 教学件）
//   从自身 RCDATA 资源取出加密的 payload -> XOR 解密 -> 内存展开 PE -> 调用其 DllMain/导出。
//   对标看雪《免杀壳》的 "CodeLoader 解密 + PeLoader 内存加载" —— 但【不含任何对抗特性】
//   (无反调试 / 反沙箱 / 延时 / 入口点模糊 / 面向特定杀软的调优)。
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_RES_ID 100
#define XOR_KEY        0x5A

// ---------- PeLoader: 内存展开并执行一个 DLL ----------
static int map_and_run(unsigned char* buf, unsigned long fsz)
{
    (void)fsz;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { printf("[stub] bad MZ\n"); return 1; }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { printf("[stub] bad NT\n"); return 1; }

    ULONGLONG prefBase = nt->OptionalHeader.ImageBase;
    DWORD sizeOfImage  = nt->OptionalHeader.SizeOfImage;
    DWORD sizeOfHdrs   = nt->OptionalHeader.SizeOfHeaders;
    DWORD entryRva     = nt->OptionalHeader.AddressOfEntryPoint;
    printf("[stub] payload ImageBase=0x%llX SizeOfImage=0x%X EntryRVA=0x%X\n",
           prefBase, sizeOfImage, entryRva);

    BYTE* img = (BYTE*)VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!img) { printf("[stub] VirtualAlloc failed %lu\n", GetLastError()); return 1; }
    ULONGLONG delta = (ULONGLONG)img - prefBase;
    printf("[stub] mapped @ %p (delta=0x%llX)\n", img, delta);
    memcpy(img, buf, sizeOfHdrs);

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (sec[i].SizeOfRawData)
            memcpy(img + sec[i].VirtualAddress, buf + sec[i].PointerToRawData, sec[i].SizeOfRawData);

    unsigned long relocCount = 0;
    if (delta) {
        IMAGE_DATA_DIRECTORY rd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rd.Size) {
            IMAGE_BASE_RELOCATION* rel = (IMAGE_BASE_RELOCATION*)(img + rd.VirtualAddress);
            BYTE* end = (BYTE*)rel + rd.Size;
            while ((BYTE*)rel < end && rel->SizeOfBlock) {
                DWORD n = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* e = (WORD*)((BYTE*)rel + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD j = 0; j < n; j++)
                    if ((e[j] >> 12) == IMAGE_REL_BASED_DIR64) {
                        *(ULONGLONG*)(img + rel->VirtualAddress + (e[j] & 0x0FFF)) += delta;
                        relocCount++;
                    }
                rel = (IMAGE_BASE_RELOCATION*)((BYTE*)rel + rel->SizeOfBlock);
            }
        }
    }
    printf("[stub] relocations applied = %lu\n", relocCount);

    IMAGE_DATA_DIRECTORY id = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (id.Size) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(img + id.VirtualAddress);
        for (; imp->Name; imp++) {
            HMODULE h = LoadLibraryA((char*)(img + imp->Name));
            if (!h) continue;
            ULONGLONG* ref = (ULONGLONG*)(img + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                                                         : imp->FirstThunk));
            ULONGLONG* iat = (ULONGLONG*)(img + imp->FirstThunk);
            for (; *ref; ref++, iat++) {
                if (*ref & IMAGE_ORDINAL_FLAG64)
                    *iat = (ULONGLONG)GetProcAddress(h, (LPCSTR)(*ref & 0xFFFF));
                else {
                    IMAGE_IMPORT_BY_NAME* bn = (IMAGE_IMPORT_BY_NAME*)(img + *ref);
                    *iat = (ULONGLONG)GetProcAddress(h, (char*)bn->Name);
                }
            }
        }
    }
    printf("[stub] imports resolved\n");

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD ch = sec[i].Characteristics, old, prot = PAGE_READONLY;
        if (ch & IMAGE_SCN_MEM_EXECUTE) prot = (ch & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE) prot = PAGE_READWRITE;
        VirtualProtect(img + sec[i].VirtualAddress, sec[i].Misc.VirtualSize, prot, &old);
    }

    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        typedef BOOL (WINAPI *DllMain_t)(HMODULE, DWORD, LPVOID);
        printf("[stub] DllMain ret=%d\n", ((DllMain_t)(img + entryRva))((HMODULE)img, DLL_PROCESS_ATTACH, NULL));
    }

    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ed.Size) {
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(img + ed.VirtualAddress);
        DWORD* nr = (DWORD*)(img + exp->AddressOfNames);
        WORD*  no = (WORD*)(img + exp->AddressOfNameOrdinals);
        DWORD* fr = (DWORD*)(img + exp->AddressOfFunctions);
        for (DWORD i = 0; i < exp->NumberOfNames; i++)
            if (strcmp((char*)(img + nr[i]), "RunMe") == 0) {
                void (*fn)(void) = (void(*)(void))(img + fr[no[i]]);
                printf("[stub] calling export RunMe @ %p\n", (void*)fn);
                fn();
                break;
            }
    }
    return 0;
}

// ---------- CodeLoader: 取资源 -> 解密 -> 交给 PeLoader ----------
int main(void)
{
    HRSRC r = FindResourceA(NULL, MAKEINTRESOURCEA(PAYLOAD_RES_ID), RT_RCDATA);
    if (!r) { printf("[stub] payload resource not found (err=%lu)\n", GetLastError()); return 1; }
    DWORD sz = SizeofResource(NULL, r);
    HGLOBAL g = LoadResource(NULL, r);
    unsigned char* d = (unsigned char*)LockResource(g);
    printf("[stub] encrypted payload resource = %lu bytes\n", sz);

    unsigned char* pl = (unsigned char*)malloc(sz);
    for (DWORD i = 0; i < sz; i++) pl[i] = d[i] ^ XOR_KEY;
    printf("[stub] decrypted (XOR 0x%02X)\n", XOR_KEY);

    int ret = map_and_run(pl, sz);
    printf("[stub] payload finished\n");
    Sleep(5000);   // 让 payload 弹的窗口停留一下
    return ret;
}
