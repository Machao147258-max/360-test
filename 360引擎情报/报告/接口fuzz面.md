# 360 · 接口 fuzz 面（纯静态）

> 分类依据：出现 `RpcServerRegisterIf*`/`RpcServerUseProtseqEpW`/`NdrServerCall*` = **服务端**（接受调用 → fuzz 入口）；
> 只出现 `NdrClientCall2/NdrAsyncClientCall` = 客户端桩（是攻击工具，不是入口）。
> opnum 规模 = capstone 数出的 Ndr* 桩调用点数量（近似等于该接口的方法数）。

## 一、服务端接口（fuzz 入口，11 个）

| 模块 | 架构 | 服务端特征 | Ndr* 调用点 | 绑定串(宽/窄) |
|---|---|---|---|---|
| `Utils/NewIDView.exe` | x86 | NdrServer/RegisterIf | 9 (NdrClientCall2×4, NdrAsyncClientCall×5) | ncalrpc |
| `EntAdmin/360EntCloudData.dll` | x86 | NdrServer/RegisterIf | 1 (NdrClientCall2×1) | ncalrpc |
| `SoftMgr/360AdsOpt.dll` | x86 | NdrServer/RegisterIf | 1 (NdrClientCall2×1) | 运行时拼装 |
| `deepscan/ZhuDongFangYu.exe` | x86 | NdrServer/RegisterIf | 0 (-) | ncalrpc |
| `ipc/appd.dll` | x86 | NdrServer/RegisterIf | 0 (-) | ncacn_np, ncalrpc |
| `safemon/360cala3dc2.dll` | x86 | NdrServer/RegisterIf | 0 (-) | 运行时拼装 |
| `safemon/360TrayStub.dll` | x86 | NdrServer/RegisterIf | 0 (-) | ncalrpc |
| `safemon/libgravity.dll` | x86 | NdrServer/RegisterIf | 0 (-) | ncalrpc |
| `safemon/svcMonitor.dll` | x64 | NdrServer/RegisterIf | 0 (-) | 运行时拼装 |
| `safemon/wdswfsafe.exe` | x86 | NdrServer/RegisterIf | 0 (-) | ncalrpc |
| `safemon/WscReg.exe` | x86 | NdrServer/RegisterIf | 0 (-) | ncalrpc |

## 二、纯客户端桩（22 个，作为 fuzz 工具复用）

| 模块 | 架构 | Ndr* 调用点 |
|---|---|---|
| `SoftMgr/zpthdo.dll` | x86 | 2 |
| `360Util.dll` | x86 | 1 |
| `360Safe.exe` | x86 | 0 |
| `CrashReport.dll` | x86 | 0 |
| `deepscan/Cloudsec3.dll` | x86 | 0 |
| `ipc/360boxmain.exe` | x86 | 0 |
| `ipc/ipcService.dll` | x86 | 0 |
| `safemon/360GPMon.dll` | x86 | 0 |
| `safemon/360GPMon64.dll` | x64 | 0 |
| `safemon/360hipspopwnd.dll` | x86 | 0 |
| `safemon/360RDPNLAProtect64.dll` | x64 | 0 |
| `safemon/360realpro.exe` | x86 | 0 |
| `safemon/360scovec.dll` | x86 | 0 |
| `safemon/360scovec64.dll` | x64 | 0 |
| `safemon/360tray.exe` | x86 | 0 |
| `safemon/DlProc.dll` | x86 | 0 |
| `safemon/safemon.dll` | x86 | 0 |
| `safemon/SettingCenterCfg.dll` | x86 | 0 |
| `sweeper/360CleanHelper.exe` | x86 | 0 |
| `Utils/360AppCustomer.exe` | x86 | 0 |

## 三、能本地先做 / 必须 VM 才能做

**本地可做（不需要运行 360）**
- 从每个服务端模块的 MIDL 描述符（ProcFormatString/TypeFormatString）重建方法签名 → 生成 fuzz 模板
- 用调用点数量定 opnum 上界（本表已给），用客户端桩的参数压栈顺序推每个 opnum 的参数个数
- 设备 IOCTL：三码已知（0x222020/0x22204C/0x222094），可直接写 IOCTL fuzz 字典（in/out 长度矩阵）
- COM（53 个 CLSID）：静态枚举 CLSID → InprocServer32/LocalServer32 映射，产出自注册清单

**必须运行才可 fuzz（与"不安装"纪律冲突，需快照 VM）**
- 对 ncalrpc/命名管道端点发畸形调用（需要服务已注册）
- `\\.\360SelfProtection` 的 DeviceIoControl fuzz（需要驱动已加载）
- COM 对象的 CoCreateInstance + 方法 fuzz（需要已注册）

