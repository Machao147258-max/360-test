# lab-c2\runs —— 证据与靶机侧脚本

> 2026-10-04 整理。原则：**脚本与产出分开，按类型一目录一层**，文件名自解释。

## 靶机侧脚本的四条硬规矩（都是实测踩出来的）

| 规矩 | 原因（实测） |
|---|---|
| **ASCII-only** | 936 代码页的 cmd 会把 UTF-8 中文注释拆坏（`'1)' 不是内部命令`） |
| **零参数** | 经 `vmctl -script` 传参的 bat 一律 `exit 255`，且连第一行输出都不写 |
| **CRLF 行尾** | 我用编辑器写出的 bat 是 LF 行尾，cmd 会把 `REM` 注释当命令执行 |
| **路径硬编码** | 配合"零参数"，避免 `%1` 与引号解析问题 |

## 目录

| 目录 | 内容 | 数量 |
|---|---|---|
| `guest-scripts\` | 推到靶机执行的脚本 | 35 |
| `evidence\` | 靶机侧 dump / 判定结果（txt） | 49 |
| `screens\` | 截图（png） | 10 |
| `logs\` | 服务端 / 构建 / 追踪日志 | 13 |
| `loot\` | 从靶机取回的文件 | 1 |

## guest-scripts 分类

| 用途 | 脚本 |
|---|---|
| 探测与体检 | `reach.bat` `guest_probe.bat` `guest_probe.ps1` `health.bat` `desktop.bat` `verify.bat` `diag.bat` `diag2.bat` `huorong_check.bat` |
| 启动载荷 | `runldr.bat`（WMI 启动）`go.bat` `go2.bat` `hrgo.bat`（UIA 尝试）`hrmouse.bat` `hrmouse.ps1` `hmclick2.bat` `hmclick2.ps1`（鼠标输入实验）|
| 持久化 | `persist.bat` `persist_ldr.bat` `persist2.bat` |
| 清理 / 电源 | `killall.bat`（特权杀进程）`reboot.bat` `autologon.bat` |
| 杀软测量 | `avtest.bat`（Defender 按需扫描台）|
| 火绒安装（半程）| `hrinstall.bat` `hrinstall64.bat` `hrgui.bat` `hrdo.bat` `hrdo2.bat` `hrdo3.bat` `hrkeys.bat` `hrkeys2.bat` `hrclick2.bat` |
| 拉回对照 | `go2_from_guest.bat` `hrdo2_from_guest.bat` |

## 关键证据索引

| 文件 | 它证明了什么 |
|---|---|
| `evidence\diag.txt` | VIX guest 操作是**高完整性**（`Mandatory Label\High Mandatory Level`、`net session` 成功）|
| `evidence\launch_stable.txt`、`launch_v3.txt`、`launch_v5.txt` | WMI `Win32_Process::Create` 成功（`pid=… rc=0`）|
| `evidence\launch_ctrl.txt`、`launch_wmi2.txt` | 同一链路 `rc=8` —— 对照实验：连复制过去的 `cmd.exe` 也失败 |
| `evidence\persist2.txt` | 三条**免登录**自启任务建成（`lcs_onstart` / `lcs_1min` / `lcs_onlogon`）|
| `evidence\verify_pre.txt`、`verify_post.txt` | 重启前 boot=`17:10:05`、重启后 boot=`17:24:24`，载荷自行拉起 → **重启存活成立** |
| `logs\lcs_trace*.log` | 载荷分阶段追踪：门禁打分 → ntdll unhook → AMSI/ETW → 解密 → 反射式映射 → 起线程 |
| `logs\monitor.log` | 10 分钟浸泡全程 `live=1`；双实例抢槽期间 pid 在 2072/8040 之间交替 |
| `logs\c2.log` | 会话注册与任务往返（`ctl push #N` → `结果 #N`）|
| `evidence\avtest.txt` | Defender 按需扫描结果（含唯一一次 `found no threats`）|
| `evidence\huorong.txt`、`huorong2.txt` | 火绒**尚未装成**：无 `Sysdiag` 服务、无安装目录；安全中心仍是 Windows Defender |
| `screens\desktop_proof.png` | 桌面已登录 `vix` —— "能不能自己进桌面"的直接证据 |
| `screens\hr_state.png` | 火绒提示 **x64 系统要用对应安装包** → 之所以换 x64 包 |
| `screens\hr_gui.png` | 火绒 6.0 安装向导（自绘控件，UIA 树里没有 Button）|
| `screens\hr_after_click2.png` | `{TAB}` 把焦点送到标题栏 X → 弹出"确定要退出本次安装吗" |
| `screens\hr_clicked3.png` | 鼠标点击已注入（`CLICKED 513,406`）但界面无变化 → 这一步未成 |
