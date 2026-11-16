# Windows x64 Shellcode 实验集

三个自包含的 Windows x64 shellcode + 完整工具链 + 分析报告。全部用**原生 MSVC 工具链**（`cl.exe` / `ml64.exe`）编译，从编译产物里抠出机器码，再独立加载执行验证。

## 目录结构

| 路径 | 内容 |
|---|---|
| `src/` | 源码：`shellcode.c`（C 版）、`calc_nf.asm`（汇编版）、`priv_sc.c`（令牌版，生成物） |
| `tools/` | 脚本：`gen_priv.py`、`extract.py`、`loader.py`、`loader_priv.py`、`token_privs.py` |
| `bin/` | 抠出的 shellcode：`shellcode.bin`、`shellcode_asm.bin`、`priv_sc.bin` |
| `build/` | 编译中间产物：`*.obj` / `*.exe` |
| `go*.bat` | 三条一键流水线 |
| `分析报告.md` | 完整分析报告（原理 + 反汇编 + 防御视角） |
| `backup_20260926/` | 整理前的原始快照 |

## 快速上手

```bat
go.bat        :: 变体 1  C 版        -> 弹 calc
go_asm.bat    :: 变体 2  汇编 null-free -> 弹 calc
go_priv.bat   :: 变体 3  令牌提权      -> 启用权限 (默认 SeDebugPrivilege)
go_priv.bat SeBackupPrivilege   :: 变体 3 可指定任意权限名
```

每条脚本自动完成：**编译 → 抠段 → 加载执行/验证**。

前置：VS Build Tools（含 `vcvars64.bat`，路径写在脚本里）；Python 需 `capstone`。

## 三个 shellcode

| 变体 | 源码 | 汇编器 | 大小 | 空字节 | 行为 |
|---|---|---|---|---|---|
| 1 | `src/shellcode.c` | `cl` | 209 B | 有 | 弹 calc |
| 2 | `src/calc_nf.asm` | `ml64` | 176 B | **无** | 弹 calc |
| 3 | `src/priv_sc.c` | `cl` | 618 B | 有 | 启用自身 `SeDebugPrivilege` |

## 原理速览

三个变体共享同一核心：**位置无关 + 不依赖导入表**。

- `gs:[0x60]` 取 PEB → 走 `InMemoryOrderModuleList` 找到 **kernel32** 基址；
- 解析导出表，对函数名做 **ROR13 哈希** 认 API（常量：`WinExec=0x0E8AFE98`、`LoadLibraryA=0xEC0E4E8E`、`GetProcAddress=0x7C0DFCAA`）；
- 字符串在栈上拼（C 用 `volatile` qword、汇编用 `movabs`/`[reg+disp8]`），避免 `.rdata` 重定位；
- 变体 3 升级为**引导链**：hash 拿 `LoadLibraryA`/`GetProcAddress` → 动态加载 `advapi32.dll` → 取令牌 API。

详细逐条反汇编剖析见 **`分析报告.md`**。

## 令牌权限枚举 / 翻转

```bat
python tools\token_privs.py                         :: 只列当前令牌的全部权限 + enabled/disabled
python tools\token_privs.py --enable  SeBackupPrivilege
python tools\token_privs.py --disable SeBackupPrivilege
```

打开自身进程令牌，`GetTokenInformation(TokenPrivileges)` + `LookupPrivilegeNameA`，列出现有权限及状态。`--enable/--disable` 用纯 Python（`AdjustTokenPrivileges`）直接翻转，作为对照——和 `priv_sc` shellcode 做的事一样，只是不经机器码。

**变体 3 可换权限名**：`gen_priv.py --priv <Name>` 生成对应 shellcode；`go_priv.bat [Name]` 一键走完「生成 → 编译 → 抠段 → 用整张权限表前后对比」。`loader_priv.py` 会打印**完整令牌权限表**，目标权限那行标 `<<==`，可直观看到 `disabled → ENABLED`。

## 说明

本人为安全教学/研究材料。calc 变体行为仅弹出计算器；令牌变体仅对**自身进程**启用其已持有的权限，不对他人系统操作。
