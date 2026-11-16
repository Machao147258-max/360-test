# 免杀远控 —— 工作目录

> 2026-10-04 整理。当前状态：**远控已成立、免杀未成立，火绒对照停在"点安装按钮"半步。**
>
> 🔖 **交接标记见 [`待续.md`](待续.md)**（停在哪 / 下次 4 步 / 未验证清单 / 状态快照）

## 从哪看起

| 想了解 | 看哪里 |
|---|---|
| 全过程记录（结论 / 证据 / 踩坑 / 待办） | `工程日志.md`（§一 ~ §十五） |
| 工程本体（架构 / 构建 / 运行 / 实测坑清单 / 当前状态） | `lab-c2\README.md` |
| 证据与靶机脚本索引 | `lab-c2\runs\README.md` |
| 源码 | `lab-c2\implant\`（beacon / loader / syscall / ekko + 生成物） |
| 服务端侧工具 | `lab-c2\tools\`（enc / setcfg / c2ctl / selftest / smoketest / run_beacon_test …） |
| 安装包 | `lab-c2\downloads\`（火绒 x64 6.0.12.1） |
| 旧副本与无用大文件 | `_archive\` |

## 一句话结论

- **远控：成立。** 靶机 `windows测试`（`192.168.253.140`）上运行的是**内存反射映射**的信标
  （磁盘无解密 PE），拿到的是**高完整性管理员令牌**（`SeDebugPrivilege` 等已启用）；
  10 分钟浸泡零掉线，重启后由计划任务自行恢复；双实例按会话隔离、互不顶替。
- **免杀：未成立。** Defender 行为引擎判定 `Trojan:Win32/Bearfoos.B!ml`，曾在上线 **69 秒**后
  终结进程；静态判定随构建漂移（`Sabsik.EN.A!ml` / `Wacatac.H!ml` / 干净都出现过）。
- **火绒对照：半程。** x64 安装包已推进靶机、安装向导已在桌面打开；但 VIX 按键注入被宿主权限
  拒绝、UIA 看不到自绘按钮、合成鼠标点击未生效 —— 只差人工点一下「極速安裝」。

## 两条容易被忽略的提醒

1. 迭代期给靶机加的 Defender 排除项 `C:\Users\Public` **仍在位**，最终验收前必须回滚：
   `Remove-MpPreference -ExclusionPath C:\Users\Public`
2. 所有靶机侧 bat 必须 **ASCII-only + 零参数 + CRLF**；`c2ctl.py results` 必须显式带 sid。
   （原因都在 `lab-c2\runs\README.md` 里，都是实测踩出来的。）
