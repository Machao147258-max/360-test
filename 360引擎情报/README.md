# 360 引擎情报（给免杀线用的那一份）

> 来源：`C:\Users\20751\Desktop\360逆向`（360安全卫士极速版 v15.0.3.1058 解包载荷）
> 纪律：**全程静态 + 本地补环境（Unicorn）**，未安装、未运行、未加载驱动、样本未联网。
> 放置时间：2026-10-05 ｜ 合计 186 文件 / 13.9 MB

---

## 为什么放这儿

`待续.md` 里定的方向是：**先逆向火绒/360 的引擎本身 → 再按引擎实现细节做定向绕过**。
这份就是"360 引擎侧"的部分 —— 机制面已经打通，**判定内容（特征库/模型）还没打开**，而那是绕过的前提。

---

## 目录

| 目录 | 内容 |
|---|---|
| `报告/` | 360接口总表.md（含 **IOCTL 码表**）、检测引擎静态分析.md（1816 行）、签名信任机制排查.md（845 行）、API导出清单.md、接口清单.md、接口fuzz面.md、引擎模块画像 dossier.md、逆向报告、补环境执行记录 |
| `数据/` | `payload_pe_scan.tsv`（426 PE × 28 列）、`payload_sig.tsv`（签名全量）、`api_exports.tsv`（3202 条导出）、`certs/`（29 PFX + 46 链 + 清单）、fuzz 日志 |
| `工具/` | 43 个分析脚本（pe_scan / engine_recon / api_inventory / thirdparty_scan / db_container / iface_recon / iface_fuzz_recon / **emu_qex_typeid** / **fuzz_qex_v2** / keyhunt / anomaly_audit2 …） |
| `引擎模块/` | AVEI.dll、AVEngine.dll、360QVM.dll、qex.dll + `qex/*.enc`（3 个库）、heavygate.dll、cloudcom2.dll、BAPI.dll、`360SelfProtection.sys`、`hookport_win10.sys`、`cacert.dat`、`libaw.dat`（共 10.4 MB，**自测够用了**） |
| `归档_旧树/` | 之前那棵树的证书链（46 条，补到根）+《证书链与白名单》报告 |

---

## 对免杀**直接有用**的五类情报

### 1) 检测分三层，触发点都定位到了
| 层 | 组件 | 触发点/入口 |
|---|---|---|
| 静态特征 | `AVE/AVEngine.dll` + `AVEI.dll`（**微特征 `CalcMicroFeature`** + `.NET 索引 `CalcDotNetIndex`） | `CreateScanner → Scan/ScanFileEnum → AveQueryResult` |
| 静态-学习型 | `360QVM.dll`（内部代号 **Bole**） | `BoleInitialize/BoleFeaturesInitialize/BoleGetVersion` |
| 文档/OLE | `qex/qex.dll` | `testole_*` + 格式识别 `TypeEnum2Descript` |
| 行为 | `BAPI.dll` + `BAPIDRV*.sys`、`hookport`、`360qpesv`(minifilter)、`360SelfProtection` | **IOCTL 码表已逆**（`\\.\360SelfProtection` 24 个码 / `\\.\360HookPort` CREATE 门禁非管理员直接 `0xC0000022`） |
| 云查 | `jcloudscan.dll` | `CloudQueryCalcBufferMfSha1AndFingerprint`；头 `x-360-md5` / `x-360-sign`，回 `TrojanName` / `QvmInfoScore` |

### 2) 信任放行链（**这条吃不到，别浪费力气**）
判定粒度 = **签名者证书** → 签名白名单（`libwhite*.dat`/`Qshield*.dat`/`bifdb.dat`）→ **根证书白（`cacert.dat` = 155 张根）** → 信任区 `CDeepScanCache`(XD) → 缓存 → 云查。
**关键限制**：放行需要**用该签名者私钥产生的新签名**；我们导出的 29 个 PFX **全部无私钥**（0/29，复核 3 次），`360TrayLogin.tpi` 里那段 PKCS#8 是**截断的**（450/1214 B，n/d/p/q 全无）。
→ **自制/自签 CA 在这套模型里完全无效**（信任绑在已知签名者 + 155 张根上）。

### 3) 库与容器格式（**打开它就是打开"认什么特征"**）
- `qex/qex.vdb.enc`、`patt.enc`、`MacroDef.enc` = **`1EF17ADA` 容器**：
  `magic(4) + 原长(4) + 密文长(4) + 256(4) + [256B 材料块] + 密文`（三样本逐字节校验通过）
- **容器类型码 `0x37`** —— 已在 Unicorn 补环境里跑出来（3 次复现：`37 37 37 00 01`）
- `patt.enc` 16 字节块重复率 **8.4% → ECB 迹象**；单字节 XOR 不是它的加密
- 库文件名（`qex.vdb`/`patt.enc`）在整包**零明文** → 加载器是运行时拼路径
- `ds*.dat` = `D063`(32) / `QHDT`(32) 容器；`libaw.dat`/`libvi.dat` = **SQLite**（`adware`1054/`rrule`3759/`frule`2719/`mrule`2246，文本列 `enc=1` 加密）

### 4) 引擎 API 可在**本地补环境里直接调**（替代"装杀软自测"）
```
AVEI.dll    (x86, 19 导出)  依赖仅 ADVAPI32 + KERNEL32
360QVM.dll  (x86,  6 导出)  依赖仅 KERNEL32          ← 最干净
AVEngine.dll(x86,  7 导出)  ADVAPI32 + KERNEL32 + VERSION
```
→ 可以做一条 **"不装 360 也能测自己样本检出"** 的本地流水线：`CreateScanner → Scan → AveQueryResult`。
（`360QVM.dll` 里还留着明文 `virus.db` —— 库文件名的第一个锚点。）

### 5) 第三方组件版本（**只当情报，不要拿去堆报告**）
OpenSSL **6 代并存**：0.9.7c(2003)×3 / 0.9.8k(2009)×9 / 0.9.8s(2011)×2 / **1.0.1f(2014)×3（含 `jcloudscan.dll`，落 Heartbleed 区间，**是否启用 heartbeat 未验证**）/ 1.0.2o(2018)×2 / 1.1.1g(2020)×1
zlib **1.2.3 / 1.2.5**（65 模块）｜Lua **5.1 / 5.1.4 / 5.3.4**（`360AntiHijack.tpi` 是伪装成 .tpi 的 PE）｜**tinyxml2**（`SafeInstallSandbox`/`SecurityProxy`/`SoftMgr` 解析外部 XML）｜Detours（16 模块）
→ **口径**：纯"版本陈旧"按 SRC 标准基本不收；要收必须有 PoC/可达性。

---

## 下一步（按价值排，都在"不装不跑"范围内）

1. **打开库**（最高价值）：`.enc` 解析器已在补环境跑通类型判定 → 下一步喂**全量载荷**走进 `0x37` 分支，找 **256B 材料块**的消费点 → 拿到解密路径。工具：`工具/emu_qex_typeid.py`、`工具/fuzz_qex_v2.py`（74 例/秒）
2. **AVE/QVM 引擎本地自测 harness**：补环境里 `BoleGetVersion()` → `CreateEnviroment()` → `AVEI: CreateScanner → Scan` 喂自己的样本 → **本地拿检出结论**（不必装 360）
3. **行为拦截面清单**：`BAPI.dll` 143 个 `AcquireAr*` 规则 + `hookport` 的 `sub_10486`（未读）+ minifilter `360qpesv` 名单 → 行为规避的目标表

## 红线（记在文件里，免得后面忘）
- **不要**再往"签名放行/自签证书"方向投入（无私钥，模型不认）
- **不要**为"老版本组件"单独出报告（情报级，收不了）
- **不要**在没打开特征库前谈"定向绕过"——没有靶子
