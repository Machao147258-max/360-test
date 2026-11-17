# 360 引擎情报归档

一份针对 360 杀毒引擎（版本 v15.0.3.1058）的**静态逆向情报归档**。全部内容来自对已解包载荷的静态分析与本地补环境实验，按「样本画像 → 检测链 → 驱动与接口 → 信任体系 → 私有格式 → 分析工具链」组织，用于理解引擎的模块构成、检测机制与接口面。

> **主文入口**：[`360杀毒引擎静态逆向记录.md`](./360杀毒引擎静态逆向记录.md) —— 约 9.2 万字的完整长文，32 个 TOP，覆盖 426 个 PE 全量画像、四层检测链、模块逐档分析、接口与签名信任、私有容器格式，以及 Unicorn 补环境实测。建议从主文读起，再按需查阅下方归档资料。

> 研究纪律：全程静态分析 + 本地补环境（Unicorn）；未安装、未运行目标软件，未加载其驱动，样本未联网。所有魔数、地址、IOCTL 码仅用于说明机制定位，不构成可利用流程。

---

## 内容概览

- 主文 1 篇（约 9.2 万字）+ 归档资料 188 个文件 / 约 15 MB
- 9 份分析文档（约 5,700 行）
- 70 份数据文件（画像表、导出表、证书清单、fuzz 日志）
- 43 个分析脚本
- 14 个引擎模块样本
- 50 份旧树归档资料

---

## 目录结构

```
360引擎情报/
├── 报告/         9 份   分析文档与补环境执行记录
├── 数据/         70 份  画像表、导出表、证书清单、fuzz 日志
├── 工具/         43 个  静态分析与补环境脚本
├── 引擎模块/     14 个  DLL / SYS / 数据文件样本
├── 归档_旧树/    50 份  早期版本的证书链与报告
└── README.md           内部研究说明
```

### `报告/`

| 文件 | 行数 | 内容 |
| --- | ---: | --- |
| `检测引擎静态分析.md` | 1816 | 四层检测链：微特征、QVM/Bole、qex 文档层、BAPI 行为 + 云查；含字符串分类与加密库指纹 |
| `dossier.md` | 2596 | 25 个模块逐模块画像（arch / size / entry / sections / imports / device / registry / api / ioctl 等维度） |
| `签名信任机制排查.md` | 845 | 三层信任链、签名白名单、根证书体系、PFX 私钥排查结论 |
| `API导出清单.md` | 817 | 模块导出函数全表 |
| `接口清单.md` | 211 | RPC / COM 接口清单 |
| `逆向报告_v15.0.3.1058.md` | 220 | 总体逆向结论 |
| `360接口总表.md` | 103 | 24 个 IOCTL 码表、权限门与返回码 |
| `接口fuzz面.md` | 60 | 接口 fuzz 面分类 |
| `emu_qex_typeid.txt` | 33 | Unicorn 补环境类型判定执行记录 |

### `数据/`

- `payload_pe_scan.tsv` — 426 个 PE 的静态画像（28 列）
- `payload_sig.tsv` — 签名全量数据
- `api_exports.tsv` — 3,202 条导出记录
- `certs/` — PFX、证书链、证书清单与签名条目
- `fuzz_qex_part1..4.log` — 四批 fuzz 日志（合计 255 例）

### `工具/`

43 个脚本，按用途大致分为几组：

- **样本与 PE 画像**：`pe_scan.py`、`api_inventory.py`、`thirdparty_scan.py`、`recon*.py`、`scan_summary.py`
- **模块与接口发现**：`dossier.py`、`iface_recon.py`、`iface_fuzz_recon.py`、`iface_wide_recon.py`、`ida_*.py`（IDA 系列）
- **格式与容器**：`db_container.py`、`carve_payload.py`、`extract_payload.py`、`find_overlay.py`、`parse_filelist.py`
- **证书与信任**：`cert_inventory.py`、`cert_report.py`、`signature.py`、`trust_recon.py`、`privkey_detect_recon.py`
- **补环境与 fuzz**：`emu_qex_typeid.py`、`fuzz_qex_v2.py`、`fuzz_qex_typeid.py`、`anomaly_audit*.py`

### `引擎模块/`

AVEI.dll、AVEngine.dll、360QVM.dll、qex.dll、heavygate.dll、cloudcom2.dll、BAPI.dll、360SelfProtection.sys、hookport_win10.sys，以及若干 `.enc` / `.dat` 数据文件。

### `归档_旧树/`

早期版本的证书链（补到根）与《证书链与白名单》《360 逆向报告》等历史文档。

---

## 阅读顺序建议

1. 先读根目录主文 `360杀毒引擎静态逆向记录.md` 建立完整框架
2. 再看 `报告/逆向报告_v15.0.3.1058.md` 建立整体印象
3. 再看 `报告/检测引擎静态分析.md` 理解检测链分层
4. 结合 `数据/payload_pe_scan.tsv` 核对样本画像结论
5. 需要模块级细节时查 `报告/dossier.md`
6. 接口面看 `报告/360接口总表.md` 与 `报告/接口清单.md`
7. 复现分析过程参看 `工具/` 下对应脚本

---

## 说明与边界

- 本归档为静态研究资料，仅用于理解引擎机制与防护原理。
- 不含可复现的绕过流程、可利用载荷或目标服务的真实端点信息。
- 私钥、特征库内容、完整证书材料不在公开范围内；相关字段仅保留结构性描述。
- 相关研究应在合法授权与适用法律的框架内进行。
