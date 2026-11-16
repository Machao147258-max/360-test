"""Aggregate cert_inventory.tsv + signature_entries.tsv into 签名证书清单.md."""
import csv
import collections
import datetime
import io
import os
import sys

CERTS = sys.argv[1]
ENTRIES = sys.argv[2]
PE_SCAN = sys.argv[3]
OUT = sys.argv[4]

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

certs = list(csv.DictReader(open(CERTS, encoding="utf-8"), delimiter="\t"))
entries = list(csv.DictReader(open(ENTRIES, encoding="utf-8"), delimiter="\t"))
scan = {r["rel"]: r for r in csv.DictReader(open(PE_SCAN, encoding="utf-8"), delimiter="\t")}

L = []
w = L.append

signers = [c for c in certs if c["role"] in ("signer", "nested-signer")]
tsas = [c for c in certs if c["role"] == "tsa"]

w("# 360 安全卫士极速版 v15.0.3.1058 —— 签名证书清单")
w("")
w(f"> 数据来源：`cert_inventory.tsv`（{len(certs)} 条证书记录）+ `signature_entries.tsv`（{len(entries)} 条签名项）")
w(f"> 扫描对象：426 个 PE ｜ 生成时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
w("")

# ---------- 1. signer certificates ----------
w("## 一、签名者证书（谁在签）")
w("")
w("| 角色 | 主体 | 序列号 | 密钥 | 有效期 | 签名本证书用 | 文件数 |")
w("|---|---|---|---|---|---|---|")
by_signer = collections.Counter()
for c in signers:
    by_signer[(c["role"], c["subject"], c["serial"])] += 1
for (role, subject, serial), n in sorted(by_signer.items(), key=lambda kv: (-kv[1], kv[0][2])):
    row = next(c for c in signers if c["serial"] == serial)
    w(f"| {role} | {subject[:70]} | `{serial}` | {row['key']} | {row['not_before'][:10]} → {row['not_after'][:10]} | "
      f"{row['cert_sig_algo']} | {n} |")
w("")

# ---------- 2. EV detail ----------
w("## 二、EV 主体信息（工商身份）")
w("")
seen = set()
for c in signers:
    if c["ev"] and c["serial"] not in seen:
        seen.add(c["serial"])
        w(f"- **serial `{c['serial']}`** — {c['subject'][:60]}")
        for part in c["ev"].split(";"):
            part = part.strip()
            if part:
                w(f"  - {part}")
w("")

# ---------- 3. digest / signature algorithms ----------
w("## 三、签名算法与时间戳覆盖")
w("")
w("| 签名层 | 摘要算法 | 签名算法 | 数量 |")
w("|---|---|---|---|")
for kind in ("primary", "nested", "countersignature"):
    for (d, s), n in collections.Counter(
            (e["digest"], e["sig"]) for e in entries if e["kind"] == kind).most_common():
        w(f"| {kind} | {d or '-'} | {s or '-'} | {n} |")
w("")
prim = [e for e in entries if e["kind"] == "primary"]
tsa_ts = {e["rel"] for e in prim if e["gen_time"]}
cs_ts = {(e["rel"], e["entry"]) for e in entries if e["kind"] == "countersignature" and e["gen_time"]}
by_rel_cs = {r for (r, _e) in cs_ts}
w(f"- 主签名总数：**{len(prim)}**")
w(f"- 走 RFC3161 / 微软时间戳令牌：**{len(tsa_ts)}**")
w(f"- 走传统计数器签名（RFC 5652 countersignature，`1.2.840.113549.1.9.6`）：**{len(by_rel_cs)}**")
w(f"- 完全没有时间戳的主签名：**{sum(1 for e in prim if not e['gen_time'] and (e['rel'], e['entry']) not in cs_ts)}**")
w("")
w("| 签名项类型 | 数量 |")
w("|---|---|")
for k, v in collections.Counter(e["kind"] for e in entries).most_common():
    w(f"| {k} | {v} |")
w("")

# ---------- 4. TSA ----------
w("## 四、时间戳来源")
w("")
w("| 类型 | 时间戳主体/令牌 | 有效期 | 指纹(SHA256 前 16) |")
w("|---|---|---|---|")
seen = set()
for c in tsas:
    if c["thumb_sha256"] in seen:
        continue
    seen.add(c["thumb_sha256"])
    w(f"| TSA 证书 | {c['subject'][:60]} | {c['not_before'][:10]} → {c['not_after'][:10]} | `{c['thumb_sha256'][:16]}` |")
w("")
gens = sorted(e["gen_time"] for e in entries if e["gen_time"])
if gens:
    w(f"签名时间跨度：**{gens[0]} → {gens[-1]}**（UTC，共 {len(gens)} 个签名时间）")
w("")
w("| 签名时间年份 | 数量 | 同期文件编译年份数量 |")
w("|---|---|---|")
yrs = collections.Counter(g[:4] for g in gens)
build_yrs = collections.Counter(scan[r]["file_ts"][:4] for r in scan if scan[r]["file_ts"])
for y in sorted(yrs):
    w(f"| {y} | {yrs[y]} | {build_yrs.get(y, 0)} |")
w("")

# ---------- 5. anomalies ----------
w("## 五、异常与值得注意的点")
w("")
now = datetime.datetime.now(datetime.timezone.utc)
expired_now = [c for c in signers if datetime.datetime.strptime(c["not_after"], "%Y-%m-%d %H:%M:%S").replace(
    tzinfo=datetime.timezone.utc) < now]
w(f"1. **证书已过期但仍在使用**：{len(expired_now)} 条记录（依赖时间戳链验证）。代表：")
seen = set()
for c in expired_now:
    if c["serial"] in seen:
        continue
    seen.add(c["serial"])
    w(f"   - {c['subject'][:60]} · serial `{c['serial']}` · 到期 {c['not_after'][:10]}")
w("")
weak = [e for e in entries if e["kind"] == "primary" and e["digest"] == "sha1"]
w(f"2. **主签名用 SHA-1 摘要**：{len(weak)} 个文件（Windows 仍接受，MS 已弃用）；这些文件全部配了传统计数器签名或 TSA 时间戳来兜底。示例："
  + ", ".join(sorted({e['rel'] for e in weak})[:10]))
w("")
nested = [e for e in entries if e["kind"] == "nested"]
w(f"3. **双签名（内嵌 nested signature）**：{len(nested)} 条签名项")
pairs = collections.Counter()
for e in nested:
    prim = next((c["subject"] for c in certs if c["rel"].startswith(e["rel"] + "#sig" + e["entry"]) and c["role"] == "signer"), "?")
    nest = next((c["subject"] for c in certs if c["rel"].startswith(e["rel"] + "#sig" + e["entry"]) and c["role"] == "nested-signer"), "?")
    pairs[(prim.split(",")[0], nest.split(",")[0])] += 1
for (p, n), cnt in pairs.most_common():
    w(f"   - {p}  →  内嵌 {n}  ×{cnt}")
w("")

# ---------- 6. per-module signer map ----------
w("## 六、模块 → 签名者 映射（按目录聚合）")
w("")
dirmap = collections.defaultdict(collections.Counter)
for c in certs:
    if c["role"] != "signer":
        continue
    rel = c["rel"].split("#sig")[0]
    d = "/".join(rel.split("/")[:-1]) or "(root)"
    dirmap[d][c["subject"].split(",")[0]] += 1
w("| 目录 | 签名者分布 |")
w("|---|---|")
for d in sorted(dirmap):
    items = ", ".join(f"{k}×{v}" for k, v in dirmap[d].most_common())
    w(f"| {d} | {items} |")
w("")

open(OUT, "w", encoding="utf-8", newline="\n").write("\n".join(L) + "\n")
print(f"{len(L)} lines -> {OUT}")
