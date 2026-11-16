"""360 样本资产异常审计 v2（修正路径基准 + 异常点名）

root 传解包树绝对路径；HOME 传 360逆向 工作目录（用于检查安装包本体与既有 tsv）。
"""
import csv
import datetime
import hashlib
import os
import sys
from collections import Counter, defaultdict

import pefile

MAGICS = [
    (b"MZ", "PE/EXE"), (b"PK\x03\x04", "ZIP"), (b"7z\xbc\xaf", "7Z"),
    (b"SQLite format 3", "SQLite"), (b"\x1f\x8b", "GZIP"), (b"BZh", "BZIP2"),
    (b"Rar!", "RAR"), (b"%PDF", "PDF"), (b"\x89PNG", "PNG"),
    (b"\x1e\xf1\x7a\xda", "360-ENC 容器"), (b"D063", "D063 容器"),
    (b"QHDT", "QHDT 容器"), (b"XYR\x00", "XYR 容器"), (b"-----BEGIN", "PEM 文本"),
]


def sniff(head):
    for magic, name in MAGICS:
        if head.startswith(magic):
            return name
    if b"-----BEGIN CERTIFICATE-----" in head[:4000]:
        return "PEM 证书"
    return "其它"


def main():
    root, home = sys.argv[1], sys.argv[2]
    print("== 1) 安装包本体（绝对路径核对）==")
    for rel in ["解包\\payload.7z", "_归档_faga旧树\\payload\\jk_payload.7z",
                "setupbeta_jisu.exe", "解包\\360payload"]:
        p = os.path.join(home, rel)
        if os.path.exists(p):
            if os.path.isdir(p):
                n = sum(len(f) for _b, _d, f in os.walk(p))
                print(f"  [在] {rel:44s} 目录 {n} 文件")
            else:
                h = hashlib.sha256(open(p, "rb").read()).hexdigest()[:20]
                print(f"  [在] {rel:44s} {os.path.getsize(p):>14,} B  sha256={h}")
        else:
            print(f"  [缺] {rel}")

    ext_type = defaultdict(Counter)
    odd = defaultdict(list)
    stamps = {}
    for base, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            ext = os.path.splitext(n)[1].lower() or "(无)"
            with open(p, "rb") as fh:
                head = fh.read(4096)
            t = sniff(head)
            ext_type[ext][t] += 1
            if ext in (".tpi", ".ui", ".dat", ".db", ".enc", ".bin", ".qex"):
                odd[t].append(rel)
            if t == "PE/EXE":
                try:
                    pe = pefile.PE(p, fast_load=True)
                    stamps[rel] = pe.FILE_HEADER.TimeDateStamp
                    pe.close()
                except Exception:
                    pass

    print("\n== 2) 扩展名 vs 真实类型（伪装/改名项点名）==")
    for label, t in (("伪装成 .tpi 的 PE", "PE/EXE"),):
        pass
    for ext in (".tpi", ".ui", ".dat", ".db", ".enc"):
        c = ext_type.get(ext, {})
        print(f"  {ext:6s} 共 {sum(c.values()):3d} → {dict(c)}")
    print("  --- .tpi 实为 PE 的清单 ---")
    for rel in sorted(r for r in sum(odd.values(), []) if r.endswith(".tpi") and r):
        try:
            pe = pefile.PE(os.path.join(root, *rel.split("/")), fast_load=True)
            print(f"    {rel}  PE 时间戳={datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, datetime.UTC):%Y-%m-%d}")
            pe.close()
        except Exception:
            print(f"    {rel}")
    print("  --- .dat 里是 SQLite / ZIP 的清单 ---")
    for base2, _d, names2 in os.walk(root):
        for n in names2:
            if not n.lower().endswith((".dat", ".db")):
                continue
            p = os.path.join(base2, n)
            with open(p, "rb") as fh:
                h = fh.read(16)
            t = sniff(h)
            if t in ("SQLite", "ZIP"):
                print(f"    [{t:6s}] {os.path.relpath(p, root).replace(chr(92), '/')}")

    print("\n== 3) PE 时间戳异常点 ==")
    fm = lambda x: datetime.datetime.fromtimestamp(x, datetime.UTC).strftime("%Y-%m-%d %H:%M")
    c = Counter(stamps.values())
    lo = min(stamps.values())
    print(f"  最早 {fm(lo)} ← {[r for r, t in stamps.items() if t == lo][:6]}")
    weird = {r: t for r, t in stamps.items()
             if t == 0 or t == 0xFFFFFFFF or t < 946684800 or t > 1900000000}
    print(f"  异常值（0 / 0xFFFFFFFF / 早于 2000 年 / 晚于 2030 年）：{len(weird)}")
    for r, t in sorted(weird.items(), key=lambda x: x[1])[:20]:
        print(f"    {fm(t) if t else '0'}  hex={t:#010x}  {r}")
    print(f"  仅出现 1 次的时间戳：{sum(1 for v in c.values() if v == 1)} / {len(c)} 个（构建批次越散越真）")

    print("\n== 4) 公司名（读既有 payload_pe_scan.tsv）==")
    tsv = os.path.join(home, "payload_pe_scan.tsv")
    if os.path.exists(tsv):
        comp = Counter()
        with open(tsv, encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh, delimiter="\t"):
                v = (row.get("company") or row.get("CompanyName") or "").strip()
                if v:
                    comp[v] += 1
        for k, v in comp.most_common(20):
            tag = "" if ("360" in k or "奇虎" in k or "奇元" in k or "Qihu" in k or "Qihoo" in k) else "   ← 非 360 主体"
            print(f"  {v:4d}  {k}{tag}")
    else:
        print("  (无 tsv)")


if __name__ == "__main__":
    main()
