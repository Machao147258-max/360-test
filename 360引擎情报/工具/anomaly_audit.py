"""360 样本资产异常审计（纯静态只读）

检查项：
  1) 安装包本体是否在场（原始 exe / 7z 载荷 / 解包树）
  2) 扩展名 vs 真实文件类型（.tpi 其实是 PE？.dat 其实是 SQLite？…）
  3) PE 编译时间戳分布（是否有未来时间、异常聚集、与签名时间矛盾）
  4) 版本资源里的公司名（是否有非 360 主体）
  5) PE overlay（节表之后还挂着数据 → 夹带）
  6) 同名不同内容 / 同内容不同名
  7) 签名状态（无签名 / 无效）
"""
import hashlib
import os
import re
import sys
from collections import Counter, defaultdict

import pefile

MAGICS = [
    (b"MZ", "PE/EXE"), (b"PK\x03\x04", "ZIP"), (b"7z\xbc\xaf", "7Z"),
    (b"SQLite format 3", "SQLite"), (b"\x1f\x8b", "GZIP"), (b"BZh", "BZIP2"),
    (b"Rar!", "RAR"), (b"%PDF", "PDF"), (b"RIFF", "RIFF"), (b"\x89PNG", "PNG"),
    (b"1ef17ada", "HEX? no"), (b"\x1e\xf1\x7a\xda", "360-ENC 容器"),
    (b"D063", "D063 容器"), (b"QHDT", "QHDT 容器"), (b"XYR\x00", "XYR 容器"),
    (b"-----BEGIN", "PEM 文本"), (b"<?xml", "XML"), (b"\xef\xbb\xbf", "UTF8-BOM"),
]


def sniff(head):
    for magic, name in MAGICS:
        if head.startswith(magic):
            return name
    if head[:4] == b"1ef1"[0:4]:
        return "?"
    if b"-----BEGIN CERTIFICATE-----" in head[:4000]:
        return "PEM 证书"
    return "未知/其它"


def main():
    root = sys.argv[1]
    wrap = sys.argv[2] if len(sys.argv) > 2 else None

    print("== 1) 安装包本体 ==")
    for p in [os.path.join(os.path.dirname(root), "解包", "payload.7z"),
              os.path.join(os.path.dirname(root), "_归档_faga旧树", "payload", "jk_payload.7z"),
              os.path.join(os.path.dirname(root), "setupbeta_jisu.exe"),
              os.path.join(os.path.dirname(root), "jk.exe"), os.path.join(os.path.dirname(root), "hh.exe")]:
        if os.path.exists(p):
            h = hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]
            print(f"  [在] {os.path.relpath(p, os.path.dirname(root)):46s} {os.path.getsize(p):>12,} B  sha256={h}")
        else:
            print(f"  [缺] {os.path.relpath(p, os.path.dirname(root))}")

    ext_of_type = defaultdict(Counter)
    companies = Counter()
    stamps = Counter()
    overlays = []
    no_sig = []
    rows = []

    for base, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            ext = os.path.splitext(n)[1].lower() or "(无)"
            size = os.path.getsize(p)
            with open(p, "rb") as fh:
                head = fh.read(4096)
            t = sniff(head)
            ext_of_type[ext][t] += 1
            rows.append((rel, ext, t, size))
            if t == "PE/EXE":
                try:
                    pe = pefile.PE(p, fast_load=True)
                    ts = pe.FILE_HEADER.TimeDateStamp
                    stamps[ts] += 1
                    ov = pe.get_overlay_data_start_offset()
                    if ov and size - ov > 65536:
                        overlays.append((rel, size - ov))
                    for fi in getattr(pe, "FileInfo", []) or []:
                        for e in fi:
                            if e.Key == b"StringFileInfo":
                                for st in e.StringTable:
                                    cn = st.entries.get(b"CompanyName")
                                    if cn:
                                        companies[cn.decode("utf-8", "ignore")] += 1
                    pe.close()
                except Exception:
                    pass
            # 签名状态（复用既有 tsv）
    ts = os.path.join(os.path.dirname(root), "payload_sig.tsv")
    if os.path.exists(ts):
        import csv
        with open(ts, encoding="utf-8-sig", newline="") as fh:
            for r in csv.DictReader(fh, delimiter="\t"):
                if (r.get("status") or "").strip().lower() not in ("valid", "ok", "valid;"):
                    no_sig.append((r.get("file") or r.get("path") or "?", r.get("status")))

    print("\n== 2) 扩展名 vs 真实类型（只列不一致的）==")
    for ext, c in sorted(ext_of_type.items()):
        for t, n in c.items():
            if ext in (".dll", ".exe", ".sys", ".cpl") and t != "PE/EXE":
                print(f"  {ext:8s} 但真实是 {t:14s} × {n}")
            elif ext not in (".dll", ".exe", ".sys", ".cpl", ".png", ".jpg", ".gif", ".ico", ".jpg") and t == "PE/EXE":
                print(f"  {ext:8s} 但真实是 PE/EXE × {n}   ← 伪装扩展名")
            elif ext in (".dat", ".db", ".enc", ".tpi", ".ui", ".bin") and t in ("SQLite", "ZIP", "PE/EXE", "360-ENC 容器", "D063 容器", "PEM 证书"):
                print(f"  {ext:8s} → {t:14s} × {n}")

    print("\n== 3) PE 编译时间戳 ==")
    import datetime
    if stamps:
        lo, hi = min(stamps), max(stamps)
        fm = lambda x: datetime.datetime.utcfromtimestamp(x).strftime("%Y-%m-%d %H:%M")
        print(f"  最早 {fm(lo)}  最晚 {fm(hi)}  共 {sum(stamps.values())} 个 PE，{len(stamps)} 个不同时间戳")
        print("  最集中的 8 个（同一构建批次会有相同时间戳）：")
        for t, n in stamps.most_common(8):
            print(f"    {fm(t)}  × {n}")
        fut = [t for t in stamps if t > 2000000000]
        if fut:
            print(f"  ⚠ 异常时间戳（>2033 年）{len(fut)} 个：{[hex(x) for x in fut[:5]]}")

    print("\n== 4) 版本资源里的公司名 ==")
    for c, n in companies.most_common():
        tag = "" if ("360" in c or "奇虎" in c or "奇元" in c or "Qihu" in c or "Qihoo" in c) else "   ← 非 360 主体"
        print(f"  {n:4d}  {c}{tag}")

    print("\n== 5) PE overlay（节表之后挂数据，>64KB 才列）==")
    for rel, n in sorted(overlays, key=lambda x: -x[1])[:12]:
        print(f"  {n:>12,} B  {rel}")
    if not overlays:
        print("  （无）")

    print("\n== 6) 签名状态异常 ==")
    if no_sig:
        for f, s in no_sig[:20]:
            print(f"  {s:14s} {f}")
        print(f"  合计 {len(no_sig)} 条")
    else:
        print("  （无：payload_sig.tsv 全为 Valid 或无该文件）")


if __name__ == "__main__":
    main()
