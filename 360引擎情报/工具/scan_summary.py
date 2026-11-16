"""Aggregate payload_pe_scan.tsv into console stats (no files written)."""
import collections
import csv
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "payload_pe_scan.tsv"
rows = list(csv.DictReader(open(path, encoding="utf-8"), delimiter="\t"))
print(f"total PE rows: {len(rows)}")


def group(field, limit=30, table=None):
    src = table if table is not None else rows
    c = collections.Counter(r[field] for r in src)
    print(f"\n== {field} ==")
    for k, v in c.most_common(limit):
        print(f"  {v:5d}  {k}")


for f in ("ext", "arch", "subsystem", "is_dll", "linker", "dotnet", "tls", "signed_dir"):
    group(f)

print("\n== 编译时间戳年份分布 ==")
years = collections.Counter(r["file_ts"][:4] for r in rows if r["file_ts"])
for k, v in sorted(years.items()):
    print(f"  {v:5d}  {k}")

print("\n== packer 命中 ==")
pk = [r for r in rows if r["packer"]]
print(f"  {len(pk)} 条")
for r in pk[:20]:
    print(f"    {r['rel']}  {r['packer']}  maxent={r['max_entropy']}")

print("\n== notes 分布 ==")
notes = collections.Counter()
for r in rows:
    for n in filter(None, r["notes"].split("|")):
        notes[n] += 1
for k, v in notes.most_common():
    print(f"  {v:5d}  {k}")

print("\n== HIGH_ENTROPY 明细 ==")
for r in sorted((r for r in rows if "HIGH_ENTROPY" in r["notes"]),
                key=lambda r: -float(r["max_entropy"])):
    print(f"    {float(r['max_entropy']):.2f}  {r['rel']}  packer={r['packer'] or '-'} epsec={r['ep_section']}")

print("\n== EP 不在 .text ==")
for r in rows:
    if "EP_OUTSIDE_TEXT" in r["notes"]:
        print(f"    {r['rel']}  epsec={r['ep_section']} maxent={r['max_entropy']}")

print("\n== 无导入表 / 导入极少（<=3 DLL）==")
for r in rows:
    if int(r["import_dlls"] or 0) <= 3:
        print(f"    {r['rel']}  dlls={r['import_dlls']} funcs={r['import_funcs']} notes={r['notes']}")

print("\n== overlay（段后附加数据）top15 ==")
for r in sorted(rows, key=lambda r: -int(r["overlay"] or 0))[:15]:
    ov = int(r["overlay"] or 0)
    if ov:
        print(f"    {ov:>12,}  {r['rel']}")

print("\n== 各家签名归属（按 company）==")
group("company", 40)

print("\n== 含 PDB 路径 ==")
for r in rows:
    if r["pdb"]:
        print(f"    {r['rel']}  ->  {r['pdb']}")
