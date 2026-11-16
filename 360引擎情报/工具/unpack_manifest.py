import os, re, collections

D = r"C:\Users\20751\Desktop\360逆向\resources\SETUPCONFIG_id_10204"
OUT = r"C:\Users\20751\Desktop\360逆向\解包"
os.makedirs(OUT, exist_ok=True)

def read(p):
    b = open(p, "rb").read()
    for enc in ("utf-16", "utf-8-sig", "utf-8", "latin1"):
        try:
            return b.decode(enc)
        except Exception:
            continue

fl = read(os.path.join(D, "filelist.xml"))

# 每条 <File .../>
entries = []
for m in re.finditer(r"<File\b([^>]*)/?>", fl):
    a = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
    entries.append(a)
print("File 条目:", len(entries))

# 导出完整清单
with open(os.path.join(OUT, "manifest.tsv"), "w", encoding="utf-8") as f:
    f.write("Name\tIsPE\tVersion\tSize\tMD5\n")
    for a in entries:
        f.write("%s\t%s\t%s\t%s\t%s\n" % (
            a.get("Name", ""), a.get("IsPE", ""), a.get("Version", ""),
            a.get("Size", ""), a.get("MD5", "")))

# 分类
by_ext = collections.Counter()
by_dir = collections.Counter()
total = 0
for a in entries:
    n = a.get("Name", "")
    by_ext[os.path.splitext(n)[1].lower()] += 1
    top = n.replace("\\", "/").split("/")[0] if ("\\" in n or "/" in n) else "(root)"
    by_dir[top] += 1
    try:
        total += int(a.get("Size", 0))
    except Exception:
        pass

print("总大小: %.1f MB" % (total / 1e6))
print("按后缀:", by_ext.most_common(20))
print("按顶层目录:", by_dir.most_common(20))

# 可执行/驱动重点
for kw in [".exe", ".sys", ".cat", ".enc", ".db"]:
    names = [a["Name"] for a in entries if a.get("Name", "").lower().endswith(kw)]
    print("\n[%s] %d 个，前 20:" % (kw, len(names)))
    for n in names[:20]:
        print("   ", n)

# 找下载源 / URL（在配置和 exe 里）
print("\n=== 找下载 URL ===")
import glob
for p in [os.path.join(D, x) for x in os.listdir(D)]:
    try:
        t = read(p)
    except Exception:
        continue
    for m in set(re.findall(r"https?://[ -~]{5,90}", t)):
        print("  [%s] %s" % (os.path.basename(p), m))
exe = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"
b = open(exe, "rb").read()
doms = collections.Counter()
for m in re.finditer(rb"https?://[a-zA-Z0-9._\-/]{5,80}", b):
    s = m.group().decode("latin1")
    dom = re.match(r"https?://([^/]+)", s).group(1)
    doms[dom] += 1
print("\n[exe] 域名 top20:")
for d, c in doms.most_common(20):
    print("   %-40s x%d" % (d, c))
