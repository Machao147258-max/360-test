import os, collections

D = r"C:\Users\20751\Desktop\360逆向\解包\360payload"
print("根:", D, "存在:", os.path.isdir(D))

top = collections.Counter()
topsz = collections.Counter()
exts = collections.Counter()
exes, syss = [], []
n = 0; tot = 0
for dp, dn, fn in os.walk(D):
    for f in fn:
        p = os.path.join(dp, f); s = os.path.getsize(p); n += 1; tot += s
        rel = os.path.relpath(p, D)
        t = rel.split(os.sep)[0] if os.sep in rel else "(root)"
        top[t] += 1; topsz[t] += s
        exts[os.path.splitext(f)[1].lower()] += 1
        if f.lower().endswith(".exe"): exes.append((s, rel))
        if f.lower().endswith(".sys"): syss.append((s, rel))

print("文件 %d, 总 %.1f MB" % (n, tot / 1e6))
print("\n顶层目录 top20:")
for t, c in top.most_common(20):
    print("   %-16s %4d 个  %7.1f MB" % (t, c, topsz[t] / 1e6))
print("\n后缀 top15:", exts.most_common(15))
print("\n最大 exe top20:")
for s, r in sorted(exes, reverse=True)[:20]:
    print("   %7.2f MB  %s" % (s / 1e6, r))
print("\n最大 .sys top15:")
for s, r in sorted(syss, reverse=True)[:15]:
    print("   %7.2f MB  %s" % (s / 1e6, r))
