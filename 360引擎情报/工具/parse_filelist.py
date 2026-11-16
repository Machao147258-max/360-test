import os, re, collections

D = r"C:\Users\20751\Desktop\360逆向\resources\SETUPCONFIG_id_10204"

def read(p):
    b = open(p, "rb").read()
    for enc in ("utf-16", "utf-8-sig", "utf-8", "latin1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("latin1", "replace")

fl = read(os.path.join(D, "filelist.xml"))
print("filelist.xml 头部字节:", open(os.path.join(D, "filelist.xml"), "rb").read(8).hex())

# 统计 <File ...> 条目
files = re.findall(r"<File\b[^>]*>", fl)
print("File 条目数:", len(files))
# 解析属性名
attrs = collections.Counter()
for f in files:
    for m in re.finditer(r"(\w+)=", f):
        attrs[m.group(1)] += 1
print("属性:", dict(attrs))

# 常见后缀
exts = collections.Counter()
names = []
for f in files:
    m = re.search(r'Name="([^"]+)"', f)
    if m:
        names.append(m.group(1))
        e = os.path.splitext(m.group(1))[1].lower()
        exts[e] += 1
print("后缀 top15:", exts.most_common(15))
print("样例文件（前 25）:")
for n in names[:25]:
    print("   ", n)

# 看看有没有 URL / 下载源
for kw in ["http", "URL", "Down", "Source", "Hash", "MD5", "Size", "Ver"]:
    c = fl.count(kw)
    if c:
        print("关键词 %-8s 出现 %d 次" % (kw, c))
