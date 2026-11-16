import os, io
import py7zr

OUT = r"C:\Users\20751\Desktop\360逆向\解包"
payload = open(os.path.join(OUT, "payload.7z"), "rb").read()
dst = os.path.join(OUT, "360payload")
os.makedirs(dst, exist_ok=True)
z = py7zr.SevenZipFile(io.BytesIO(payload))
z.extractall(path=dst)
z.close()

# 统计
tot = 0
n = 0
for dp, dn, fn in os.walk(dst):
    for f in fn:
        n += 1
        try:
            tot += os.path.getsize(os.path.join(dp, f))
        except Exception:
            pass
print("解出 %d 个文件, 共 %.1f MB -> %s" % (n, tot / 1e6, dst))
