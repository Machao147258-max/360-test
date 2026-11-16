import os

roots = [r"C:\Program Files", r"C:\Program Files (x86)", r"C:\Windows",
         "D:\\", r"C:\Users\20751", r"C:\Users\20751\Desktop"]
want = {"7z.exe", "7za.exe", "7zr.exe", "7zg.exe", "7z.dll"}
cands = []
for r in roots:
    if not os.path.isdir(r):
        continue
    base = r.count(os.sep)
    for dp, dn, fn in os.walk(r):
        if dp.count(os.sep) - base > 4:
            dn[:] = []
            continue
        for f in fn:
            if f.lower() in want:
                cands.append(os.path.join(dp, f))
    if len(cands) > 40:
        break
for c in cands[:40]:
    print(c)
print("共", len(cands))
