import pefile, re, os

P = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"
pe = pefile.PE(P, fast_load=True)
pe.parse_data_directories()

print("=== 版本信息 ===")
if hasattr(pe, "FileInfo"):
    for fi in pe.FileInfo:
        for f in (fi if isinstance(fi, list) else [fi]):
            if getattr(f, "Key", b"") == b"StringFileInfo":
                for st in f.StringTable:
                    for k, v in st.entries.items():
                        print("  %-20s %s" % (k.decode("latin1", "replace"),
                                              v.decode("latin1", "replace")))

print("=== 资源树（前 40 条，带大小）===")
cnt = 0
if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tname = t.name if t.name is not None else ("type %s" % t.id)
        for i in getattr(t, "directory", None).entries if t.directory else []:
            iname = i.name if i.name is not None else ("id %s" % i.id)
            sz = 0
            if i.directory and i.directory.entries:
                d = i.directory.entries[0].data
                sz = d.struct.Size if d else 0
            print("  %-14s / %-22s size=%d" % (tname, iname, sz))
            cnt += 1
            if cnt >= 40:
                break
        if cnt >= 40:
            break

print("=== 关键字符串 ===")
b = open(P, "rb").read()
pats = {
    "URL": rb"https?://[ -~]{4,80}",
    "360kw": rb"[ -~]*(?:360\.cn|360safe|qihoo|360se|360safeinstall)[ -~]{0,40}",
    "exe/path": rb"[ -~]*(?:System32|SysWOW64|\\Drivers\\|\.sys|\.dll)[ -~]{0,30}",
}
for name, pat in pats.items():
    seen = set()
    for m in re.finditer(pat, b, re.I):
        s = m.group().decode("latin1", "replace").strip()
        if s and s not in seen and 3 < len(s) < 100:
            seen.add(s)
    print("  [%s] %d 个，样例：" % (name, len(seen)))
    for s in list(seen)[:12]:
        print("     ", s)
