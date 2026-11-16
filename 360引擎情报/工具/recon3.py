import pefile, binascii

P = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"
pe = pefile.PE(P, fast_load=True)
pe.parse_data_directories()

def find_types(name):
    out = []
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tn = t.name.decode("latin1", "replace") if t.name is not None else None
        if tn == name:
            for i in t.directory.entries:
                iname = i.name.decode("latin1","replace") if i.name is not None else ("id %s" % i.id)
                if i.directory and i.directory.entries:
                    d = i.directory.entries[0].data
                    off = pe.get_offset_from_rva(d.struct.OffsetToData)
                    out.append((iname, d.struct.Size, pe.__data__[off:off + d.struct.Size]))
    return out

for nm in ["SETUPCONFIG", "SETUPDATA", "SETUPPLUGIN", "OEMDATA", "LICENCE",
           "BASE360", "DRIVERDLL", "DLL", "VIEWER", "ROOTSUPD", "WSCREG", "URLPROC"]:
    for iname, sz, data in find_types(nm):
        head = data[:24]
        printable = "".join(chr(c) if 32 <= c < 127 else "." for c in head)
        print("%-12s / %-8s len=%8d  |%s|" % (nm, iname, sz, printable))

# 挑一个看内容
print("\n=== SETUPCONFIG 头部 ===")
for iname, sz, data in find_types("SETUPCONFIG"):
    print(binascii.hexlify(data[:64]).decode())
    try:
        print("as text:", data[:400].decode("utf-8", "replace"))
    except Exception as e:
        print("decode err", e)

print("\n=== OEMDATA（小）===")
for iname, sz, data in find_types("OEMDATA"):
    print(repr(data))
    for enc in ("utf-16-le", "utf-8", "latin1"):
        try:
            print(enc, "->", data.decode(enc))
            break
        except Exception:
            pass
