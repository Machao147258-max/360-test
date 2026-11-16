import pefile, io, os, binascii
import py7zr

P = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"
OUT = r"C:\Users\20751\Desktop\360逆向\resources"
os.makedirs(OUT, exist_ok=True)

pe = pefile.PE(P, fast_load=True)
pe.parse_data_directories()
DATA = pe.__data__

def iter_named(name):
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tn = t.name.decode("latin1", "replace") if t.name is not None else None
        if tn == name:
            for i in t.directory.entries:
                iname = i.name.decode("latin1", "replace") if i.name is not None else ("id_%s" % i.id)
                if i.directory and i.directory.entries:
                    d = i.directory.entries[0].data
                    off = pe.get_offset_from_rva(d.struct.OffsetToData)
                    yield iname, DATA[off:off + d.struct.Size]

SEVENZ = ["SETUPCONFIG", "OEMDATA", "BASE360", "DLL", "ROOTSUPD", "WSCREG", "URLPROC"]
for name in SEVENZ:
    for iname, data in iter_named(name):
        if not data.startswith(b"7z\xbc\xaf\x27\x1c"):
            continue
        tag = "%s_%s" % (name, iname)
        try:
            z = py7zr.SevenZipFile(io.BytesIO(data))
            names = z.getnames()
            print("[%s] 7z, %d 项:" % (tag, len(names)))
            for n in names[:40]:
                print("    ", n)
            sub = os.path.join(OUT, tag)
            os.makedirs(sub, exist_ok=True)
            z.extractall(path=sub)
            z.close()
        except Exception as e:
            print("[%s] 解压失败: %s" % (tag, e))
