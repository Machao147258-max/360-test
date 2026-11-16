import os, hashlib, math, struct
from collections import Counter
import pefile

P = r"C:\Users\20751\Downloads\inst.exe"
print("存在:", os.path.exists(P))
b = open(P, "rb").read()
print("大小: %d (%.2f MB)" % (len(b), len(b) / 1e6))
print("MD5:", hashlib.md5(b).hexdigest())
print("SHA256:", hashlib.sha256(b).hexdigest())

def ent(d):
    if not d: return 0.0
    c = Counter(d); n = len(d)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

pe = pefile.PE(P, fast_load=True)
pe.parse_data_directories()
print("Machine: 0x%x  Subsystem: %d  EP: 0x%x  ImageBase: 0x%x" %
      (pe.FILE_HEADER.Machine, pe.OPTIONAL_HEADER.Subsystem,
       pe.OPTIONAL_HEADER.AddressOfEntryPoint, pe.OPTIONAL_HEADER.ImageBase))
print("TimeDate: 0x%x  Sections: %d" % (pe.FILE_HEADER.TimeDateStamp, pe.FILE_HEADER.NumberOfSections))
print("=== 段 ===")
for s in pe.sections:
    nm = s.Name.rstrip(b"\x00").decode("latin1", "replace")
    print("  %-9s vsize=%9d raw=%9d ent=%.2f" % (nm, s.Misc_VirtualSize, s.SizeOfRawData, ent(s.get_data())))
end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
print("段结束 0x%x (%.2f MB)" % (end, end/1e6))
try:
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    print("证书表 0x%x 大小 %d" % (sec.VirtualAddress, sec.Size))
    print("段末→证书表: %.2f MB" % ((sec.VirtualAddress - end)/1e6))
except Exception as e:
    print("证书:", e)
print("=== 导入 DLL ===")
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        print("  ", e.dll.decode("latin1", "replace"))
print("=== 版本信息 ===")
if hasattr(pe, "FileInfo"):
    for fi in pe.FileInfo:
        for f in (fi if isinstance(fi, list) else [fi]):
            if getattr(f, "Key", b"") == b"StringFileInfo":
                for st in f.StringTable:
                    for k, v in st.entries.items():
                        print("  %-18s %s" % (k.decode("latin1", "replace"), v.decode("latin1", "replace")))
# overlay magic
seg = b[end:end+16]
print("段末字节:", seg.hex())
