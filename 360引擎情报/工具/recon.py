import pefile, math, os, hashlib
from collections import Counter

P = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"

def ent(d):
    if not d:
        return 0.0
    c = Counter(d); n = len(d)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

pe = pefile.PE(P, fast_load=True)
pe.parse_data_directories()

print("Machine: 0x%x  (0x14c=x86, 0x8664=x64)" % pe.FILE_HEADER.Machine)
print("Subsystem:", pe.OPTIONAL_HEADER.Subsystem, "(2=GUI, 3=CUI)")
print("EntryPoint: 0x%x" % pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print("ImageBase:  0x%x" % pe.OPTIONAL_HEADER.ImageBase)
print("DllChar:    0x%x" % pe.OPTIONAL_HEADER.DllCharacteristics)
print("TimeDate:   0x%x" % pe.FILE_HEADER.TimeDateStamp)
print("Sections:", pe.FILE_HEADER.NumberOfSections)

print("=== 段 ===")
for s in pe.sections:
    nm = s.Name.rstrip(b"\x00").decode("latin1", "replace")
    print("  %-9s vsize=%9d raw=%9d ent=%.2f ch=0x%x" %
          (nm, s.Misc_VirtualSize, s.SizeOfRawData, ent(s.get_data()), s.Characteristics))

print("=== 导入的 DLL ===")
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        print("  ", e.dll.decode("latin1", "replace"))
else:
    print("  (无导入表 — 可能被壳压缩)")

print("导出数:", len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
      if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else 0)

# 资源
if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
    print("=== 资源类型 ===")
    seen = set()
    for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tid = t.id if t.id is not None else t.name
        if tid not in seen:
            seen.add(tid)
            print("  type", tid)
