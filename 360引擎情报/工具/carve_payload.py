import pefile, os, io
import py7zr

P = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"
OUT = r"C:\Users\20751\Desktop\360逆向\解包"
os.makedirs(OUT, exist_ok=True)

pe = pefile.PE(P, fast_load=True)
raw = pe.__data__
end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
payload = raw[end:sec.VirtualAddress]
print("payload: 0x%x .. 0x%x  = %.1f MB  magic=%s" %
      (end, sec.VirtualAddress, len(payload) / 1e6, payload[:6].hex()))
open(os.path.join(OUT, "payload.7z"), "wb").write(payload)

z = py7zr.SevenZipFile(io.BytesIO(payload))
names = z.getnames()
print("7z 内条目:", len(names))
for n in names[:60]:
    print("   ", n)
z.close()
