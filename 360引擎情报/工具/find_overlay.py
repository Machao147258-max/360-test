import pefile, binascii, struct

P = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"
pe = pefile.PE(P, fast_load=True)
raw = pe.__data__
print("文件大小: %d (%.1f MB)" % (len(raw), len(raw) / 1e6))

# 段末尾
end = max(s.PointerToRawData + s.SizeOfRawData for s in pe.sections)
print("段数据结束于: 0x%x (% .1f MB)" % (end, end / 1e6))
sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
print("证书表: 0x%x .. 0x%x" % (sec.VirtualAddress, sec.VirtualAddress + sec.Size))
print("段末→证书表 之间: %.1f MB" % ((sec.VirtualAddress - end) / 1e6))

# 看段末附近的字节
print("\n段末后 64 字节:", binascii.hexlify(raw[end:end+64]).decode())

# 扫描常见压缩/归档 magic
magics = {
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"MSCF": "CAB",
    b"Rar!\x1a\x07": "RAR",
    b"PK\x03\x04": "ZIP",
    b"\x1f\x8b\x08": "GZIP",
    b"BZh": "BZIP2",
    b"\xfd7zXZ\x00": "XZ",
}
print("\n=== 全文件里的归档 magic（前 20 个偏移）===")
found = []
for mg, name in magics.items():
    off = 0
    while True:
        i = raw.find(mg, off)
        if i < 0:
            break
        found.append((i, name))
        off = i + 1
        if len(found) > 60:
            break
found.sort()
for off, name in found[:30]:
    print("  0x%08x  %s" % (off, name))
