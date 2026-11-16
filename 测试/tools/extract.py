# -*- coding: utf-8 -*-
# extract.py -- 从 .obj 的指定段抠出 shellcode 字节 + 反汇编 + 空字节定位
# 用法: python tools\extract.py [obj] [section] [out.bin]
#   默认: build\shellcode.obj / .text$sc / bin\shellcode.bin
#   汇编变体: python tools\extract.py build\calc_nf.obj .text$mn bin\shellcode_asm.bin
import struct, os, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)                                  # 项目根
obj     = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "shellcode.obj")
secname = sys.argv[2] if len(sys.argv) > 2 else ".text$sc"
out     = sys.argv[3] if len(sys.argv) > 3 else os.path.join("bin", "shellcode.bin")
obj = obj if os.path.isabs(obj) else os.path.join(ROOT, obj)
out = out if os.path.isabs(out) else os.path.join(ROOT, out)

data = open(obj, "rb").read()
machine, nsec, _td, _syms, _nsym, _opthdr, _chars = struct.unpack_from("<HHIIIHH", data, 0)
off = 20 + struct.unpack_from("<H", data, 16)[0]

target = None
print(f"[*] COFF sections in {os.path.basename(obj)}:")
for i in range(nsec):
    b = off + i * 40
    name = data[b:b + 8].rstrip(b"\x00").decode("latin1")
    vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
    print(f"    {name:<16} rawsize={rawsize:<6} rawptr={rawptr}")
    if name == secname:
        target = (rawptr, rawsize)

assert target, f"未找到段 {secname}"
rawptr, rawsize = target
sc = bytearray(data[rawptr:rawptr + rawsize])
while sc and sc[-1] in (0xCC, 0x90, 0x00):   # 去尾部对齐填充
    sc.pop()
sc = bytes(sc)

print(f"\n[+] {secname} -> {len(sc)} bytes")
print(f"[*] null bytes: {'YES @ ' + str([i for i,b in enumerate(sc) if b==0]) if 0 in sc else 'NONE ✔'}")
hexstr = "".join(f"\\x{b:02x}" for b in sc)
print(f"[*] bytes:\n{hexstr}\n")

md = Cs(CS_ARCH_X86, CS_MODE_64)
print("[*] disassembly:")
for ins in md.disasm(sc, 0):
    raw = sc[ins.address:ins.address + ins.size]
    print(f"  {ins.address:04X}  {raw.hex():<24} {ins.mnemonic:<7} {ins.op_str}")

os.makedirs(os.path.dirname(out), exist_ok=True)
open(out, "wb").write(sc)
print(f"\n[+] wrote {out}")
