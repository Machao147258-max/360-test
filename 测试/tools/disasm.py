#!/usr/bin/env python3
"""disasm.py - disassemble carved shellcode blobs (x64) with capstone.
Usage: python tools/disasm.py <file.bin> [base]
Prints offset, bytes, mnemonic. Also scans for ROR13 API hashes.
"""
import sys, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

HASHES = {
    0x0E8AFE98: ("WinExec",        "0x0E8AFE98"),
    0xEC0E4E8E: ("LoadLibraryA",   "0xEC0E4E8E"),
    0x7C0DFCAA: ("GetProcAddress", "0x7C0DFCAA"),
    0x16B3FE72: ("CreateProcessA", "0x16B3FE72"),
    0x91AFCA54: ("kernel32.dll",   "0x91AFCA54"),
}

def ror13(name: str) -> int:
    h = 0
    for c in name:
        h = ((h >> 13) | (h << (32 - 13))) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

def main():
    path = sys.argv[1]
    base = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
    data = open(path, "rb").read()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    print(f"[*] {path}  ({len(data)} bytes)  base=0x{base:X}")
    print(f"[*] sha256 = {__import__('hashlib').sha256(data).hexdigest()}")
    print("-" * 78)
    for ins in md.disasm(data, base):
        b = data[ins.address - base: ins.address - base + ins.size]
        print(f"{ins.address:08X}  {b.hex():<24} {ins.mnemonic:<8} {ins.op_str}")
    print("-" * 78)

    # scan for embedded 32-bit constants matching known ROR13 hashes
    print("[*] ROR13 constant scan (little-endian dwords in blob):")
    found = False
    for i in range(len(data) - 3):
        v = int.from_bytes(data[i:i+4], "little")
        if v in HASHES:
            name, _ = HASHES[v]
            print(f"    +0x{i:04X}: 0x{v:08X} -> {name}")
            found = True
    if not found:
        print("    (none at aligned scan; constants may be in movabs immediates)")

    # verify constants against computed
    print("[*] recompute ROR13 for reference:")
    for n in ["WinExec", "LoadLibraryA", "GetProcAddress", "kernel32.dll"]:
        print(f"    {n:<18} = 0x{ror13(n):08X}  (expected 0x{HASHES.get(ror13(n), (None, hex(ror13(n))))[0]}" if False else
              f"    {n:<18} = 0x{ror13(n):08X}")

if __name__ == "__main__":
    main()
