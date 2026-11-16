# -*- coding: utf-8 -*-
# loader_priv.py -- 验证 pc_priv shellcode 确实启用了 SeDebugPrivilege
#   流程: 查当前状态 -> 禁用 -> 跑 shellcode -> 再查 (期望 禁用->启用)
import ctypes, os, sys, struct
from ctypes import wintypes

BASE = os.path.dirname(os.path.abspath(__file__))
f = sys.argv[1] if len(sys.argv) > 1 else "priv_sc.bin"
path = f if os.path.isabs(f) else os.path.join(BASE, f)
sc = open(path, "rb").read()

adv = ctypes.WinDLL("advapi32")
k32 = ctypes.windll.kernel32

TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x0002
TokenPrivileges = 3

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

k32.GetCurrentProcess.restype = wintypes.HANDLE
adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
adv.LookupPrivilegeValueA.argtypes = [wintypes.LPCSTR, wintypes.LPCSTR, ctypes.POINTER(LUID)]
adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p,
                                      wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

def open_tok():
    h = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h)):
        raise ctypes.WinError()
    return h

def luid_of(name):
    l = LUID()
    if not adv.LookupPrivilegeValueA(None, name.encode(), ctypes.byref(l)):
        raise ctypes.WinError()
    return l

def set_priv(h, luid, enable):
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED if enable else 0
    adv.AdjustTokenPrivileges(h, False, ctypes.byref(tp), 0, None, None)

def is_enabled(h, luid):
    need = wintypes.DWORD(0)
    adv.GetTokenInformation(h, TokenPrivileges, None, 0, ctypes.byref(need))
    buf = ctypes.create_string_buffer(need.value)
    if not adv.GetTokenInformation(h, TokenPrivileges, buf, need.value, ctypes.byref(need)):
        raise ctypes.WinError()
    n = struct.unpack_from("<I", buf, 0)[0]
    off = 4
    for _ in range(n):
        low, high, attr = struct.unpack_from("<IiI", buf, off)
        if low == luid.LowPart and high == luid.HighPart:
            return bool(attr & SE_PRIVILEGE_ENABLED)
        off += 12
    return None

h = open_tok()
luid = luid_of("SeDebugPrivilege")
print(f"[*] shellcode {len(sc)} bytes")
print(f"[*] SeDebugPrivilege BEFORE     : enabled={is_enabled(h, luid)}")
set_priv(h, luid, False)
print(f"[*] manually DISABLED           : enabled={is_enabled(h, luid)}")

k32.VirtualAlloc.restype = ctypes.c_void_p
addr = k32.VirtualAlloc(0, len(sc), 0x3000, 0x40)
if not addr:
    raise SystemExit("VirtualAlloc failed: %d" % k32.GetLastError())
ctypes.memmove(addr, sc, len(sc))
print(f"[*] running shellcode @ 0x{addr:X} ...")
ctypes.CFUNCTYPE(None)(addr)()

print(f"[+] SeDebugPrivilege AFTER shellcode: enabled={is_enabled(h, luid)}")
print("    -> shellcode enabled the privilege" if is_enabled(h, luid) else "    -> NOT enabled (?)")
