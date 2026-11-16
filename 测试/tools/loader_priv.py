# -*- coding: utf-8 -*-
# loader_priv.py -- 跑 priv_sc shellcode, 用【整张令牌权限表】前后对比证明翻转
#   用法: python tools\loader_priv.py [bin] [PrivilegeName]
#     默认 bin\priv_sc.bin  SeDebugPrivilege
#   流程: 打印表 -> 手动禁用目标权限 -> 打印表 -> 跑 shellcode -> 打印表
import ctypes, os, sys, struct
from ctypes import wintypes

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)
binarg = sys.argv[1] if len(sys.argv) > 1 else os.path.join("bin", "priv_sc.bin")
TARGET = sys.argv[2] if len(sys.argv) > 2 else "SeDebugPrivilege"
path = binarg if os.path.isabs(binarg) else os.path.join(ROOT, binarg)
sc = open(path, "rb").read()

adv = ctypes.WinDLL("advapi32")
k32 = ctypes.windll.kernel32

TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
SE_PRIVILEGE_ENABLED = 0x0002
SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x0001
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
adv.LookupPrivilegeNameA.argtypes = [wintypes.LPCSTR, ctypes.POINTER(LUID), wintypes.LPSTR, ctypes.POINTER(wintypes.DWORD)]
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
    adv.LookupPrivilegeValueA(None, name.encode(), ctypes.byref(l))
    return l

def set_priv(h, luid, enable):
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED if enable else 0
    adv.AdjustTokenPrivileges(h, False, ctypes.byref(tp), 0, None, None)

def _privs(h):
    need = wintypes.DWORD(0)
    adv.GetTokenInformation(h, TokenPrivileges, None, 0, ctypes.byref(need))
    buf = ctypes.create_string_buffer(need.value)
    adv.GetTokenInformation(h, TokenPrivileges, buf, need.value, ctypes.byref(need))
    n = struct.unpack_from("<I", buf, 0)[0]
    out, off = [], 4
    for _ in range(n):
        low, high, attr = struct.unpack_from("<IiI", buf, off); off += 12
        nb = ctypes.create_string_buffer(256); nl = wintypes.DWORD(256)
        adv.LookupPrivilegeNameA(None, ctypes.byref(LUID(low, high)), nb, ctypes.byref(nl))
        out.append((nb.value.decode("ascii", "replace"), bool(attr & SE_PRIVILEGE_ENABLED)))
    return out

def table(h, title):
    print(f"\n--- {title} ---")
    for name, en in _privs(h):
        mark = "  <<==" if name == TARGET else ""
        print(f"    {'ENABLED ' if en else 'disabled'}  {name}{mark}")

h = open_tok()
print(f"[*] shellcode {len(sc)} bytes   target privilege = {TARGET}")
table(h, "BEFORE (原状)")
luid = luid_of(TARGET)
set_priv(h, luid, False)
table(h, "手动 DISABLED 后")

k32.VirtualAlloc.restype = ctypes.c_void_p
addr = k32.VirtualAlloc(0, len(sc), 0x3000, 0x40)
if not addr:
    raise SystemExit("VirtualAlloc failed: %d" % k32.GetLastError())
ctypes.memmove(addr, sc, len(sc))
print(f"\n[*] running shellcode @ 0x{addr:X} ...")
ctypes.CFUNCTYPE(None)(addr)()
table(h, "shellcode 运行后")

state = dict(_privs(h)).get(TARGET, None)
print(f"\n[+] {TARGET} final enabled = {state}")
print("    -> shellcode 成功启用了该权限" if state else "    -> 未启用 (?)")
