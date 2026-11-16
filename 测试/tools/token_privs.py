# -*- coding: utf-8 -*-
# token_privs.py -- 枚举【当前进程令牌】的权限; 可选用纯 Python 启用/禁用一个 (对照用)
#   用法:
#     python tools\token_privs.py                      # 只列
#     python tools\token_privs.py --enable  SeBackupPrivilege
#     python tools\token_privs.py --disable SeBackupPrivilege
import ctypes, struct, argparse
from ctypes import wintypes

adv = ctypes.WinDLL("advapi32")
k32 = ctypes.windll.kernel32

TOKEN_QUERY             = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TokenPrivileges = 3
TokenElevation  = 20

SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x0001
SE_PRIVILEGE_ENABLED            = 0x0002
SE_PRIVILEGE_REMOVED            = 0x0004
SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

SENSITIVE = {
    "SeDebugPrivilege", "SeImpersonatePrivilege", "SeBackupPrivilege",
    "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
    "SeManageVolumePrivilege", "SeSecurityPrivilege", "SeTcbPrivilege",
    "SeCreateTokenPrivilege", "SeAssignPrimaryTokenPrivilege", "SeRelabelPrivilege",
}

class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

k32.GetCurrentProcess.restype = wintypes.HANDLE
adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
adv.LookupPrivilegeNameA.argtypes = [wintypes.LPCSTR, ctypes.POINTER(LUID), wintypes.LPSTR, ctypes.POINTER(wintypes.DWORD)]
adv.LookupPrivilegeValueA.argtypes = [wintypes.LPCSTR, wintypes.LPCSTR, ctypes.POINTER(LUID)]
adv.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p,
                                      wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]

ap = argparse.ArgumentParser()
ap.add_argument("--enable",  metavar="NAME", help="启用指定权限 (纯 Python, 对照用)")
ap.add_argument("--disable", metavar="NAME", help="禁用指定权限")
args = ap.parse_args()

def open_token(adjust=False):
    acc = TOKEN_QUERY | (TOKEN_ADJUST_PRIVILEGES if adjust else 0)
    h = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), acc, ctypes.byref(h)):
        raise ctypes.WinError()
    return h

def whoami():
    buf = ctypes.create_unicode_buffer(256); n = wintypes.DWORD(256)
    adv.GetUserNameW(buf, ctypes.byref(n)); return buf.value

def elevation(h):
    out = wintypes.DWORD(0); ret = wintypes.DWORD(0)
    adv.GetTokenInformation(h, TokenElevation, ctypes.byref(out), ctypes.sizeof(out), ctypes.byref(ret))
    return bool(out.value)

def adjust(h, name, enable):
    luid = LUID()
    if not adv.LookupPrivilegeValueA(None, name.encode(), ctypes.byref(luid)):
        return f"LookupPrivilegeValueA 失败: {ctypes.WinError()}"
    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED if enable else 0
    k32.SetLastError(0)
    if not adv.AdjustTokenPrivileges(h, False, ctypes.byref(tp), 0, None, None):
        return f"AdjustTokenPrivileges 失败: {ctypes.WinError()}"
    err = k32.GetLastError()
    if err:
        return f"调用返回成功但 GetLastError={err} (1300=ERROR_NOT_ALL_ASSIGNED: 令牌不含该权限)"
    return "OK"

# 先做可选调整
if args.enable or args.disable:
    h2 = open_token(adjust=True)
    if args.enable:
        print(f"[*] enable  {args.enable}: {adjust(h2, args.enable, True)}")
    if args.disable:
        print(f"[*] disable {args.disable}: {adjust(h2, args.disable, False)}")

h = open_token()
print("=" * 74)
print(f"  User     : {whoami()}")
print(f"  Elevated : {elevation(h)}")
print("=" * 74)

need = wintypes.DWORD(0)
adv.GetTokenInformation(h, TokenPrivileges, None, 0, ctypes.byref(need))
buf = ctypes.create_string_buffer(need.value)
adv.GetTokenInformation(h, TokenPrivileges, buf, need.value, ctypes.byref(need))
count = struct.unpack_from("<I", buf, 0)[0]

print(f"  当前进程令牌持有 {count} 项权限:\n")
print(f"  {'#':>2}  {'状态':<9} {'权限名':<40} 敏感")
print("  " + "-" * 70)
enabled_n = 0
off = 4
for i in range(count):
    low, high, attr = struct.unpack_from("<IiI", buf, off); off += 12
    nb = ctypes.create_string_buffer(256); nl = wintypes.DWORD(256)
    adv.LookupPrivilegeNameA(None, ctypes.byref(LUID(low, high)), nb, ctypes.byref(nl))
    name = nb.value.decode("ascii", "replace")
    en = bool(attr & SE_PRIVILEGE_ENABLED); enabled_n += en
    tags = []
    if attr & SE_PRIVILEGE_ENABLED_BY_DEFAULT: tags.append("default")
    if attr & SE_PRIVILEGE_REMOVED: tags.append("removed")
    if attr & SE_PRIVILEGE_USED_FOR_ACCESS: tags.append("used")
    print(f"  {i:>2}  {'ENABLED' if en else 'disabled':<9} {name:<40} {'★' if name in SENSITIVE else ''}"
          + (("  [" + ",".join(tags) + "]") if tags else ""))
print("  " + "-" * 70)
print(f"  => 共 {count} 项, ENABLED {enabled_n}, disabled {count - enabled_n}")
print("  ★ = 典型敏感权限; disabled 的可被(持有该权限的进程)启用")
