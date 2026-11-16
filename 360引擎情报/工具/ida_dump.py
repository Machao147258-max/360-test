"""IDA 9.x headless recon dump: module facts, notable import xrefs, string stats.

Run: idat.exe -A -S"ida_dump.py out.txt" <target>
IDA 9.x requires explicit module imports (see IDA94 CLI notes).
"""
import os
import sys

import ida_auto
import ida_bytes
import ida_funcs
import ida_segment
import idautils
import idc

WATCH = {
    "DeviceIoControl", "ZwQuerySystemInformation", "NtQueryInformationProcess",
    "ZwProtectVirtualMemory", "WinVerifyTrust", "CreateProcessW", "CreateProcessAsUserW",
    "CreateServiceW", "RegSetValueExW", "RegCreateKeyExW", "InternetOpenUrlW",
    "WinHttpSendRequest", "NdrClientCall2", "NdrAsyncClientCall", "CreateMutexW",
    "OpenProcess", "ReadProcessMemory", "WriteProcessMemory", "SetWindowsHookExW",
    "CryptEncrypt", "BCryptEncrypt", "GetSystemFirmwareTable", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "LoadLibraryW", "GetProcAddress", "CreateToolhelp32Snapshot",
}


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(idc.get_input_file_path()), "ida_dump.txt")
    ida_auto.auto_wait()

    lines = [f"# IDA recon: {idc.get_input_file_path()}",
             f"- proc: {idc.get_inf_attr(idc.INF_PROCNAME)}"]
    segs = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        perm = ("R" if seg.perm & 4 else "") + ("W" if seg.perm & 2 else "") + ("X" if seg.perm & 1 else "")
        segs.append(f"  {ida_segment.get_segm_name(seg)} {hex(seg.start_ea)}-{hex(seg.end_ea)} {perm}")
    lines.append(f"- segments ({len(segs)}):")
    lines.extend(segs)

    funcs = list(idautils.Functions())
    lines.append(f"- functions: {len(funcs)}")

    # string inventory
    strs = []
    try:
        sc = idautils.Strings()
        sc.setup(strtypes=[0, 1, 2])
        for s in sc:
            strs.append((s.ea, str(s)))
    except Exception as exc:  # noqa: BLE001
        lines.append(f"- string scan failed: {exc}")
    lines.append(f"- strings: {len(strs)}")

    # named symbols of interest and who calls them
    hits = {}
    for ea, name in idautils.Names():
        base = name.split("_")[-1] if name.startswith("__imp_") else name
        base = base.split("@")[0]
        if base in WATCH:
            callers = []
            for xref in idautils.XrefsTo(ea):
                fn = ida_funcs.get_func(xref.frm)
                callers.append(ida_funcs.get_func_name(fn.start_ea) if fn else hex(xref.frm))
            hits.setdefault(base, {"ea": ea, "callers": callers})
    lines.append(f"- watched API hits: {len(hits)}")
    for api, info in sorted(hits.items()):
        lines.append(f"  [{api}] @ {hex(info['ea'])} callers={len(info['callers'])}")
        for c in info["callers"][:12]:
            lines.append(f"      <- {c}")

    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    idc.qexit(0)


main()
