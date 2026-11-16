"""IDA 9.x headless：给定地址，列出交叉引用者并反编译第一层调用者。

用法：idat.exe -A -S"ida_xref.py out.txt 0x10038090,0x100c50f0" <target>
"""
import sys

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import idautils
import idc


def decomp(ea, limit=140):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return "! no function"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return "! decompile None"
        lines = [ida_lines.tag_remove(l.line) for l in cf.get_pseudocode()]
        return "\n".join(lines[:limit]) + ("\n... (truncated)" if len(lines) > limit else "")
    except Exception as exc:                          # noqa: BLE001
        return f"! decompile failed: {exc}"


def main():
    args = sys.argv[1:]
    out = args[0]
    targets = [int(a, 0) for a in args[1].split(",")] if len(args) > 1 else []
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()

    L = [f"# xref 追链: {idc.get_input_file_path()}", ""]
    for t in targets:
        fn = ida_funcs.get_func(t)
        L.append(f"## 目标 {hex(t)}  （函数 {ida_funcs.get_func_name(fn.start_ea) if fn else '?'}）")
        callers = {}
        for x in idautils.XrefsTo(fn.start_ea if fn else t):
            cf = ida_funcs.get_func(x.frm)
            if cf:
                callers.setdefault(cf.start_ea, []).append(x.frm)
        L.append(f"- 被 {len(callers)} 个函数引用：")
        for cea, sites in callers.items():
            L.append(f"  - {ida_funcs.get_func_name(cea)} @ {hex(cea)}  （{len(sites)} 处调用）")
        for cea in list(callers)[:2]:
            L.append(f"\n### 调用者 {ida_funcs.get_func_name(cea)} @ {hex(cea)}")
            L.append("```c")
            L.append(decomp(cea))
            L.append("```")
        L.append("")

    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    idc.qexit(0)


main()
