"""IDA 9.x headless Hex-Rays dump for selected functions.

Run: idat.exe -A -S"ida_decomp.py out.txt 0x407B70 0x44FE98" <target>
"""
import os
import sys

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import idc

def main():
    args = sys.argv[1:]
    out = args[0] if args else "ida_decomp.txt"
    targets = args[1:]
    ida_auto.auto_wait()
    chunks = [f"# decompiled functions from {idc.get_input_file_path()}", ""]
    if not ida_hexrays.init_hexrays_plugin():
        chunks.append("! Hex-Rays unavailable")
    for t in targets:
        try:
            ea = int(t, 16) if t.lower().startswith("0x") else idc.get_name_ea_simple(t)
        except ValueError:
            ea = idc.BADADDR
        if ea == idc.BADADDR:
            chunks.append(f"## {t}\n! not found\n")
            continue
        fn = ida_funcs.get_func(ea)
        name = ida_funcs.get_func_name(ea)
        chunks.append(f"## {name} @ {hex(ea)}")
        if not fn:
            chunks.append("! no function at address\n")
            continue
        try:
            cfunc = ida_hexrays.decompile(fn.start_ea)
            text = "\n".join(ida_lines.tag_remove(l.line) for l in cfunc.get_pseudocode())
        except Exception as exc:  # noqa: BLE001
            text = f"! decompile failed: {exc}"
        chunks.append("```c")
        chunks.append(text)
        chunks.append("```")
        chunks.append("")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(chunks) + "\n")
    idc.qexit(0)


main()
