"""IDA 9.x headless：反编译 IOCTL 派发函数 + 它调用的所有 handler（一层）

用法：idat.exe -A -S"ida_ioctl_handlers.py out.txt 0x2F2EC" <driver.sys>
输出：派发函数全文 + 每个被调函数的「缓冲区/长度/探查」相关行（命中才算，避免刷屏）
"""
import re
import sys

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import idautils
import idc

KEY = re.compile(r"(InputBufferLength|OutputBufferLength|SystemBuffer|Type3InputBuffer|"
                 r"UserBuffer|ProbeFor|MmIsAddressValid|MmGetSystemAddress|IoControlCode|"
                 r"Parameters|memcpy|memmove|RtlCopy|v\w+\s*\[|MdlAddress|Irp->)", re.I)


def decomp(ea):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return None, "no function"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return None, "decompile None"
        return [ida_lines.tag_remove(l.line) for l in cf.get_pseudocode()], fn
    except Exception as exc:                                  # noqa: BLE001
        return None, f"decompile failed: {exc}"


def main():
    args = sys.argv[1:]
    out, va = args[0], int(args[1], 0)
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()

    L = [f"# IOCTL handler 审计: {idc.get_input_file_path()}  入口 {va:#x}", ""]
    lines, fn = decomp(va)
    if lines is None:
        L.append(f"入口反编译失败: {fn}")
    else:
        L.append(f"## 派发函数 {ida_funcs.get_func_name(va)} @ {hex(fn.start_ea)}（全文 {len(lines)} 行）")
        L.append("```c")
        L.extend(lines)
        L.append("```")
        callees = sorted({c for c in idautils.CodeRefsFrom(fn.start_ea, 1)})
        targets = {}
        for ea in range(fn.start_ea, fn.end_ea):
            for c in idautils.CodeRefsFrom(ea, 1):
                f2 = ida_funcs.get_func(c)
                if f2 and f2.start_ea != fn.start_ea:
                    targets[f2.start_ea] = ida_funcs.get_func_name(f2.start_ea)
        L.append(f"\n## 被调用函数 {len(targets)} 个")
        for tea, name in sorted(targets.items()):
            sub, f2 = decomp(tea)
            L.append(f"\n### {name} @ {hex(tea)}")
            if sub is None:
                L.append(f"（{f2}）")
                continue
            hits = [l for l in sub if KEY.search(l)]
            L.append(f"- 总行数 {len(sub)}，命中关键行 {len(hits)}")
            L.append("```c")
            L.extend(hits[:80] if hits else sub[:25])
            L.append("```")

    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    idc.qexit(0)


main()
