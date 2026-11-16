"""IDA 9.x headless：驱动 IRP_MJ_DEVICE_CONTROL 分派函数定位 + IOCTL 常量提取。

原理：
  驱动在 DriverEntry 里写 DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] 时，
  编译结果是一句 `mov [reg+disp], offset handler`，x86 的 disp = 14*4 = 0x38，
  x64 的 disp = 14*8 = 0x70。扫这个写操作即可拿到分派函数，再反编译它取 switch 常量。

用法：
  idat.exe -A -S"ida_drv_ioctl.py out.txt 0x38" <driver.sys>      # x86 传 0x38，x64 传 0x70
  （可选）最后追加若干地址，作为"额外反编译"列表

输出：分派候选、其伪代码、伪代码里出现的大常量（疑似 IOCTL）、以及 \Device\ 字符串及其引用。
"""
import os
import re
import sys

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_lines
import ida_segment
import ida_ua
import idautils
import idc

try:
    import ida_allins
    NN_mov = ida_allins.NN_mov
except Exception:                                    # noqa: BLE001
    NN_mov = None

DEV_STR = re.compile(rb"\\Device\\[A-Za-z0-9_]+|\\DosDevices\\[A-Za-z0-9_]+|\\\?\?\\[A-Za-z0-9_]+")
CONST = re.compile(r"\b0x([0-9A-Fa-f]{6,8})\b")


def decompile_text(ea, limit=120):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return "! no function"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return "! decompile returned None"
        lines = [ida_lines.tag_remove(l.line) for l in cf.get_pseudocode()]
        return "\n".join(lines[:limit]) + ("\n... (truncated)" if len(lines) > limit else "")
    except Exception as exc:                          # noqa: BLE001
        return f"! decompile failed: {exc}"


def find_devctl_handlers(disp):
    """扫全代码段里 `mov [reg+disp], offset` 形态，收集 handler 候选。"""
    hits = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or not (seg.perm & 1):             # 只要可执行段
            continue
        ea = seg.start_ea
        end = seg.end_ea
        while ea < end:
            insn = ida_ua.insn_t()
            ln = ida_ua.decode_insn(insn, ea)
            if ln <= 0:
                ea += 1
                continue
            itype_ok = (NN_mov is None) or (insn.itype == NN_mov)
            if itype_ok and insn.ops[0].type == ida_ua.o_displ and insn.ops[0].addr == disp:
                tgt = None
                if insn.ops[1].type == ida_ua.o_imm:
                    tgt = insn.ops[1].value
                elif insn.ops[1].type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                    tgt = insn.ops[1].addr
                if tgt:
                    # 立即数可能是"未重定位偏移"，用 IDA 的 image base 换算
                    cands = {tgt}
                    try:
                        cands.add(tgt + ida_segment.get_first_seg().start_ea)
                        cands.add(idc.get_inf_attr(idc.INF_MIN_EA) + tgt)
                    except Exception:                  # noqa: BLE001
                        pass
                    for c in sorted(cands):
                        if ida_funcs.get_func(c):
                            hits.append((ea, c))
                            break
            ea += ln
    return hits


def device_strings():
    out = []
    for s in idautils.Strings():
        try:
            raw = ida_bytes.get_bytes(s.ea, max(1, s.length)) or b""
        except Exception:                              # noqa: BLE001
            raw = b""
        if DEV_STR.search(raw):
            out.append((s.ea, str(s)))
    # idautils.Strings 未必枚举到全部宽串，补扫数据段里的 UTF-16LE \Device\
    needle = "\\Device\\".encode("utf-16-le")
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or (seg.perm & 1):
            continue
        data = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea) or b""
        idx = 0
        while True:
            i = data.find(needle, idx)
            if i < 0:
                break
            ea = seg.start_ea + i
            if not any(abs(ea - e) < 16 for e, _ in out):
                out.append((ea, "<wide \\Device\\>"))
            idx = i + len(needle)
    return out


def main():
    args = sys.argv[1:]
    out = args[0] if args else "ida_drv_ioctl.txt"
    disp = int(args[1], 0) if len(args) > 1 else 0x38
    extra = [int(a, 0) for a in args[2:]] if len(args) > 2 else []
    ida_auto.auto_wait()

    L = [f"# driver recon: {idc.get_input_file_path()}",
         f"- proc: {idc.get_inf_attr(idc.INF_PROCNAME)}  MajorFunction 偏移: {hex(disp)}"]

    funcs = list(idautils.Functions())
    L.append(f"- functions: {len(funcs)}")

    if not ida_hexrays.init_hexrays_plugin():
        L.append("! Hex-Rays 不可用（只能做交叉引用统计）")

    L.append("\n## MajorFunction[IRP_MJ_DEVICE_CONTROL] 写入点（分派候选）")
    cands = find_devctl_handlers(disp)
    if not cands:
        L.append("（未命中：可能是 lea/mov 两步写法，或分派表在数据段动态填充）")
    for site, tgt in cands:
        L.append(f"- 写入点 {hex(site)}  →  handler {hex(tgt)}  {ida_funcs.get_func_name(tgt)}")

    seen = set()
    for _site, tgt in cands:
        if tgt in seen:
            continue
        seen.add(tgt)
        L.append(f"\n## 分派函数 {ida_funcs.get_func_name(tgt)} @ {hex(tgt)}")
        text = decompile_text(tgt)
        L.append("```c")
        L.append(text)
        L.append("```")
        consts = sorted({int(m, 16) for m in CONST.findall(text)})
        if consts:
            L.append("疑似 IOCTL / 常量：" + ", ".join(hex(c) for c in consts))
            ctl = []
            for c in consts:
                if c >= 0x10000:
                    dev = (c >> 16) & 0xFFFF
                    access = c & 3
                    func = (c >> 2) & 0xFFF
                    method = (c >> 14) & 3
                    ctl.append(f"  {hex(c)} → device={hex(dev)} access={access} "
                               f"function={hex(func)} method={method}")
            L.extend(ctl)

    for ea in extra:
        L.append(f"\n## 额外反编译 @ {hex(ea)}")
        L.append("```c")
        L.append(decompile_text(ea))
        L.append("```")

    L.append("\n## \\Device\\ 设备名字符串及其引用")
    for ea, s in device_strings():
        refs = [hex(x.frm) for x in idautils.XrefsTo(ea)][:6]
        L.append(f"- {hex(ea)}  {s}   refs={refs}")

    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    idc.qexit(0)


main()
