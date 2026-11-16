"""IDA 9.x headless：驱动分派表 / 入口 / 设备名 提取（第二轮，补第一轮漏项）

第一轮只扫 `mov [reg+disp], offset` 找 IRP_MJ_DEVICE_CONTROL，漏掉了两步写法
（`lea esi, sub_XXX` + `mov [eax+38h], esi`）。本轮改为：

  1) 反编译驱动入口（INF_START_EA）—— 分派表赋值在 Hex-Rays 里直接可见；
  2) 反编译所有引用 IoCreateDevice / IoCreateSymbolicLink 的函数（通常是 DriverEntry/AddDevice）；
  3) 把 \Device\ 宽串解码成可读文本；
  4) 保留第一轮的 `mov [reg+disp], offset` 扫描作为补充。

用法： idat.exe -A -S"ida_drv_entry.py out.txt 0x38" <driver.sys>
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

CONST = re.compile(r"\b0x([0-9A-Fa-f]{6,8})\b")
WATCH_IMPORTS = ("IoCreateDevice", "IoCreateSymbolicLink", "IoCreateDeviceSecure",
                 "FltRegisterFilter", "PsSetCreateProcessNotifyRoutine", "ObRegisterCallbacks",
                 "IoRegisterDeviceInterface")


def wide_text(ea, maxlen=400):
    raw = ida_bytes.get_bytes(ea, maxlen) or b""
    out = bytearray()
    for i in range(0, len(raw) - 1, 2):
        ch = raw[i] | (raw[i + 1] << 8)
        if ch == 0:
            break
        out += chr(ch).encode("utf-8", "replace")
    return raw[:max(2, len(out) * 2)].decode("utf-16-le", "replace").split("\x00")[0]


def decompile_text(ea, limit=200):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return None, "! no function"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return fn, "! decompile returned None"
        lines = [ida_lines.tag_remove(l.line) for l in cf.get_pseudocode()]
        return fn, "\n".join(lines[:limit]) + ("\n... (truncated)" if len(lines) > limit else "")
    except Exception as exc:                          # noqa: BLE001
        return fn, f"! decompile failed: {exc}"


def scan_devctl_writes(disp):
    hits = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or not (seg.perm & 1):
            continue
        ea, end = seg.start_ea, seg.end_ea
        while ea < end:
            insn = ida_ua.insn_t()
            ln = ida_ua.decode_insn(insn, ea)
            if ln <= 0:
                ea += 1
                continue
            if ((NN_mov is None) or insn.itype == NN_mov) and \
                    insn.ops[0].type == ida_ua.o_displ and insn.ops[0].addr == disp:
                tgt = insn.ops[1].value if insn.ops[1].type == ida_ua.o_imm else \
                    (insn.ops[1].addr if insn.ops[1].type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far) else None)
                if tgt:
                    for c in (tgt, tgt + 0x10000):
                        if ida_funcs.get_func(c):
                            hits.append((ea, c))
                            break
            ea += ln
    return hits


def import_xref_funcs():
    """引用关键导入的函数（含 DriverEntry 常见写法）。"""
    out = {}
    for ea, name in idautils.Names():
        base = name.split("__imp_")[-1].split("@")[0]
        if base in WATCH_IMPORTS:
            for x in idautils.XrefsTo(ea):
                fn = ida_funcs.get_func(x.frm)
                if fn:
                    out.setdefault(fn.start_ea, set()).add(base)
    return out


def device_strings():
    out = []
    for s in idautils.Strings():
        try:
            raw = ida_bytes.get_bytes(s.ea, max(1, s.length)) or b""
        except Exception:                              # noqa: BLE001
            raw = b""
        if re.search(rb"\\Device\\|\\DosDevices\\|\\\\\?\\", raw):
            out.append((s.ea, wide_text(s.ea)))
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
                out.append((ea, wide_text(ea)))
            idx = i + len(needle)
    return out


def main():
    args = sys.argv[1:]
    out = args[0] if args else "ida_drv_entry.txt"
    disp = int(args[1], 0) if len(args) > 1 else 0x38
    ida_auto.auto_wait()
    hexrays_ok = ida_hexrays.init_hexrays_plugin()

    L = [f"# driver recon v2: {idc.get_input_file_path()}",
         f"- proc {idc.get_inf_attr(idc.INF_PROCNAME)}  MajorFunction 偏移 {hex(disp)}  "
         f"functions {len(list(idautils.Functions()))}  hexrays={bool(hexrays_ok)}"]

    entry = idc.get_inf_attr(idc.INF_START_EA)
    L.append(f"\n## 入口 DriverEntry @ {hex(entry)}")
    L.append("```c")
    L.append(decompile_text(entry)[1])
    L.append("```")

    L.append("\n## 引用关键导入的函数（IoCreateDevice 等）→ 分派表就在这里")
    for fn_ea, imps in sorted(import_xref_funcs().items()):
        nm = ida_funcs.get_func_name(fn_ea)
        L.append(f"\n### {nm} @ {hex(fn_ea)}   导入: {', '.join(sorted(imps))}")
        L.append("```c")
        L.append(decompile_text(fn_ea)[1])
        L.append("```")

    L.append("\n## 补充：mov [reg+disp], offset 扫描（分派写入点）")
    hits = scan_devctl_writes(disp)
    L.extend([f"- {hex(site)} → {hex(t)} {ida_funcs.get_func_name(t)}" for site, t in hits]
             or ["（无）"])
    for _s, t in hits[:2]:
        L.append(f"\n### 分派候选 {ida_funcs.get_func_name(t)} @ {hex(t)}")
        text = decompile_text(t)[1]
        L.append("```c")
        L.append(text)
        L.append("```")
        consts = sorted({int(m, 16) for m in CONST.findall(text)})
        for c in consts:
            if c >= 0x10000:
                L.append(f"  常量 {hex(c)} → device={(c >> 16) & 0xFFFF:#x} access={c & 3} "
                         f"function={(c >> 2) & 0xFFF:#x} method={(c >> 14) & 3}")

    L.append("\n## 设备名（\\Device\\ / \\DosDevices\\ 宽串解码）")
    for ea, txt in device_strings():
        refs = [hex(x.frm) for x in idautils.XrefsTo(ea)][:6]
        L.append(f"- {hex(ea)}  {txt!r}  refs={refs}")

    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    idc.qexit(0)


main()
