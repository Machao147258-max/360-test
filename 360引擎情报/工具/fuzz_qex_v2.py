"""qex 容器解析器 fuzz v2 —— 分批 + 逐例实时输出（可监控）

用法:
  python fuzz_qex_v2.py <payload_root> <part> [--limit N]
  part: 1=头字段边界  2=magic 近似  3=长度截断  4=填充/随机  5=全量载荷深挖

监控：每例一行实时 flush，同时追加到 分析_2026-10/fuzz_qex_partN.log
判据（每例都归类，不再丢弃）：
  CRASH  未映射读/写、异常
  HANG   指令数超上限
  SLOW   指令数 > 3× 基线（异常慢路径）
  TYPE   out0 与预期不同（正常应为 0x37；非容器输入可为 0x00/0x01）
  STUB   命中了导入桩（说明走到需要 OS 的路径 → 补环境缺口）
"""
import hashlib
import os
import random
import sys
import time

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED,
                     UC_HOOK_MEM_WRITE_UNMAPPED, UC_MODE_32, UC_PROT_ALL, Uc)
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP,
                               UC_X86_REG_ECX, UC_X86_REG_EDX)

IMG = 0x10000000
STACK = 0x20000000
STACK_SZ = 0x100000
OUTBUF = 0x30000000
SRCBUF = 0x30000800
STUB = 0x40000000
STUB_SZ = 0x10000
SENTINEL = 0xDEAD0000
TARGET = 0x100C50F0
MD = Cs(CS_ARCH_X86, CS_MODE_32)
LOG = None
BASELINE_INS = 1098          # 真实头跑出来的指令数（后面用实测校准）


def say(msg):
    print(msg, flush=True)
    if LOG:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(msg + "\n")


def load_image(uc, path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    uc.mem_map(IMG, (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF, UC_PROT_ALL)
    raw = open(path, "rb").read()
    for s in pe.sections:
        uc.mem_write(IMG + s.VirtualAddress, raw[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData])
    uc.mem_map(STUB, STUB_SZ, UC_PROT_ALL)
    slot = STUB + 0x1000
    uc.mem_write(slot, b"\x31\xc0\xc3")
    names = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in e.imports:
                if not imp.name:
                    continue
                names[slot] = f"{e.dll.decode('latin1')}!{imp.name.decode('latin1')}"
                off = imp.address if imp.address >= IMG else IMG + (imp.address - pe.OPTIONAL_HEADER.ImageBase)
                uc.mem_write(off, slot.to_bytes(4, "little"))
    pe.close()
    return names


def one_run(dll, data, max_ins=300000):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    names = load_image(uc, dll)
    uc.mem_map(0x0, 0x2000, UC_PROT_ALL)                 # TEB（FS 基址默认 0）
    uc.mem_write(0x0, b"\xff\xff\xff\xff")
    uc.mem_write(0x18, (0).to_bytes(4, "little"))
    for addr, size in ((STACK, STACK_SZ), (OUTBUF, 0x1000), (SENTINEL & ~0xFFF, 0x1000)):
        uc.mem_map(addr, size, UC_PROT_ALL)
    uc.mem_write(OUTBUF, b"\x00" * 0x1000)
    uc.mem_write(SRCBUF, data)
    esp = STACK + STACK_SZ - 0x400
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.mem_write(esp, SENTINEL.to_bytes(4, "little"))
    uc.mem_write(esp + 4, OUTBUF.to_bytes(4, "little"))
    uc.reg_write(UC_X86_REG_ECX, SRCBUF)
    uc.reg_write(UC_X86_REG_EDX, len(data))
    st = {"stop": "returned", "stubs": [], "ins": 0, "oob": None}

    def on_code(uc_, addr, size, _u):
        st["ins"] += 1
        if addr == SENTINEL:
            uc_.emu_stop()
            return
        if STUB <= addr < STUB + STUB_SZ:
            st["stubs"].append(names.get(addr, "?"))
            r = int.from_bytes(uc_.mem_read(uc_.reg_read(UC_X86_REG_ESP), 4), "little")
            uc_.reg_write(UC_X86_REG_EAX, 0)
            uc_.reg_write(UC_X86_REG_EIP, r)
            uc_.reg_write(UC_X86_REG_ESP, uc_.reg_read(UC_X86_REG_ESP) + 4)

    def on_bad(uc_, access, address, size, value, _u):
        eip = uc_.reg_read(UC_X86_REG_EIP)
        try:
            dis = " ".join(f"{i.mnemonic} {i.op_str}" for i in list(MD.disasm(uc_.mem_read(eip, 16), eip))[:1])
        except Exception:                                  # noqa: BLE001
            dis = "?"
        st["stop"] = f"{'WRITE' if access == 18 else 'READ'}_UNMAPPED@{address:#x} @EIP={eip:#x} [{dis}]"
        return False

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_bad)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_bad)
    try:
        uc.emu_start(TARGET, SENTINEL, timeout=3_000_000, count=max_ins)
    except Exception as exc:                               # noqa: BLE001
        if st["stop"] == "returned":
            st["stop"] = f"EXC:{type(exc).__name__}"
    if st["ins"] >= max_ins:
        st["stop"] = "HANG"
    return uc.reg_read(UC_X86_REG_EAX), bytes(uc.mem_read(OUTBUF, 8)), st


def classify(out0, st, expect_container):
    tags = []
    if st["stop"].startswith(("READ_UNMAPPED", "WRITE_UNMAPPED", "EXC")):
        tags.append("CRASH")
    if st["stop"] == "HANG":
        tags.append("HANG")
    if st["stubs"]:
        tags.append("STUB:" + st["stubs"][0])
    if st["ins"] > BASELINE_INS * 3:
        tags.append("SLOW")
    ok = (out0 == 0x37) if expect_container else (out0 in (0x00, 0x01, 0x37))
    if not ok:
        tags.append("TYPE")
    return tags


def gen(part, seed_bodies):
    """按 part 生成语料：(expect_container, label, bytes)"""
    out = []
    for sname, head in seed_bodies:
        hdr = bytearray(head[:512].ljust(512, b"\x00"))
        if part == 1:
            for off, lab in ((4, "u32@4"), (8, "u32@8"), (12, "u32@12")):
                for v in (0, 1, 0x100, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF):
                    b = bytearray(hdr); b[off:off + 4] = v.to_bytes(4, "little")
                    out.append((True, f"{sname}|{lab}={v:#x}", bytes(b)))
        elif part == 2:
            for m in (b"\x1e\xf1\x7a\xda", b"\x1e\xf1\x7a\xdb", b"\x1e\xf1\x7a\xd9", b"\x1e\xf1\x7b\xda",
                      b"\x1e\xf2\x7a\xda", b"\x1f\xf1\x7a\xda", b"\x00\xf1\x7a\xda", b"\xdf\x7a\xf1\x1e",
                      b"\x0d\xa7\xaf\x11", b"\x00\x00\x00\x00", b"\xff\xff\xff\xff"):
                b = bytearray(hdr); b[0:4] = m
                out.append((m == b"\x1e\xf1\x7a\xda", f"{sname}|magic={m.hex()}", bytes(b)))
        elif part == 3:
            for n in list(range(1, 17)) + [17, 31, 255, 256, 257, 511, 512]:
                out.append((False, f"{sname}|len={n}", bytes(hdr[:n])))
        elif part == 4:
            for f in (b"\x00", b"\x41", b"\xff", b"\x90", b"\x0f", b"\x80"):
                out.append((False, f"{sname}|fill={f.hex()}x512", f * 512))
            rnd = random.Random(42)
            for i in range(24):
                b = bytearray(hdr)
                for _ in range(rnd.randint(1, 40)):
                    b[rnd.randrange(0, 128)] = rnd.randrange(256)
                out.append((True, f"{sname}|mut#{i}", bytes(b)))
    return out


def main():
    global LOG, BASELINE_INS
    root, part = sys.argv[1], int(sys.argv[2])
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    outdir = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "分析_2026-10")
    os.makedirs(outdir, exist_ok=True)
    LOG = os.path.join(outdir, f"fuzz_qex_part{part}.log")
    open(LOG, "w", encoding="utf-8").close()

    dll = os.path.join(root, "deepscan", "qex", "qex.dll")
    seeds = []
    for rel in ("deepscan/qex/qex.vdb.enc", "deepscan/qex/patt.enc", "deepscan/qex/MacroDef.enc"):
        with open(os.path.join(root, *rel.split("/")), "rb") as fh:
            seeds.append((os.path.basename(rel), fh.read(512)))
    eax, out, st = one_run(dll, seeds[0][1])
    BASELINE_INS = st["ins"]
    say(f"[part{part}] 基线：真实 qex.vdb.enc 头 → EAX={eax:#010x} out0={out[0]:#04x} ins={BASELINE_INS}")

    cases = gen(part, seeds)
    if limit:
        cases = cases[:limit]
    say(f"[part{part}] 用例 {len(cases)} 个，开始（每例一行，实时）")
    t0 = time.time()
    stats = {}
    for i, (expect, label, data) in enumerate(cases, 1):
        eax, out0, st = one_run(dll, data)
        tags = classify(out0[0], st, expect)
        for t in tags:
            stats[t] = stats.get(t, 0) + 1
        mark = "  " if not tags else "!!"
        say(f"{mark} [{i:>3}/{len(cases)}] {label:44s} EAX={eax:#010x} out0={out0[0]:#04x} "
            f"ins={st['ins']:>6} {'|'.join(tags) if tags else 'ok'} {st['stop'][:48] if tags else ''}")
    dt = time.time() - t0
    say(f"[part{part}] 完成 {len(cases)} 例 / {dt:.1f}s / {len(cases)/dt:.1f} 例/秒")
    say(f"[part{part}] 汇总：{'  '.join(f'{k}={v}' for k, v in sorted(stats.items())) or '无异常'}")


if __name__ == "__main__":
    main()
