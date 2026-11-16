"""qex 容器解析器 fuzz（补环境内循环执行，离线、不装不跑产品）

被测：qex.dll 的容器识别/解析函数 sub_100C50F0 @ 0x100c50f0（fastcall，已验证正确约定）
环境 shim：0 地址页当 TEB（SEH）+ IAT 全指向自建桩页（上一轮踩出来的两处必需补丁）
判据：
  · crash        —— Unicorn 异常（未映射读/写、非法指令）
  · hang         —— 指令数超上限
  · oob-write    —— 写出到 out 缓冲 0x1000 之外（越界写迹象）
  · type-changed —— 输出类型码 与 0x37 不同
变异策略（系统化 + 少量随机）：
  A. 头字段边界：u32@4 / u32@8 / u32@12 → 0, 1, 0x100, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF, ±1
  B. magic 近似：正确 / 差 1 字节 / 0x0DA7AF11E（大端） / 全 0 / 全 FF
  C. Size 截断：1..16 字节头
  D. 全字节填充：0x00 / 0x41 / 0xFF / 随机
"""
import os
import random
import sys

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


def load_image(uc, path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    sz = pe.OPTIONAL_HEADER.SizeOfImage
    uc.mem_map(IMG, (sz + 0xFFF) & ~0xFFF, UC_PROT_ALL)
    raw = open(path, "rb").read()
    for s in pe.sections:
        uc.mem_write(IMG + s.VirtualAddress,
                     raw[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData])
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


def setup_teb(uc):
    """裸 Unicorn 的 FS 基址为 0，且 2.x 不允许写 FS_BASE → 把 0 页映射出来当 TEB。"""
    base = 0x0
    uc.mem_map(base, 0x2000, UC_PROT_ALL)
    uc.mem_write(base + 0x00, b"\xff\xff\xff\xff")          # SEH 链末端
    uc.mem_write(base + 0x18, base.to_bytes(4, "little"))   # TEB 自指针
    uc.mem_write(base + 0x04, (base + 0x1FF0).to_bytes(4, "little"))


def one_run(dll, data, max_ins=200000):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    names = load_image(uc, dll)
    for addr, size in ((STACK, STACK_SZ), (OUTBUF, 0x1000), (SENTINEL & ~0xFFF, 0x1000)):
        try:
            uc.mem_map(addr, size, UC_PROT_ALL)
        except Exception:                                      # noqa: BLE001
            pass
    setup_teb(uc)
    uc.mem_write(OUTBUF, b"\x00" * 0x1000)
    uc.mem_write(SRCBUF, data + b"\x00" * max(0, 512 - len(data)))
    esp = STACK + STACK_SZ - 0x400
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.mem_write(esp, SENTINEL.to_bytes(4, "little"))
    uc.mem_write(esp + 4, OUTBUF.to_bytes(4, "little"))
    uc.reg_write(UC_X86_REG_ECX, SRCBUF)
    uc.reg_write(UC_X86_REG_EDX, len(data))
    state = {"stop": "returned", "stubs": [], "oob": 0, "ins": 0}

    def on_code(uc_, addr, size, _u):
        state["ins"] += 1
        if addr == SENTINEL:
            uc_.emu_stop()
            return
        if STUB <= addr < STUB + STUB_SZ:
            state["stubs"].append(names.get(addr, "?"))
            r = int.from_bytes(uc_.mem_read(uc_.reg_read(UC_X86_REG_ESP), 4), "little")
            uc_.reg_write(UC_X86_REG_EAX, 0)
            uc_.reg_write(UC_X86_REG_EIP, r)
            uc_.reg_write(UC_X86_REG_ESP, uc_.reg_read(UC_X86_REG_ESP) + 4)

    def on_bad(uc_, access, address, size, value, _u):
        eip = uc_.reg_read(UC_X86_REG_EIP)
        try:
            ins = " ".join(f"{i.mnemonic} {i.op_str}" for i in list(MD.disasm(uc_.mem_read(eip, 16), eip))[:1])
        except Exception:                                      # noqa: BLE001
            ins = "?"
        state["stop"] = f"{'WRITE' if access == 18 else 'READ'}_UNMAPPED@{address:#x} @EIP={eip:#x} [{ins}]"
        return False

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_bad)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_bad)
    try:
        uc.emu_start(TARGET, SENTINEL, timeout=2_000_000, count=max_ins)
    except Exception as exc:                                   # noqa: BLE001
        if state["stop"] == "returned":
            state["stop"] = f"EXC:{type(exc).__name__}"
    if state["ins"] >= max_ins:
        state["stop"] = "HANG(指令数上限)"
    return uc.reg_read(UC_X86_REG_EAX), bytes(uc.mem_read(OUTBUF, 4)), state


def corpus(seed_head):
    c = []
    add = lambda n, b: c.append((n, b))
    hdr = bytearray(seed_head)
    for off, label in ((4, "u32@4"), (8, "u32@8"), (12, "u32@12")):
        for v in (0, 1, 0x100, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF):
            b = bytearray(hdr)
            b[off:off + 4] = v.to_bytes(4, "little")
            add(f"{label}={v:#x}", bytes(b))
    for m in (b"\x1e\xf1\x7a\xda", b"\x1e\xf1\x7a\xdb", b"\x1e\xf1\x7b\xda", b"\xdf\x7a\xf1\x1e",
              b"\x0d\xa7\xaf\x11", b"\x00\x00\x00\x00", b"\xff\xff\xff\xff"):
        b = bytearray(hdr)
        b[0:4] = m
        add("magic=" + m.hex(), bytes(b))
    for n in range(1, 17):
        add(f"truncated={n}B", bytes(hdr[:n]))
    for fill in (b"\x00", b"\x41", b"\xff"):
        add("fill=" + fill.hex(), fill * 512)
    rnd = random.Random(1337)
    for i in range(20):
        b = bytearray(hdr)
        for _ in range(rnd.randint(1, 20)):
            b[rnd.randrange(0, 64)] = rnd.randrange(256)
        add(f"random-mut#{i}", bytes(b))
    return c


def main():
    root = sys.argv[1]
    dll = os.path.join(root, "deepscan", "qex", "qex.dll")
    heads = []
    for rel in ("deepscan/qex/qex.vdb.enc", "deepscan/qex/patt.enc", "deepscan/qex/MacroDef.enc"):
        with open(os.path.join(root, *rel.split("/")), "rb") as fh:
            heads.append(fh.read(512))
    print(f"被测: {dll}  函数: {TARGET:#x}  语料: 3 个真实 .enc 头 × 系统化变异")
    total = crash = hang = oob = tchg = 0
    interesting = []
    for seed_name, seed in (("qex.vdb.enc", heads[0]), ("patt.enc", heads[1]), ("MacroDef.enc", heads[2])):
        print(f"\n== 种子 {seed_name} ==")
        for label, data in corpus(seed):
            total += 1
            eax, out0, st = one_run(dll, data)
            flags = []
            if st["stop"].startswith(("READ_UNMAPPED", "WRITE_UNMAPPED", "EXC")):
                crash += 1
                flags.append(st["stop"])
            if st["stop"].startswith("HANG"):
                hang += 1
                flags.append("HANG")
            if st["stop"] != "returned" or out0[0] not in (0x37, 0x00, 0x01):
                if out0[0] not in (0x37,):
                    tchg += 1
                flags.append(f"out0={out0[0]:#04x}")
            if flags:
                interesting.append((seed_name, label, eax, out0[0], st["stop"]))
                print(f"  [{label:22s}] EAX={eax:#010x} out0={out0[0]:#04x} ins={st['ins']:>6}  {st['stop'][:70]}")
    print(f"\n== 汇总 ==  用例 {total} | crash {crash} | hang {hang} | 类型码非 0x37 {tchg}")
    print(f"  有价值的用例（非正常返回）：{len(interesting)}")
    for s, l, e, o, st in interesting[:25]:
        print(f"    {s:14s} {l:22s} EAX={e:#010x} out0={o:#04x} {st[:60]}")


if __name__ == "__main__":
    main()
