"""补环境实测：用 Unicorn 直接跑 qex.dll 的容器识别函数（不执行整个程序）

目标函数：`sub_100C50F0` @ VA 0x100c50f0（x86-32）
  反编译签名：int __fastcall sub_100C50F0(void *Src, size_t Size, _DWORD *a3)
  行为（静态已知）：memset(buf,0,0x200) → memmove(buf, Src, min(Size,512)) → switch(buf[0])
                  → 各分支比对自己格式的魔数；其中一条是 `cmp dword ptr [..], 0DA7AF11Eh`

本脚本做的事（真正的"补环境"）：
  1. 把 qex.dll 按 PE 节表映射进 Unicorn（含 IAT），栈/输出缓冲/导入桩全部自己搭
  2. 依次用三种调用约定 + 五种输入（三个真实 .enc 头 512B、随机、全零）跑这个函数
  3. 记录 EAX、输出缓冲被写的字节、停止原因、是否命中导入桩

判据：哪种调用约定能让"三个真实 .enc 头"走出一条明显不同于随机/全零的路径，
      哪种约定就是对的；同时验证该识别函数确实按魔数判定。
"""
import os
import sys

import pefile
from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED,
                     UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
                     UC_MODE_32, UC_PROT_ALL, Uc)
from unicorn.x86_const import (UC_X86_REG_EIP, UC_X86_REG_EAX, UC_X86_REG_ESP,
                               UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_FS_BASE)

IMG = 0x10000000
STACK = 0x20000000
STACK_SZ = 0x100000
OUTBUF = 0x30000000
STUB = 0x40000000
STUB_SZ = 0x10000
SENTINEL = 0xDEAD0000
TARGET = 0x100C50F0
# 补环境必需：MSVC x86 函数开头普遍是 `mov eax, fs:[0]`（SEH 链），必须搭一个最小 TEB
TEB = 0x7FFDF000
TEB_PAGE = 0x7FFD0000


def setup_teb(uc):
    """补环境：给 SEH 框架一个可读的 TEB。Unicorn 2.x 不允许写 FS_BASE，
    而裸 Unicorn 的 FS 基址默认是 0 —— 所以直接把 0 地址页映射出来当 TEB 用。"""
    base = TEB
    try:
        uc.mem_map(TEB_PAGE, 0x3000, UC_PROT_ALL)
        uc.reg_write(UC_X86_REG_FS_BASE, TEB)
    except Exception:                                          # noqa: BLE001
        base = 0x0
        uc.mem_map(0x0, 0x2000, UC_PROT_ALL)
    uc.mem_write(base + 0x00, (0xFFFFFFFF).to_bytes(4, "little"))   # SEH 链末端
    uc.mem_write(base + 0x04, (base + 0x1FF0).to_bytes(4, "little"))
    uc.mem_write(base + 0x08, (base + 0x1000).to_bytes(4, "little"))
    uc.mem_write(base + 0x18, base.to_bytes(4, "little"))          # TEB 自指针
    uc.mem_write(base + 0x20, (base + 0x1000).to_bytes(4, "little"))
    return base


def load_image(uc, path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    size = pe.OPTIONAL_HEADER.SizeOfImage
    uc.mem_map(IMG, (size + 0xFFF) & ~0xFFF, UC_PROT_ALL)
    raw = open(path, "rb").read()
    for s in pe.sections:
        data = raw[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        uc.mem_write(IMG + s.VirtualAddress, data)
    # IAT 指向桩页；桩页里每个函数写 `xor eax,eax; ret`（并记录名字）
    names = {}
    uc.mem_map(STUB, STUB_SZ, UC_PROT_ALL)
    slot = STUB + 0x1000
    uc.mem_write(slot, b"\x31\xc0\xc3")                        # xor eax,eax ; ret
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            dlln = e.dll.decode("latin1")
            for imp in e.imports:
                nm = imp.name.decode("latin1") if imp.name else f"ord{imp.ordinal}"
                names[slot] = f"{dlln}!{nm}"
                off = imp.address if imp.address >= IMG else \
                    IMG + (imp.address - pe.OPTIONAL_HEADER.ImageBase)
                uc.mem_write(off, slot.to_bytes(4, "little"))
    pe.close()
    return names


def run_one(uc, names, data, conv, log):
    uc.mem_map(OUTBUF, 0x1000, UC_PROT_ALL)
    uc.mem_write(OUTBUF, b"\x00" * 0x1000)
    src = OUTBUF + 0x800
    uc.mem_write(src, data)
    esp = STACK + STACK_SZ - 0x400
    uc.reg_write(UC_X86_REG_ESP, esp)
    # 栈上：[ESP]=返回哨兵，后面按约定摆参数
    uc.mem_write(esp, SENTINEL.to_bytes(4, "little"))
    if conv == "cdecl":
        uc.mem_write(esp + 4, src.to_bytes(4, "little"))
        uc.mem_write(esp + 8, len(data).to_bytes(4, "little"))
        uc.mem_write(esp + 12, OUTBUF.to_bytes(4, "little"))
    elif conv == "fastcall":
        uc.reg_write(UC_X86_REG_ECX, src)
        uc.reg_write(UC_X86_REG_EDX, len(data))
        uc.mem_write(esp + 4, OUTBUF.to_bytes(4, "little"))
    elif conv == "thiscall":
        uc.reg_write(UC_X86_REG_ECX, src)
        uc.mem_write(esp + 4, len(data).to_bytes(4, "little"))
        uc.mem_write(esp + 8, OUTBUF.to_bytes(4, "little"))

    state = {"stop": "normal", "stubs": []}

    def on_code(uc_, addr, size, _u):
        if addr == SENTINEL:
            state["stop"] = "returned"
            uc_.emu_stop()
            return
        if STUB <= addr < STUB + STUB_SZ:
            nm = names.get(addr, "?")
            state["stubs"].append(nm)
            r = int.from_bytes(uc_.mem_read(uc_.reg_read(UC_X86_REG_ESP), 4), "little")
            uc_.reg_write(UC_X86_REG_EAX, 0)
            uc_.reg_write(UC_X86_REG_EIP, r)
            uc_.reg_write(UC_X86_REG_ESP, uc_.reg_read(UC_X86_REG_ESP) + 4)

    def on_unmapped(uc_, access, addr, size, value, _u):
        eip = uc_.reg_read(UC_X86_REG_EIP)
        ins = b""
        try:
            ins = uc_.mem_read(eip, 16)
        except Exception:                                   # noqa: BLE001
            pass
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        txt = " ".join(f"{i.mnemonic} {i.op_str}" for i in list(md.disasm(ins, eip))[:1])
        state["stop"] = (f"UNMAPPED access={access} addr={addr:#x} size={size} @EIP={eip:#x} "
                         f"[{txt}] esp={uc_.reg_read(UC_X86_REG_ESP):#x} "
                         f"ecx={uc_.reg_read(UC_X86_REG_ECX):#x} edx={uc_.reg_read(UC_X86_REG_EDX):#x}")
        return False

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_unmapped)
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_unmapped)
    try:
        uc.emu_start(TARGET, SENTINEL, timeout=3 * 1000 * 1000, count=400000)
    except Exception as exc:                                    # noqa: BLE001
        if not state["stop"].startswith("UNMAPPED"):
            state["stop"] = f"exc:{type(exc).__name__}:{str(exc)[:60]}"
    eax = uc.reg_read(UC_X86_REG_EAX)
    out = uc.mem_read(OUTBUF, 24)
    log.append(f"    {conv:9s} EAX={eax:#010x} stop={state['stop']:28s} "
               f"out={bytes(out)[:12].hex()} stubs={len(state['stubs'])}")
    return eax, state


def main():
    root = sys.argv[1]
    dll = os.path.join(root, "deepscan", "qex", "qex.dll")
    encrels = ["deepscan/qex/qex.vdb.enc", "deepscan/qex/patt.enc", "deepscan/qex/MacroDef.enc"]
    inputs = []
    for rel in encrels:
        p = os.path.join(root, *rel.split("/"))
        with open(p, "rb") as fh:
            head = fh.read(512)
        inputs.append((os.path.basename(p), head + b"\x00" * (512 - len(head))))
    inputs.append(("random512", bytes((i * 37 + 11) % 256 for i in range(512))))
    inputs.append(("zeros512", b"\x00" * 512))

    for conv in ("cdecl", "fastcall", "thiscall"):
        print(f"== 约定 {conv} ==")
        for name, data in inputs:
            uc = Uc(UC_ARCH_X86, UC_MODE_32)
            names = load_image(uc, dll)
            uc.mem_map(STACK, STACK_SZ, UC_PROT_ALL)
            uc.mem_map(SENTINEL & ~0xFFF, 0x1000, UC_PROT_ALL)
            setup_teb(uc)
            uc.mem_write(SENTINEL, b"\xc3")                      # ret（作为哨兵处指令，保险）
            log = []
            run_one(uc, names, data, conv, log)
            print(f"  {name:20s}")
            print("\n".join(log))


if __name__ == "__main__":
    main()
