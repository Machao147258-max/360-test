"""接口 fuzz 面提取（纯静态、只读）

在「接口清单.md」基础上补三件 fuzz 需要的东西：
  1) 绑定串补扫 UTF-16（上一版只扫 ASCII，所以全空 —— 例如 `ncalrpc` 宽串会被漏掉）
  2) 用 capstone 数每模块 Ndr* 桩调用点 → 得到 **opnum 规模**（客户端桩数 / 服务端分发数）
  3) 按"服务端 vs 客户端"给接口分类 —— 服务端才算 fuzz 入口
输出：接口fuzz面.md
"""
import os
import re
import sys
from collections import Counter, defaultdict

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

PE_EXT = {".exe", ".dll", ".sys"}
NDR = ("NdrClientCall2", "NdrAsyncClientCall", "NdrClientCall3", "NdrServerCall2", "NdrServerCallAll")
SERVER_MARK = ("RpcServerRegisterIf", "RpcServerRegisterIf2", "RpcServerRegisterIf3",
               "RpcServerUseProtseqEpW", "RpcServerUseProtseqEpA", "NdrServerCall2", "NdrServerCallAll")
CLIENT_MARK = ("NdrClientCall2", "NdrAsyncClientCall", "NdrClientCall3")
PROTOSEQ = ("ncacn_np", "ncacn_ip_tcp", "ncacn_http", "ncalrpc", "ncacn_vns", "ncadg_ip_udp")
U16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def wide_strings_in(data, needles):
    """在原始字节里按 UTF-16LE 找关键词（逐字节比较，避免解码开销）"""
    hits = []
    for nd in needles:
        pat = nd.encode("utf-16-le")
        i = data.find(pat)
        while i >= 0 and len(hits) < 40:
            # 取前后各 40 字节里可读的宽串作为上下文
            ctx = data[max(0, i - 64):i + 128]
            s = re.sub(rb"\x00", b"", ctx).decode("latin1", "ignore")
            hits.append(f"{nd} @{i} ctx={s.strip()[:70]}")
            i = data.find(pat, i + 1)
    return hits


def count_stub_calls(path):
    """反汇编 .text，统计对 Ndr* IAT 槽的 call 数量（= 桩/分发点个数）"""
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    base = pe.OPTIONAL_HEADER.ImageBase
    iat = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in e.imports:
                if imp.name and imp.name.decode("latin1") in NDR:
                    iat[imp.address] = imp.name.decode("latin1")
    is64 = pe.FILE_HEADER.Machine == 0x8664
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
    counts = Counter()
    for s in pe.sections:
        if not (s.Characteristics & 0x20000000):
            continue
        code = s.get_data()
        va = base + s.VirtualAddress
        for ins in md.disasm(code, va):
            if ins.mnemonic != "call":
                continue
            m = re.search(r"\[(0x[0-9a-f]+)\]", ins.op_str)
            if not m:
                continue
            tgt = int(m.group(1), 16)
            if tgt in iat:
                counts[iat[tgt]] += 1
    pe.close()
    return counts, is64


def main():
    root, out = sys.argv[1], sys.argv[2]
    rows = []
    binds = defaultdict(set)
    for base, _dirs, names in os.walk(root):
        for n in names:
            if os.path.splitext(n)[1].lower() not in PE_EXT:
                continue
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            with open(p, "rb") as fh:
                data = fh.read(12_000_000)
            mark_s = any(m.encode() in data for m in SERVER_MARK)
            mark_c = any(m.encode() in data for m in CLIENT_MARK)
            wb = wide_strings_in(data, PROTOSEQ)
            ab = [m.group().decode("latin1") for m in re.finditer(
                rb"ncacn_[a-z0-9_]+|ncalrpc", data)]
            if wb or ab:
                binds[rel] |= set(x.split()[0] for x in wb) | set(ab)
            if not (mark_s or mark_c):
                continue
            try:
                counts, is64 = count_stub_calls(p)
            except Exception:
                counts, is64 = Counter(), False
            rows.append({
                "rel": rel, "server": mark_s, "client": mark_c, "arch": "x64" if is64 else "x86",
                "calls": dict(counts), "total": sum(counts.values()),
                "bind": sorted(binds.get(rel, [])),
            })

    rows.sort(key=lambda r: (-int(r["server"]), -r["total"]))
    L = ["# 360 · 接口 fuzz 面（纯静态）", "",
         "> 分类依据：出现 `RpcServerRegisterIf*`/`RpcServerUseProtseqEpW`/`NdrServerCall*` = **服务端**（接受调用 → fuzz 入口）；",
         "> 只出现 `NdrClientCall2/NdrAsyncClientCall` = 客户端桩（是攻击工具，不是入口）。",
         "> opnum 规模 = capstone 数出的 Ndr* 桩调用点数量（近似等于该接口的方法数）。", ""]

    srv = [r for r in rows if r["server"]]
    L += [f"## 一、服务端接口（fuzz 入口，{len(srv)} 个）", "",
          "| 模块 | 架构 | 服务端特征 | Ndr* 调用点 | 绑定串(宽/窄) |", "|---|---|---|---|---|"]
    for r in srv:
        L.append(f"| `{r['rel']}` | {r['arch']} | NdrServer/RegisterIf | {r['total']} "
                 f"({', '.join(f'{k}×{v}' for k, v in r['calls'].items()) or '-'}) | "
                 f"{', '.join(r['bind']) or '运行时拼装'} |")
    L.append("")

    cli = [r for r in rows if r["client"] and not r["server"]]
    L += [f"## 二、纯客户端桩（{len(cli)} 个，作为 fuzz 工具复用）", "",
          "| 模块 | 架构 | Ndr* 调用点 |", "|---|---|---|"]
    for r in sorted(cli, key=lambda x: -x["total"])[:20]:
        L.append(f"| `{r['rel']}` | {r['arch']} | {r['total']} |")
    L.append("")

    L += ["## 三、能本地先做 / 必须 VM 才能做", "",
          "**本地可做（不需要运行 360）**",
          "- 从每个服务端模块的 MIDL 描述符（ProcFormatString/TypeFormatString）重建方法签名 → 生成 fuzz 模板",
          "- 用调用点数量定 opnum 上界（本表已给），用客户端桩的参数压栈顺序推每个 opnum 的参数个数",
          "- 设备 IOCTL：三码已知（0x222020/0x22204C/0x222094），可直接写 IOCTL fuzz 字典（in/out 长度矩阵）",
          "- COM（53 个 CLSID）：静态枚举 CLSID → InprocServer32/LocalServer32 映射，产出自注册清单",
          "",
          "**必须运行才可 fuzz（与\"不安装\"纪律冲突，需快照 VM）**",
          "- 对 ncalrpc/命名管道端点发畸形调用（需要服务已注册）",
          "- `\\\\.\\360SelfProtection` 的 DeviceIoControl fuzz（需要驱动已加载）",
          "- COM 对象的 CoCreateInstance + 方法 fuzz（需要已注册）",
          ""]

    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"-> {out}（{len(L)} 行）  服务端 {len(srv)} / 纯客户端 {len(cli)}")
    for r in srv[:12]:
        print(f"   [srv] {r['rel']:44s} {r['arch']} calls={r['total']}")


if __name__ == "__main__":
    main()
