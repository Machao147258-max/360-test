"""360 载荷「接口面」提取（纯静态只读）

提取五类接口：
  1) RPC：rpcrt4 导入 + MIDL 桩特征（NdrClientCall*）+ 绑定串（ncacn_/ncalrpc/\RPC Control\）+ 接口 UUID
  2) COM：CLSID/IID/AppID GUID 及其上下文（CLSID\{...} / Interface\{...} / InprocServer32 / .orpc 节）
  3) 命名对象：\\.\pipe\ / \pipe\ / \RPC Control\ / \BaseNamedObjects\ / \Device\ / \??\ / Mutex
  4) 导出表：按模块统计并挑出"公共 API 味"的导出（Create*/Init*/Register*/Query*/Set*）
  5) ORPC/代理桩：.orpc 节、DllRegisterServer/DllGetClassObject、oxy 代理
输出：接口清单.md
"""
import os
import re
import sys
from collections import Counter, defaultdict

import pefile

PE_EXT = {".exe", ".dll", ".sys", ".cpl"}
GUID_RX = re.compile(rb"\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?")
BIND_RX = re.compile(rb"(?:ncacn_[a-z0-9_]+|ncalrpc|ncacn_ip_tcp|ncacn_np|ncalrpc:\[[^\]]+\])")
PIPE_RX = re.compile(rb"\\\\\.\\pipe\\[A-Za-z0-9_\-\.{}]+|\\\\pipe\\\\[A-Za-z0-9_\-\.{}]+")
RPCCTL_RX = re.compile(rb"\\RPC Control\\[A-Za-z0-9_\-\.{}]+")
BNO_RX = re.compile(rb"\\BaseNamedObjects\\[A-Za-z0-9_\-\.{}]+")
DEV_RX = re.compile(rb"\\Device\\[A-Za-z0-9_\-\.]+|\\\?\?\\[A-Za-z0-9_\-\.\\]+")
RPC_IMPORTS = ("NdrClientCall2", "NdrAsyncClientCall", "NdrClientCall3", "NdrServerCall2",
               "RpcBindingFromStringBindingW", "RpcStringBindingComposeW", "RpcServerUseProtseqEpW",
               "RpcServerRegisterIf", "I_RpcMapWin32Status", "MesHandleFree", "MesEncodeDynBufferHandleCreate")
ASCII_RX = re.compile(rb"[\x20-\x7e]{5,}")
WIDE_RX = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def strings_of(path, limit=12_000_000):
    with open(path, "rb") as fh:
        data = fh.read(limit)
    out = set()
    for m in ASCII_RX.finditer(data):
        out.add(m.group().decode("latin1"))
    for m in WIDE_RX.finditer(data):
        s = m.group().decode("utf-16-le", "ignore").rstrip("\x00")
        if len(s) >= 4:
            out.add(s)
    return out, data


def guid_context(data, needle):
    """取 GUID 前后 60 字节，判断它属于哪类（CLSID/Interface/AppID/其它）"""
    out = defaultdict(set)
    for m in GUID_RX.finditer(data):
        g = m.group().decode("latin1").strip("{}").upper()
        ctx = data[max(0, m.start() - 70):m.end() + 30].decode("latin1", "ignore")
        low = ctx.lower()
        if "clsid" in low or "class\\" in low:
            out["CLSID"].add(g)
        elif "interface" in low:
            out["Interface"].add(g)
        elif "appid" in low:
            out["AppID"].add(g)
        elif "type_lib" in low or "interface" in low:
            out["TypeLib"].add(g)
        else:
            out["其它 GUID"].add(g)
    return out


def main():
    root, out = sys.argv[1], sys.argv[2]
    rpc_mods, com, pipes, devs, bno, rpcctl, exports_by_mod, orpc, rpc_bind = [], defaultdict(set), set(), set(), set(), set(), {}, [], defaultdict(set)

    for base, _dirs, names in os.walk(root):
        for n in names:
            if os.path.splitext(n)[1].lower() not in PE_EXT:
                continue
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            try:
                ss, data = strings_of(p)
                pe = pefile.PE(p, fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
                exps = [s.name.decode("latin1") for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name] \
                    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else []
                secs = [s.Name.rstrip(b"\x00").decode("latin1") for s in pe.sections]
                pe.close()
            except Exception:
                continue
            if exps:
                exports_by_mod[rel] = exps
            if any(s in secs for s in (".orpc", ".rpc")):
                orpc.append((rel, [s for s in secs if s in (".orpc", ".rpc")]))
            if any(x in ss for x in RPC_IMPORTS):
                rpc_mods.append((rel, sorted({x for x in RPC_IMPORTS if x in ss}), len(exps)))
            for m in BIND_RX.finditer(data):
                rpc_bind[rel].add(m.group().decode("latin1"))
            for m in PIPE_RX.finditer(data):
                pipes.add(m.group().decode("latin1"))
            for m in RPCCTL_RX.finditer(data):
                rpcctl.add(m.group().decode("latin1"))
            for m in BNO_RX.finditer(data):
                bno.add(m.group().decode("latin1"))
            for m in DEV_RX.finditer(data):
                devs.add(m.group().decode("latin1"))
            for k, v in guid_context(data, n).items():
                com[k] |= v

    L = ["# 360 载荷 · 接口面清单（纯静态提取）", "",
         f"> 扫描 {len(exports_by_mod)} 个带导出的模块；本表只列接口，不做价值判断。", ""]

    L += ["## 一、RPC 接口", ""]
    L.append("| 模块 | MIDL/RPC 特征 | 导出数 | 绑定串 |")
    L.append("|---|---|---|---|")
    for rel, feats, nexp in sorted(rpc_mods, key=lambda x: -x[2]):
        binds = ", ".join(sorted(rpc_bind.get(rel, []))[:4]) or "（无绑定串，可能由参数传入）"
        L.append(f"| `{rel}` | {', '.join(feats[:6])} | {nexp} | {binds} |")
    L.append("")
    L.append("**全部绑定串（按模块）**")
    for rel, binds in sorted(rpc_bind.items()):
        L.append(f"- `{rel}`: {', '.join(sorted(binds)[:8])}")
    L.append("")

    for k in ("CLSID", "Interface", "AppID", "TypeLib", "其它 GUID"):
        if not com.get(k):
            continue
        L.append(f"## 二、COM 类标识（{k}，{len(com[k])} 个）" if k == "CLSID" else f"### {k}（{len(com[k])} 个）")
        for g in sorted(com[k])[:60]:
            L.append(f"- `{{{g}}}`")
        L.append("")

    L += [f"## 三、命名对象", ""]
    for label, s in (("命名管道", pipes), ("\\RPC Control\\", rpcctl),
                     ("\\BaseNamedObjects\\", bno), ("设备对象", devs)):
        L.append(f"### {label}（{len(s)}）")
        for x in sorted(s)[:60]:
            L.append(f"- `{x}`")
        L.append("")

    L += ["## 四、含 .orpc/.rpc 节的模块（ORPC 代理桩）", ""]
    for rel, secs in orpc:
        L.append(f"- `{rel}` → {secs}")
    L.append("")

    L += ["## 五、导出表规模（前 25）+ 公共 API 味导出", ""]
    pub = re.compile(r"^(Create|Init|Register|Query|Set|Get|Open|Close|Enum|Update|Start|Stop|Install|Uninstall|Delete|Add|Remove|Enable|Disable)")
    for rel, exps in sorted(exports_by_mod.items(), key=lambda kv: -len(kv[1]))[:25]:
        pubs = [e for e in exps if pub.match(e)]
        L.append(f"- `{rel}`：导出 {len(exps)}，其中公共味 {len(pubs)} —— {', '.join(pubs[:12])}")
    L.append("")

    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"-> {out}（{len(L)} 行）")
    print(f"   RPC 模块 {len(rpc_mods)} | CLSID {len(com.get('CLSID', []))} | Interface {len(com.get('Interface', []))} "
          f"| 管道 {len(pipes)} | RPC Control {len(rpcctl)} | BNO {len(bno)} | 设备 {len(devs)} | ORPC 模块 {len(orpc)}")


if __name__ == "__main__":
    main()
