"""360 载荷 · 全部导出 API 清单（纯静态）

输出：
  · 分析_2026-10/API导出清单.md    —— 按子系统分组的可读清单
  · 分析_2026-10/api_exports.tsv   —— 机器可读（module, arch, ord, name）
"""
import csv
import os
import sys
from collections import Counter, defaultdict

import pefile

# 按模块路径归类到子系统
def subsystem(rel: str) -> str:
    low = rel.lower()
    if low.startswith("deepscan/ave/"):
        return "扫描引擎·AVE(特征)"
    if low.startswith("deepscan/qvm/"):
        return "扫描引擎·QVM(Bole)"
    if low.startswith("deepscan/qex/"):
        return "扫描引擎·qex(文档/格式)"
    if low.startswith("deepscan/"):
        return "深扫与云查(deepscan/)"
    if low.startswith("safemon/"):
        return "实时防护/托盘(safemon/)"
    if low.startswith("softmgr/"):
        return "软件管家(SoftMgr/)"
    if low.startswith("sweeper/"):
        return "清理/主页(sweeper/)"
    if low.startswith("utils/"):
        return "工具与扩展(Utils/)"
    if low.startswith("ipc/"):
        return "IPC 服务(ipc/)"
    if low.startswith("entadmin/"):
        return "企业管控(EntAdmin/)"
    if low.startswith("netmon/"):
        return "网络监控(netmon/)"
    if "/" not in rel:
        return "根目录模块"
    return "其它(" + rel.split("/")[0] + ")"


NOISE_PREFIX = ("sqlite3_",)          # 内嵌第三方库，单独折叠
PUBLIC_RX_KEYS = ("Create", "Init", "Register", "Query", "Set", "Get", "Open", "Close", "Enum",
                  "Update", "Start", "Stop", "Install", "Uninstall", "Delete", "Add", "Remove",
                  "Enable", "Disable", "Scan", "Check", "Is", "Has", "Run", "Load", "Save",
                  "Send", "Recv", "Read", "Write", "Login", "Logout", "Verify", "Sign")


def main():
    root, outmd, outtsv = sys.argv[1], sys.argv[2], sys.argv[3]
    rows = []
    stats = Counter()
    per_mod = {}
    for base, _d, names in os.walk(root):
        for n in names:
            if os.path.splitext(n)[1].lower() not in (".dll", ".exe", ".ocx", ".cpl", ".tpi"):
                continue
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            try:
                pe = pefile.PE(p, fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
                exps = [s.name.decode("latin1") for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name] \
                    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else []
                arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
                pe.close()
            except Exception:                                     # noqa: BLE001
                continue
            if not exps:
                continue
            per_mod[rel] = (arch, exps)
            stats["modules"] += 1
            stats["exports"] += len(exps)
            stats[arch] += 1
            for i, e in enumerate(exps, 1):
                rows.append((rel, arch, i, e))

    with open(outtsv, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, delimiter="\t")
        w.writerow(["module", "arch", "ordinal", "export"])
        w.writerows(rows)

    groups = defaultdict(list)
    for rel, (arch, exps) in per_mod.items():
        groups[subsystem(rel)].append((rel, arch, exps))

    L = ["# 360 载荷 · 导出 API 清单", "",
         f"> 带导出的模块 **{stats['modules']}** 个（x86 {stats['x86']} / x64 {stats['x64']}），导出合计 **{stats['exports']}** 条。",
         "> 只列导出（可被外部调用的 API），不含内部函数。机器可读版见 `api_exports.tsv`。", ""]

    for grp in sorted(groups):
        mods = sorted(groups[grp], key=lambda x: -len(x[2]))
        total = sum(len(m[2]) for m in mods)
        L.append(f"## {grp}  （{len(mods)} 模块 / {total} 导出）")
        for rel, arch, exps in mods:
            noise = [e for e in exps if e.startswith(NOISE_PREFIX)]
            real = [e for e in exps if not e.startswith(NOISE_PREFIX)]
            head = f"### `{rel}` ({arch}, {len(exps)} 导出"
            head += f"，其中 sqlite3_* {len(noise)} 条已折叠)" if noise else ")"
            L.append(head)
            if real:
                L.append("- " + ", ".join(f"`{e}`" for e in real[:60]) + (" …" if len(real) > 60 else ""))
            L.append("")

    with open(outmd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"-> {outmd}（{len(L)} 行）")
    print(f"-> {outtsv}（{len(rows)} 条导出）")
    print(f"   模块 {stats['modules']}（x86 {stats['x86']} / x64 {stats['x64']}） / 导出 {stats['exports']}")
    print("   导出最多的 12 个模块：")
    for rel, (arch, exps) in sorted(per_mod.items(), key=lambda kv: -len(kv[1][1]))[:12]:
        print(f"     {len(exps):5d}  {rel}")


if __name__ == "__main__":
    main()
