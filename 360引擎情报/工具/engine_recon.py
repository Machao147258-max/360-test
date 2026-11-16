"""360 检测引擎静态画像（纯本地、只读）

目标：AVE/AVEngine、360QVM、qex、deepscan、云查模块 + 加密库(.enc)/数据表(.dat)。
产出：导出表、关键导入、按用途分类的字符串（判定名/引擎标签/文件类型/行为 API/信任与证书/云查/中文），
      以及 .enc/.dat 的头部与熵指纹（判断是否压缩/加密、是否自有容器）。

用法：python engine_recon.py <payload_root> <out.md>
"""
import math
import os
import re
import sys
from collections import Counter

import pefile

ENGINE_FILES = [
    "deepscan/AVE/AVEngine.dll", "deepscan/AVE/AVEI.dll",
    "deepscan/QVM/360QVM.dll",
    "deepscan/qex/qex.dll",
    "deepscan/deepscan.dll",
    "deepscan/cloudcom2.dll", "deepscan/Cloudsec3.dll", "deepscan/CloudEngine.dll",
    "deepscan/jcloudscan.dll",
    "deepscan/avescan.dll", "deepscan/DSFScan.dll", "deepscan/heavygate.dll",
    "deepscan/BAPI.dll",
    "deepscan/BAPIDRV64.SYS", "deepscan/BAPIDRV.sys",
    "deepscan/360fsflt.sys", "deepscan/360FsFlt_win10.sys",
]
DATA_FILES = [
    "deepscan/qex/qex.vdb.enc", "deepscan/qex/patt.enc", "deepscan/qex/MacroDef.enc",
    "deepscan/qshieldzh.dat", "deepscan/qex/xyar.dat", "deepscan/dsws.dat",
    "deepscan/dsbs.dat", "deepscan/ssr.dat",
]

CATS = [
    ("verdict", re.compile(r"(?:Trojan|Worm|Backdoor|Rootkit|Virus|Adware|Riskware|HackTool|"
                           r"Spyware|PUA|Exploit|Ransom|Dropper|Downloader)[A-Za-z0-9._/-]{2,44}")),
    ("engine_tag", re.compile(r"\b(?:AVE|QVM|QEX|PATT|VDB|MDB|CLOUD|PACK|SCAN)[A-Za-z0-9_.-]{1,24}")),
    ("db_container", re.compile(r"(?:VDB|PATT|EMV|SIGDAT|MAGIC|HEADER|VERSION)[A-Za-z0-9_]{0,14}", re.I)),
    ("filetype", re.compile(r"\b(?:exe|dll|sys|doc[xm]?|xls[xm]?|pdf|js|jse|vbs|vbe|ps1|lnk|scr|bat|cmd|"
                            r"wsf|hta|zip|rar|7z|apk|elf|so|jar|msi|reg)\b", re.I)),
    ("behavior_api", re.compile(r"(?:CreateRemoteThread|SetWindowsHookEx|WriteProcessMemory|"
                                r"RegSetValueEx|CreateService|ShellExecute|LoadLibrary|QueueUserAPC|"
                                r"NtMapViewOfSection|VirtualAllocEx|SetThreadContext)[A-Za-z]*")),
    ("trust_cert", re.compile(r"(?:whitelist|white_list|trusted|trust|signer|signature|revoke|"
                              r"certificate|白名单|信任|签名|证书|吊销)[A-Za-z0-9_]{0,20}", re.I)),
    ("cloud", re.compile(r"(?:cloud|云查|上传|上报|query|verdict)[A-Za-z0-9_:/.-]{0,40}", re.I)),
    ("url", re.compile(r"https?://[A-Za-z0-9_.:/?=&%#@!~+-]{5,120}")),
    ("path", re.compile(r"[A-Za-z]:\\[A-Za-z0-9_\\ .-]{4,110}")),
    ("registry", re.compile(r"(?:SOFTWARE|SYSTEM|HARDWARE|SECURITY)\\[A-Za-z0-9_\\ .{}-]{4,110}", re.I)),
]
CN = re.compile(r"[\u4e00-\u9fff][\u4e00-\u9fff\w\s，。：、（）()]{2,40}")
ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def strings_of(path, limit_bytes=None):
    with open(path, "rb") as fh:
        data = fh.read(limit_bytes) if limit_bytes else fh.read()
    out = set()
    for m in ASCII_RE.finditer(data):
        out.add(m.group().decode("latin1"))
    for m in WIDE_RE.finditer(data):
        s = m.group().decode("utf-16-le", "ignore").rstrip("\x00")
        if len(s) >= 5:
            out.add(s)
    return out


def exports_of(path):
    pe = pefile.PE(path, fast_load=True)
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        ])
        exps, imps = [], {}
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if s.name:
                    exps.append(s.name.decode("latin1", "replace"))
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                names = [i.name.decode("latin1", "replace") for i in e.imports if i.name]
                imps[e.dll.decode("latin1", "replace")] = names
        return exps, imps
    finally:
        pe.close()


def main():
    root, out = sys.argv[1], sys.argv[2]
    L = ["# 360 检测引擎静态画像", "",
         "> 纯静态只读；不加载、不运行任何模块。", ""]

    L += ["## 一、引擎模块：导出与导入", ""]
    for rel in ENGINE_FILES:
        p = os.path.join(root, *rel.split("/"))
        if not os.path.exists(p):
            L.append(f"- `{rel}` —— 缺失")
            continue
        size = os.path.getsize(p)
        try:
            exps, imps = exports_of(p)
        except Exception as exc:                       # noqa: BLE001
            L.append(f"- `{rel}` ({size:,} B) —— 解析失败 {exc}")
            continue
        L.append(f"### {rel}  ({size:,} B)")
        L.append(f"- 导出 {len(exps)} 个：" + (", ".join(sorted(exps)[:25]) if exps else "（无导出）"))
        interesting = []
        for dll, names in imps.items():
            for n in names:
                if re.search(r"Crypt|BCrypt|Hash|Compress|Zlib|Lzma|Virtual|Map|Thread|Process|"
                             r"Reg|Service|File|Section|Token", n):
                    interesting.append(f"{dll.split('.')[0]}!{n}")
        L.append(f"- 导入 DLL {len(imps)} 个；关键导入：" +
                 (", ".join(sorted(set(interesting))[:30]) if interesting else "（无明显）"))
        L.append("")

    L += ["## 二、按用途分类的字符串（每个引擎模块）", ""]
    for rel in ENGINE_FILES:
        p = os.path.join(root, *rel.split("/"))
        if not os.path.exists(p):
            continue
        ss = strings_of(p)
        L.append(f"### {rel}")
        for name, rx in CATS:
            hits = sorted({s.strip() for s in ss if 5 <= len(s) <= 200 and rx.search(s)})
            if not hits:
                continue
            L.append(f"- **{name}**（{len(hits)}）：")
            L.extend(f"  - {h[:150]}" for h in hits[:18])
        cn = sorted({m.group() for s in ss for m in [CN.search(s)] if m}, key=len, reverse=True)
        if cn:
            L.append(f"- **中文串**（{len(cn)}）：")
            L.extend(f"  - {c}" for c in cn[:25])
        L.append("")

    L += ["## 三、加密库 / 数据表指纹", "",
          "| 文件 | 大小 | 熵 | 头部 32B | 判断 |", "|---|---|---|---|---|"]
    for rel in DATA_FILES:
        p = os.path.join(root, *rel.split("/"))
        if not os.path.exists(p):
            continue
        with open(p, "rb") as fh:
            head = fh.read(64)
            body = fh.read()
        e = entropy(head + body)
        verdict = ("高度压缩或加密" if e > 7.5 else
                   "加密/压缩（混合）" if e > 6.5 else "低熵：明文或结构化表")
        L.append(f"| `{rel}` | {os.path.getsize(p):,} | {e:.2f} | `{head[:32].hex()}` | {verdict} |")
    L.append("")
    L.append("> 说明：熵是整文件值（头部计入），`.enc` 后缀 + 高熵 = 自有容器/加密库；"
             "低熵说明是可解析的规则表（可进一步做结构推断）。")

    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"-> {out}  ({len(L)} 行)")


if __name__ == "__main__":
    main()
