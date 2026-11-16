"""360 的"签名信任"机制静态排查 —— 纯本地只读

问题：360 是否会因为"文件签名与它信任的签名者相同"而少检出（白名单/信任签名）？
做法（不运行任何 360 代码）：
  1) 验签/信任相关模块的导出（导出名本身就说明机制）
  2) 这些模块与引擎里的信任类字符串（白名单 / 签名 / 证书 / 信任 / 吊销 / publisher）
  3) Authenticode 相关 API 的使用（WinVerifyTrust / CertGetCertificateChain / CryptQueryObject …）
  4) 数据文件里是否内嵌"受信证书清单"（厂商名 / 40-64 位十六进制指纹）
"""
import os
import re
import sys
from collections import Counter

import pefile

TRUST_MODULES = [
    "360Verify.dll", "safemon/swverify32.dll", "safemon/swverify64.dll",
    "Utils/360SafeChecker.dll", "Utils/360Protect.dll", "safemon/SelfProtectAPI2.dll",
    "safemon/safemon64.dll", "deepscan/deepscan.dll", "deepscan/AVE/AVEngine.dll",
    "deepscan/AVE/AVEI.dll", "deepscan/cloudcom2.dll", "deepscan/Cloudsec3.dll",
    "deepscan/jcloudscan.dll", "deepscan/BAPI.dll", "SoftMgr/SDIS.exe",
    "SoftMgr/SecurityProxy.dll", "SoftMgr/360SoftMgrS.dll", "Utils/analyst.dll",
]
DATA_GLOBS = (".dat", ".enc", ".bin", ".db", ".ui", ".tpi", ".vdb")

TRUST_RX = re.compile(r"(白名单|黑名单|信任|受信|签名|证书|吊销|撤销|发行者|发布者|"
                      r"whitelist|white_list|blacklist|trust(?:ed)?|signer|signature|"
                      r"certificate|cert|revoke|publisher|authenticode|verisign|globalsign|"
                      r"digicert|symantec|comodo|sectigo|thawte|entrust|qihu|qihoo)", re.I)
VENDOR_RX = re.compile(rb"(Beijing Qihu|Qihoo|GlobalSign|DigiCert|VeriSign|Symantec|"
                       rb"Thawte|Entrust|COMODO|Sectigo|WoSign|CFCA|WoTrus)", re.I)
HEX_RX = re.compile(rb"\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b")
AUTH_API = re.compile(r"(WinVerifyTrust|CertGetCertificateChain|CryptQueryObject|CryptMsgGetParam|"
                      r"CryptVerifySignature|CertFindCertificateInStore|CertOpenStore|"
                      r"WTHelperProvDataFromStateData|CryptDecodeObject|CertGetNameString|"
                      r"BCryptVerifySignature|CryptCATAdminCalcHashFromFileHandle)")

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def strings_of(path, limit=8_000_000):
    with open(path, "rb") as fh:
        data = fh.read(limit)
    out = set()
    for m in ASCII_RE.finditer(data):
        out.add(m.group().decode("latin1"))
    for m in WIDE_RE.finditer(data):
        s = m.group().decode("utf-16-le", "ignore").rstrip("\x00")
        if len(s) >= 5:
            out.add(s)
    return out


def main():
    root, out = sys.argv[1], sys.argv[2]
    L = ["# 360 签名信任机制排查（静态）", ""]

    L += ["## 一、信任/验签相关模块的导出与 Authenticode API", ""]
    for rel in TRUST_MODULES:
        p = os.path.join(root, *rel.split("/"))
        if not os.path.exists(p):
            continue
        pe = pefile.PE(p, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        exps, apis = [], []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            exps = [s.name.decode("latin1", "replace") for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name]
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                for i in e.imports:
                    if i.name:
                        n = i.name.decode("latin1", "replace")
                        if AUTH_API.search(n):
                            apis.append(f"{e.dll.decode('latin1')}!{n}")
        pe.close()
        trustish = [e for e in exps if re.search(r"Trust|White|Black|Sign|Cert|Verify|Allow|Block|"
                                                r"Safe|Rule|Licen", e, re.I)]
        L.append(f"### {rel}")
        L.append(f"- 导出 {len(exps)} 个；签名/信任类导出：" +
                 (", ".join(sorted(trustish)[:30]) if trustish else "（无）"))
        L.append(f"- Authenticode API：" + (", ".join(sorted(set(apis))) if apis else "（无）"))
        L.append("")

    L += ["## 二、引擎与验签模块里的信任类字符串", ""]
    for rel in TRUST_MODULES:
        p = os.path.join(root, *rel.split("/"))
        if not os.path.exists(p):
            continue
        ss = strings_of(p)
        hits = sorted({s.strip() for s in ss if 5 <= len(s) <= 160 and TRUST_RX.search(s)})
        if not hits:
            continue
        L.append(f"### {rel}（{len(hits)} 条）")
        L.extend(f"- {h[:150]}" for h in hits[:40])
        L.append("")

    L += ["## 三、数据文件里是否内嵌受信证书清单", ""]
    root_walk = root
    for base, _dirs, names in os.walk(root_walk):
        for n in names:
            if not n.lower().endswith(DATA_GLOBS):
                continue
            p = os.path.join(base, n)
            try:
                data = open(p, "rb").read()
            except Exception:
                continue
            vend = Counter(m.group(0).decode("latin1", "ignore") for m in VENDOR_RX.finditer(data))
            hexes = set(m.group(0).decode() for m in HEX_RX.finditer(data))
            if not vend and not hexes:
                continue
            rel = os.path.relpath(p, root).replace("\\", "/")
            L.append(f"### {rel}（{len(data):,} B）")
            if vend:
                L.append(f"- 厂商名命中：{dict(vend)}")
            if hexes:
                sample = sorted(hexes)[:6]
                L.append(f"- 40/64 位十六进制串 {len(hexes)} 条，样例：{sample}")
            L.append("")

    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"-> {out} ({len(L)} 行)")


if __name__ == "__main__":
    main()
