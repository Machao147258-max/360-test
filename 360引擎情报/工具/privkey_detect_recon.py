"""360 对"私钥/凭据类文件"的检测能力排查（纯本地只读）

分两步：
  A. 把 safemon/360TrayLogin.tpi 里那段 PKCS#8 片段按"连续 base64 字符"重新界定，
     报出它到底在哪一个字节断掉、断点后 64 字节是什么（判断是被容器分块打断还是真的残缺）。
  B. 查 360 自己怎么"认"私钥文件：文件类型表（qex.dll 的 TypeEnum2Descript）+
     各模块里的私钥/凭据类检测字符串，最后统计谁引用了这些字面量。
"""
import os
import re
import sys

B64SET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n\x00 \t")
SECRET_RX = re.compile(
    r"(私钥|密钥文件|密钥泄露|凭据|凭证|密码本|助记词|种子短语|"
    r"PRIVATE KEY|id_rsa|id_dsa|id_ecdsa|id_ed25519|known_hosts|authorized_keys|"
    r"keystore|\.jks\b|\.p12\b|\.pfx\b|\.pem\b|PuTTY-User-Key|openssh-key|ssh-keygen|"
    r"passwordstore|wallet\.dat|credentials\.json|\.aws/credentials|\.ssh/|"
    r"InfoStealer|Stealer|Credentials?Steal)", re.I)
ASCII_RE = re.compile(rb"[\x20-\x7e\t]{4,}")
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def contiguous_b64(data, start):
    i = start
    while i < len(data) and data[i] in B64SET:
        i += 1
    return start, i


def part_a(root):
    p = os.path.join(root, "safemon", "360TrayLogin.tpi")
    data = open(p, "rb").read()
    out = [f"文件 {os.path.getsize(p):,} B"]
    for marker in (b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN CERTIFICATE-----"):
        idx = data.find(marker)
        while idx >= 0:
            s, e = contiguous_b64(data, idx + len(marker))
            raw = data[s:e].replace(b"\r", b"").replace(b"\n", b"").replace(b"\x00", b"").replace(b" ", b"")
            nbytes = len(raw) // 4 * 3
            out.append(f"{marker.decode()} @{idx}: 连续可解析区 {s}..{e}（{e - s} 字节），"
                       f"去噪后 base64 {len(raw)} 字符 ≈ {nbytes} B")
            out.append(f"    断点 @{e}，后续 48B：{data[e:e + 48]!r}")
            out.append(f"    断点前 48B：{data[max(0, e - 48):e]!r}")
            nxt = data.find(marker, idx + 1)
            if nxt - idx > 4000 or nxt < 0:
                break
            idx = nxt
    return out


def strings_of(path, limit=6_000_000):
    with open(path, "rb") as fh:
        data = fh.read(limit)
    out = set()
    for m in ASCII_RE.finditer(data):
        out.add(m.group().decode("latin1"))
    for m in WIDE_RE.finditer(data):
        s = m.group().decode("utf-16-le", "ignore").rstrip("\x00")
        if len(s) >= 4:
            out.add(s)
    return out


def part_b(root):
    out = []
    # 1) 全载荷里谁带私钥/凭据类字符串
    owners = {}
    for base, _dirs, names in os.walk(root):
        for n in names:
            if not n.lower().endswith((".dll", ".exe", ".sys", ".dat", ".enc", ".tpi", ".ui")):
                continue
            p = os.path.join(base, n)
            try:
                ss = strings_of(p)
            except Exception:
                continue
            hits = sorted({s.strip() for s in ss if 4 <= len(s) <= 160 and SECRET_RX.search(s)})
            if hits:
                owners[os.path.relpath(p, root).replace("\\", "/")] = hits
    for rel in sorted(owners, key=lambda r: -len(owners[r])):
        out.append(f"### {rel}（{len(owners[rel])} 条）")
        out.extend(f"- {h[:150]}" for h in owners[rel][:22])

    # 2) qex.dll 的文件类型表上下文（它是"认文件类型"的地方）
    q = os.path.join(root, "deepscan", "qex", "qex.dll")
    if os.path.exists(q):
        data = open(q, "rb").read()
        i = data.find(b"-----BEGIN PRIVATE KEY-----")
        if i > 0:
            lo, hi = max(0, i - 900), min(len(data), i + 1200)
            seg = data[lo:hi]
            out.append(f"\n### qex.dll 文件类型表上下文 @{i}（±900B）")
            toks = [m.group().decode("latin1") for m in re.finditer(rb"[\x20-\x7e]{4,60}", seg)]
            out.append("- 该区域内可打印串：" + " | ".join(t.replace("\n", "\\n") for t in toks[:60]))
    return out


def main():
    root = sys.argv[1]
    print("== A. 360TrayLogin.tpi 中 PKCS#8 片段的真实边界 ==")
    for line in part_a(root):
        print("  " + line)
    print("\n== B. 360 的私钥/凭据类检测面 ==")
    for line in part_b(root):
        print(line)


if __name__ == "__main__":
    main()
