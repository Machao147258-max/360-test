"""私钥猎取 —— 在 360 载荷全量文件里找私钥材料（纯本地只读）

覆盖：
  · PEM：RSA/EC/DSA/OPENSSH/PKCS8/ENCRYPTED 各类 PRIVATE KEY 头
  · 二进制：PKCS#8 / PKCS#1 / ECPrivateKey 的 DER 结构签名
  · 其他：PKCS#12、PuTTY、ssh-rsa 公钥串、.key/.pem/.pfx 扩展名
  · 专项：safemon/360TrayLogin.tpi 里那段被零填充打断的 PKCS#8 片段，尽量还原长度与缺口位置
"""
import base64
import os
import re
import sys

PEM_PRIV = re.compile(rb"-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY[ A-Z0-9]{0,20})-----")
DER_PKCS8_RSA = re.compile(rb"\x30\x82(..)\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x04\x82")
DER_PKCS1_RSA = re.compile(rb"\x30\x82(..)\x02\x01\x00\x02\x82")
DER_EC = re.compile(rb"\x30[\x70-\x7e]\x02\x01\x01\x04\x20")
OTHER = {
    "PKCS12": rb"\x30\x82(..)\x02\x01\x03\x30\x82",
    "PuTTY": rb"PuTTY-User-Key-File",
    "ssh-rsa-public": rb"ssh-rsa AAAA",
    "openssh-key": rb"openssh-key-v1",
    "AGE/SSH-ED25519": rb"-----BEGIN OPENSSH PRIVATE KEY-----",
}
KEY_EXT = (".key", ".pem", ".pfx", ".p12", ".p8", ".pk8", ".jks", ".keystore")
B64_RUN = re.compile(rb"[A-Za-z0-9+/=]{80,}")


def scan(path):
    with open(path, "rb") as fh:
        data = fh.read()
    hits = []
    for m in PEM_PRIV.finditer(data):
        end = data.find(b"-----END", m.end())
        body = data[m.end():end if end > 0 else m.end() + 4096]
        clean = re.sub(rb"[^A-Za-z0-9+/=]", b"", body)
        dec_len = len(clean) // 4 * 3
        hits.append(("PEM", m.start(), m.group(1).decode("latin1", "ignore"),
                     f"END标记={'有' if end > 0 else '无'}", f"base64 {len(clean)} 字符 → 约 {dec_len} B"))
    for name, rx in [("PKCS8-RSA", DER_PKCS8_RSA), ("PKCS1-RSA", DER_PKCS1_RSA), ("EC-PRIV", DER_EC)]:
        for m in rx.finditer(data):
            declared = int.from_bytes(m.group(1), "big") + 4 if m.groups() else None
            hits.append(("DER", m.start(), name, f"声明长度 {declared}", ""))
    for name, rx in OTHER.items():
        for m in re.finditer(rx, data):
            hits.append(("OTHER", m.start(), name, "", ""))
    return hits, data


def tpi_recover(path):
    """专项：还原 360TrayLogin.tpi 里那段 PKCS#8"""
    with open(path, "rb") as fh:
        data = fh.read()
    i = data.find(b"-----BEGIN PRIVATE KEY-----")
    if i < 0:
        return ["未找到 BEGIN PRIVATE KEY 标记"]
    out = [f"BEGIN 标记 @ {i}"]
    # 该块内所有 base64 run，按位置顺序拼接
    region_end = data.find(b"-----END", i)
    region = data[i:region_end if region_end > 0 else i + 200000]
    runs = [(m.start(), m.group()) for m in B64_RUN.finditer(region)]
    out.append(f"块内 base64 run 数：{len(runs)}，长度序列：{[len(r) for _o, r in runs][:12]}")
    joined = b"".join(r for _o, r in runs)
    for name, blob in (("仅首个 run", runs[0][1] if runs else b""), ("全 run 拼接", joined)):
        try:
            der = base64.b64decode(blob[:len(blob) // 4 * 4])
        except Exception as exc:                     # noqa: BLE001
            out.append(f"{name}: base64 解码失败 {exc}")
            continue
        claim = int.from_bytes(der[2:4], "big") + 4 if len(der) > 4 and der[0] == 0x30 else None
        out.append(f"{name}: 解出 {len(der)} B"
                   + (f"，DER 自述总长 {claim} B → {'完整' if claim and claim == len(der) else '被截断，缺 %d B' % (claim - len(der)) if claim else ''}" if claim else ""))
        for marker, label in ((b"\x02\x82\x01\x01\x00", "RSA 模数(257B)"),
                              (b"\x02\x82\x01\x01", "RSA 私钥指数段"),
                              (b"\x02\x82\x01\x00", "RSA 1024 段")):
            pos = der.find(marker)
            out.append(f"    {label}: {'@ ' + str(pos) if pos >= 0 else '未出现'}")
    # 全域搜同一片段/续段
    for probe in (b"MIIEvgIBADA", b"ZwjhUU2Ays"):
        cnt = data.count(probe)
        out.append(f"片段 {probe!r} 出现 {cnt} 次")
    return out


def main():
    root = sys.argv[1]
    print("== 一、全载荷私钥材料扫描 ==")
    total = 0
    for base, _dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            hits = []
            try:
                hits, _data = scan(p)
            except Exception as exc:                 # noqa: BLE001
                print(f"  ! {rel} 读取失败 {exc}")
                continue
            if os.path.splitext(n)[1].lower() in KEY_EXT:
                print(f"  [扩展名命中] {rel} ({os.path.getsize(p):,} B)")
            for kind, off, name, note, extra in hits:
                total += 1
                print(f"  [{kind}] {rel} @{off} {name} {note} {extra}")
    print(f"  合计命中 {total} 条")

    print("\n== 二、360TrayLogin.tpi 的 PKCS#8 片段还原 ==")
    tpi = os.path.join(root, "safemon", "360TrayLogin.tpi")
    if os.path.exists(tpi):
        for line in tpi_recover(tpi):
            print("  " + line)
    else:
        print("  文件不存在")


if __name__ == "__main__":
    main()
