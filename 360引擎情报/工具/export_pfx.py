"""Export the payload's Authenticode certificate chains as PEM bundles + PKCS#12 (.pfx).

No private keys exist in the sample, so the .pfx files are certificate-only
(PKCS#12 with cert bags, no key bag). They are for import/verification, not signing.

Usage: python export_pfx.py <payload_root> <outdir>
"""
import os
import struct
import sys
from collections import defaultdict

import pefile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import NoEncryption
from asn1crypto import cms

PE_EXT = {".exe", ".dll", ".sys", ".cpl", ".ocx", ".scr"}
OID_NESTED = "1.3.6.1.4.1.311.2.4.1"


def cert_blobs(path):
    pe = pefile.PE(path, fast_load=True)
    try:
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if not sec.VirtualAddress or not sec.Size:
            return []
        with open(path, "rb") as fh:
            fh.seek(sec.VirtualAddress)
            blob = fh.read(sec.Size)
    finally:
        pe.close()
    out, pos = [], 0
    while pos + 8 <= len(blob):
        length, _rev, ctype = struct.unpack("<IHH", blob[pos:pos + 8])
        if length < 8 or pos + length > len(blob):
            break
        if ctype == 2:
            out.append(blob[pos + 8:pos + length])
        pos += (length + 7) & ~7
    return out


def load_signed_data(der):
    """Yield (signer_serial, [leaf + chain certs]) for the primary and nested signatures."""
    info = cms.ContentInfo.load(der)
    if info["content_type"].native != "signed_data":
        return
    sd = info["content"]
    si = sd["signer_infos"][0]
    sid = si["sid"]
    serial = None
    if sid.name == "issuer_and_serial_number":
        serial = format(sid.chosen["serial_number"].native, "X")
    certs = []
    for c in (sd["certificates"] or []):
        try:
            certs.append(x509.load_der_x509_certificate(c.chosen.dump()))
        except Exception:
            continue
    yield serial, certs
    # nested signature (drivers: 360 EV outer + Microsoft WHQL inner)
    for attr in (si["unsigned_attrs"] or []):
        if attr["type"].dotted != OID_NESTED:
            continue
        for v in attr["values"]:
            try:
                ninfo = cms.ContentInfo.load(v.dump())
                nsd = ninfo["content"]
                nsid = nsd["signer_infos"][0]["sid"]
                nserial = format(nsid.chosen["serial_number"].native, "X") if \
                    nsid.name == "issuer_and_serial_number" else None
                ncerts = []
                for c in (nsd["certificates"] or []):
                    try:
                        ncerts.append(x509.load_der_x509_certificate(c.chosen.dump()))
                    except Exception:
                        continue
                yield nserial, ncerts
            except Exception:
                continue


def safe(name):
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)[:60]


def main():
    root, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    # signer serial -> {leaf: cert, chain: {thumb: cert}, files: set}
    groups = defaultdict(lambda: {"leaf": None, "chain": {}, "files": set()})
    for base, _dirs, names in os.walk(root):
        for n in names:
            if os.path.splitext(n)[1].lower() not in PE_EXT:
                continue
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            for der in cert_blobs(p):
                try:
                    for serial, certs in load_signed_data(der):
                        if not serial or not certs:
                            continue
                        g = groups[serial]
                        g["files"].add(rel)
                        for c in certs:
                            fp = c.fingerprint(hashes.SHA256()).hex()
                            if format(c.serial_number, "X") == serial:
                                g["leaf"] = c
                            else:
                                g["chain"][fp] = c
                except Exception:
                    continue

    manifest = ["# 证书导出清单（PEM + PKCS#12）", "",
                "| 签名者 | 序列号 | 文件数 | PEM | PFX | 内含证书 |", "|---|---|---|---|---|---|"]
    for serial, g in sorted(groups.items(), key=lambda kv: -len(kv[1]["files"])):
        if g["leaf"] is None:
            continue
        leaf = g["leaf"]
        cn = leaf.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        label = safe((cn[0].value if cn else leaf.subject.rfc4514_string())) or "cert"
        stem = f"{label}_{serial}"
        chain = [leaf] + sorted(g["chain"].values(), key=lambda c: c.subject.rfc4514_string())
        pem_path = os.path.join(outdir, stem + ".pem")
        with open(pem_path, "wb") as fh:
            for c in chain:
                fh.write(c.public_bytes(serialization.Encoding.PEM))
        pfx_path = os.path.join(outdir, stem + ".pfx")
        pfx = serialize_key_and_certificates(
            name=label.encode()[:60], key=None, cert=leaf,
            cas=[c for c in chain[1:]], encryption_algorithm=NoEncryption())
        with open(pfx_path, "wb") as fh:
            fh.write(pfx)
        manifest.append(f"| {leaf.subject.rfc4514_string().split(',')[0]} | `{serial}` | "
                        f"{len(g['files'])} | `{os.path.basename(pem_path)}` | "
                        f"`{os.path.basename(pfx_path)}` ({len(pfx):,}B) | {len(chain)} |")

    manifest.append("")
    manifest.append("> 全部为**仅含公钥证书**的 PKCS#12（无 key bag）：样本中不存在任何可用私钥，"
                    "故 pfx 只能用于导入证书库/离线校验链，**不能用于签名**。")
    with open(os.path.join(outdir, "导出清单.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(manifest) + "\n")
    print(f"signers={len(groups)} -> {outdir}")


if __name__ == "__main__":
    main()
