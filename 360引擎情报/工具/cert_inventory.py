"""Authenticode certificate inventory for a tree of PE files.

Reads the WIN_CERTIFICATE table directly (all entries, incl. nested signatures),
parses each PKCS#7 SignedData, and extracts:
  - every embedded certificate (signer / intermediate / timestamping / nested)
  - digest + signature algorithms per signer
  - RFC3161/microsoft time-stamp token: TSA cert + genTime
  - certificate details: serial, validity, key, EKU, AIA, EV subjects

Read-only. Usage: python cert_inventory.py <root> <outdir>
"""
import os
import re
import struct
import sys
from datetime import timezone

import pefile
from asn1crypto import cms, core, x509 as a_x509
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa

PE_EXT = {".exe", ".dll", ".sys", ".cpl", ".ocx", ".scr"}

OID_TIMESTAMP_TOKEN = "1.3.6.1.4.1.311.3.3.1"
OID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1"
OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4"

EKU_LABELS = {
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing (MS)",
    "1.3.6.1.4.1.311.61.4.1": "ELAM (Early Launch Antimalware, MS)",
    "1.3.6.1.4.1.311.61.5.1": "Windows Hardware Driver Verification (MS)",
    "2.23.140.1.3": "EV Code Signing (CA/Browser Forum)",
    "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionLocalityName (EV)",
}


class TSTInfo(core.Sequence):
    _fields = [
        ("version", core.Integer),
        ("policy", core.ObjectIdentifier),
        ("message_imprint", core.Any),
        ("serial_number", core.Integer),
        ("gen_time", core.GeneralizedTime),
        ("accuracy", core.Any, {"optional": True}),
        ("ordering", core.Boolean, {"default": False}),
        ("nonce", core.Integer, {"optional": True}),
        ("tsa", core.Any, {"optional": True}),
        ("extensions", core.Any, {"optional": True}),
    ]


def cert_table(path):
    """Yield raw PKCS#7 blobs from the WIN_CERTIFICATE attribute table."""
    pe = pefile.PE(path, fast_load=True)
    try:
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if not sec.VirtualAddress or not sec.Size:
            return
        with open(path, "rb") as fh:
            fh.seek(sec.VirtualAddress)
            blob = fh.read(sec.Size)
    finally:
        pe.close()
    pos = 0
    while pos + 8 <= len(blob):
        (length, _rev, cert_type) = struct.unpack("<IHH", blob[pos:pos + 8])
        if length < 8 or pos + length > len(blob):
            break
        if cert_type == 0x0002:  # PKCS#7
            yield blob[pos + 8:pos + length]
        pos += (length + 7) & ~7


def oid_string(value):
    """Coerce an asn1crypto attribute value (OID, Sequence-of-OID, ...) to a dotted string."""
    try:
        native = value.native
    except Exception:
        return ""
    if isinstance(native, str):
        return native
    if isinstance(native, (list, tuple)):
        for item in native:
            got = oid_string(item) if hasattr(item, "native") else str(item)
            if got:
                return got
        return ""
    if isinstance(native, dict):
        for item in native.values():
            got = oid_string(item) if hasattr(item, "native") else str(item)
            if got:
                return got
        return ""
    return ""


def attr_values(attrs, oid):
    if attrs is None:
        return []
    oid = a_x509.ObjectIdentifier(oid) if not isinstance(oid, a_x509.ObjectIdentifier) else oid
    out = []
    for attr in attrs:
        if attr["type"].dotted == oid.dotted:
            out.extend(v for v in attr["values"])
    return out


def signer_identity(si):
    """(serial_hex, issuer_der) of the certificate that produced this SignerInfo."""
    try:
        sid = si["sid"]
        if sid.name == "issuer_and_serial_number":
            return (format(sid.chosen["serial_number"].native, "X"),
                    sid.chosen["issuer"].dump())
        return (None, None)
    except Exception:
        return (None, None)


def tst_from_token(token_der):
    """token_der: ContentInfo(SignedData) of a microsoft_time_stamp_token."""
    info = cms.ContentInfo.load(token_der)
    if info["content_type"].native != "signed_data":
        return None
    sd = info["content"]
    gen_time, tsa_certs = None, []
    try:
        encap = sd["encap_content_info"]["content"]
        if encap is not None:
            # eContent is a ParsableOctetString: bytes() is the inner DER, dump() is the wrapper
            tst = TSTInfo.load(bytes(encap))
            gen_time = tst["gen_time"].native
    except Exception:
        pass
    certs = sd["certificates"]
    if certs is not None:
        for c in certs:
            try:
                tsa_certs.append(c_x509.load_der_x509_certificate(c.chosen.dump()))
            except Exception:
                # CertificateChoices may carry non-X.509 entries (MS nested signature etc.)
                continue
    return {"gen_time": gen_time, "certs": tsa_certs,
            "signer": signer_identity(sd["signer_infos"][0])}


def key_info(cert):
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC-{pub.curve.name}"
    if isinstance(pub, dsa.DSAPublicKey):
        return f"DSA-{pub.key_size}"
    return type(pub).__name__


def ev_fields(cert):
    hits = []
    for attr in cert.subject:
        dotted = attr.oid.dotted_string
        if dotted in ("2.5.4.15", "1.3.6.1.4.1.311.60.2.1.1",
                      "1.3.6.1.4.1.311.60.2.1.2", "1.3.6.1.4.1.311.60.2.1.3",
                      "2.5.4.5"):
            hits.append(f"{attr.oid._name}={attr.value}")
    return "; ".join(hits)


def aia(cert):
    """OCSP / CA-issuer URLs from the Authority Information Access extension."""
    out = []
    try:
        ext = cert.extensions.get_extension_for_class(x509_AuthorityInformationAccess)
        for d in ext.value:
            kind = {x509_AuthorityInformationAccessOID.OCSP: "OCSP",
                    x509_AuthorityInformationAccessOID.CA_ISSUERS: "CAIssuers"}.get(d.access_method, "?")
            out.append(f"{kind}:{d.access_location.value}")
    except Exception:
        pass
    return out


def crl(cert):
    out = []
    try:
        ext = cert.extensions.get_extension_for_class(x509_CRLDistributionPoints)
        for dp in ext.value:
            for name in (dp.full_name or []):
                out.append(str(name.value))
    except Exception:
        pass
    return out


def cert_row(cert, role, source=None):
    eku = []
    try:
        ext = cert.extensions.get_extension_for_class(x509_ExtendedKeyUsage)
        eku = [f"{o.dotted_string}({EKU_LABELS.get(o.dotted_string, '?')})" for o in ext.value]
    except Exception:
        pass
    return {
        "role": role,
        "source": source or "",
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "X"),
        "not_before": cert.not_valid_before_utc.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "not_after": cert.not_valid_after_utc.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "thumb_sha1": cert.fingerprint(hashes.SHA1()).hex(),
        "thumb_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "key": key_info(cert),
        "cert_sig_algo": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "?",
        "eku": " | ".join(eku),
        "ev": ev_fields(cert),
        "aia": " | ".join(aia(cert)),
        "crl": " | ".join(crl(cert)),
    }


def process(path, out_rows, out_files):
    entries = list(cert_table(path))
    if not entries:
        return
    for idx, der in enumerate(entries):
        try:
            info = cms.ContentInfo.load(der)
        except Exception as exc:  # noqa: BLE001
            out_files.append({"rel": path, "entry": idx, "digest": f"parse-error {exc}",
                              "sig": "", "tsa": "", "gen_time": "", "note": "PKCS7 parse failed"})
            continue
        if info["content_type"].native != "signed_data":
            continue
        sd = info["content"]
        si = sd["signer_infos"][0]
        digest = si["digest_algorithm"]["algorithm"].native
        sigalgo = si["signature_algorithm"]["algorithm"].native
        signed_attrs = si["signed_attrs"]
        # Authenticode marker = contentType attribute whose value is SPC_INDIRECT_DATA
        # (1.3.6.1.4.1.311.2.1.4); the OID is the *value*, never the attribute type.
        is_auth = False
        statement = ""
        for attr in (signed_attrs or []):
            if attr["type"].dotted == "1.2.840.113549.1.9.3":
                for v in attr["values"]:
                    if oid_string(v) == OID_SPC_INDIRECT_DATA:
                        is_auth = True
            if attr["type"].dotted == "1.3.6.1.4.1.311.2.1.11":
                statement = {"1.3.6.1.4.1.311.2.1.21": "Individual",
                             "1.3.6.1.4.1.311.2.1.22": "Commercial"}.get(
                    oid_string(v) if attr["values"] else "", oid_string(attr["values"][0]) if attr["values"] else "")
        note = f"authenticode/{statement}" if is_auth else "no-spc-indirect-data"

        tsa_subjects, gen_times = [], []
        for token in attr_values(si["unsigned_attrs"], OID_TIMESTAMP_TOKEN):
            try:
                parsed = tst_from_token(token.dump())
            except Exception as exc:  # noqa: BLE001 - keep going, record the miss
                out_files.append({"rel": path, "entry": idx, "kind": "primary", "digest": digest,
                                  "sig": sigalgo, "tsa": "", "gen_time": "",
                                  "note": f"timestamp-parse-error {type(exc).__name__}: {exc}"})
                continue
            if parsed:
                t_sid_serial, t_sid_issuer = parsed.get("signer") or (None, None)
                for c in parsed["certs"]:
                    role = "tsa" if (t_sid_serial and format(c.serial_number, "X") == t_sid_serial) else "tsa-chain"
                    out_rows.append((path, idx, cert_row(c, role, source="timestamp-token")))
                tsa_subjects = [c.subject.rfc4514_string() for c in parsed["certs"]
                                if t_sid_serial and format(c.serial_number, "X") == t_sid_serial]
                if parsed["gen_time"]:
                    gen_times.append(parsed["gen_time"].strftime("%Y-%m-%d %H:%M:%S"))

        s_serial, s_issuer_der = signer_identity(si)
        certs = sd["certificates"]
        if certs is not None:
            for c in certs:
                try:
                    cert = c_x509.load_der_x509_certificate(c.chosen.dump())
                except Exception:
                    continue
                is_signer = s_serial is not None and format(cert.serial_number, "X") == s_serial
                out_rows.append((path, idx, cert_row(cert, "signer" if is_signer else "chain")))

        # legacy Authenticode countersignature (RFC 5652 1.2.840.113549.1.9.6):
        # an extra SignerInfo whose signedAttrs carry the signingTime.
        for cs in attr_values(si["unsigned_attrs"], "1.2.840.113549.1.9.6"):
            try:
                cs_serial, _ = signer_identity(cs)
                cs_time = ""
                for t in attr_values(cs["signed_attrs"], "1.2.840.113549.1.9.5"):
                    try:
                        cs_time = t.native.astimezone(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        cs_time = str(getattr(t, "native", ""))
                # countersignature SignerInfo usually carries no embedded certs —
                # the TSA certificate is resolved from the system store.
                cs_certs = cs["certificates"] if "certificates" in cs else None
                for c in (cs_certs or []):
                    try:
                        cert = c_x509.load_der_x509_certificate(c.chosen.dump())
                    except Exception:
                        continue
                    is_cs = cs_serial is not None and format(cert.serial_number, "X") == cs_serial
                    out_rows.append((path, idx, cert_row(
                        cert, "countersigner" if is_cs else "countersig-chain", source="countersignature")))
                out_files.append({"rel": path, "entry": idx, "kind": "countersignature",
                                  "digest": cs["digest_algorithm"]["algorithm"].native,
                                  "sig": cs["signature_algorithm"]["algorithm"].native,
                                  "tsa": "", "gen_time": cs_time,
                                  "note": "countersigned"})
            except Exception as exc:  # noqa: BLE001
                out_files.append({"rel": path, "entry": idx, "kind": "countersignature",
                                  "digest": "", "sig": "", "tsa": "", "gen_time": "",
                                  "note": f"countersig-parse-error {type(exc).__name__}: {exc}"})

        # dual / nested signatures (typical for drivers: MS WHQL inside 360's)
        nested = attr_values(si["unsigned_attrs"], OID_NESTED_SIGNATURE)
        for n in nested:
            try:
                ninfo = cms.ContentInfo.load(n.dump() if hasattr(n, "dump") else bytes(n))
                nsd = ninfo["content"]
                n_sid_serial, _ = signer_identity(nsd["signer_infos"][0])
                for c in (nsd["certificates"] or []):
                    cert = c_x509.load_der_x509_certificate(c.chosen.dump())
                    is_nsigner = n_sid_serial is not None and format(cert.serial_number, "X") == n_sid_serial
                    out_rows.append((path, idx, cert_row(
                        cert, "nested-signer" if is_nsigner else "nested-chain", source="nested-signature")))
                nsi = nsd["signer_infos"][0]
                out_files.append({
                    "rel": path, "entry": idx, "kind": "nested",
                    "digest": nsi["digest_algorithm"]["algorithm"].native,
                    "sig": nsi["signature_algorithm"]["algorithm"].native,
                    "tsa": " | ".join(tsa_subjects), "gen_time": " | ".join(gen_times),
                    "note": "nested-signature-present",
                })
            except Exception as exc:  # noqa: BLE001
                out_files.append({"rel": path, "entry": idx, "kind": "nested", "digest": digest,
                                  "sig": sigalgo, "tsa": " | ".join(tsa_subjects),
                                  "gen_time": " | ".join(gen_times),
                                  "note": f"nested-parse-error {type(exc).__name__}: {exc}"})
        out_files.append({"rel": path, "entry": idx, "kind": "primary", "digest": digest,
                          "sig": sigalgo, "tsa": " | ".join(tsa_subjects),
                          "gen_time": " | ".join(gen_times), "note": note})


# extended-usage helpers imported lazily to keep the module import list short
from cryptography.x509 import (
    AuthorityInformationAccess as x509_AuthorityInformationAccess,
    AuthorityInformationAccessOID as x509_AuthorityInformationAccessOID,
    CRLDistributionPoints as x509_CRLDistributionPoints,
    ExtendedKeyUsage as x509_ExtendedKeyUsage,
)


def main():
    root, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    rows, files = [], []
    for base, _dirs, names in os.walk(root):
        for n in names:
            if os.path.splitext(n)[1].lower() not in PE_EXT:
                continue
            p = os.path.join(base, n)
            try:
                process(p, rows, files)
            except Exception as exc:  # noqa: BLE001
                files.append({"rel": p, "entry": -1, "kind": "primary", "digest": "", "sig": "",
                              "tsa": "", "gen_time": "", "note": f"ERROR {type(exc).__name__}: {exc}"})
    # rows carry the walk path; emit paths relative to root exactly once
    def norm(value):
        value = str(value)
        return (os.path.relpath(value, root) if value.startswith(root) else value).replace("\\", "/")

    for f in files:
        f["rel"] = norm(f["rel"])

    cols = ["rel", "role", "source", "subject", "issuer", "serial", "not_before", "not_after",
            "thumb_sha1", "thumb_sha256", "key", "cert_sig_algo", "eku", "ev", "aia", "crl"]
    with open(os.path.join(outdir, "cert_inventory.tsv"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(cols) + "\n")
        for rel, entry, row in rows:
            row = dict(row)
            row["rel"] = os.path.relpath(rel, root).replace("\\", "/") + f"#sig{entry}"
            fh.write("\t".join(str(row.get(c, "")).replace("\t", " ").replace("\n", " ") for c in cols) + "\n")

    fcols = ["rel", "entry", "kind", "digest", "sig", "tsa", "gen_time", "note"]
    with open(os.path.join(outdir, "signature_entries.tsv"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(fcols) + "\n")
        for f in files:
            fh.write("\t".join(str(f.get(c, "")).replace("\t", " ") for c in fcols) + "\n")

    # unique cert inventory
    uniq = {}
    for _rel, _e, row in rows:
        uniq.setdefault(row["thumb_sha256"], row)
    with open(os.path.join(outdir, "certs_unique.tsv"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(cols[1:]) + "\n")
        for row in uniq.values():
            fh.write("\t".join(str(row.get(c, "")).replace("\t", " ") for c in cols[1:]) + "\n")

    print(f"files-with-signature={len(files)} cert-rows={len(rows)} unique-certs={len(uniq)} -> {outdir}")


if __name__ == "__main__":
    main()
