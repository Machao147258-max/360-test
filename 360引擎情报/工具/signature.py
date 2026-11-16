import struct, os, hashlib
from asn1crypto import cms
import pefile

P = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"
OUT = r"C:\Users\20751\Desktop\360逆向\签名"
os.makedirs(OUT, exist_ok=True)

pe = pefile.PE(P, fast_load=True)
sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
raw = pe.__data__
off = sec.VirtualAddress
blob = raw[off:off + sec.Size]
dwLength, wRev, wType = struct.unpack_from("<IHH", blob, 0)
pkcs7 = blob[8:dwLength]
print("WIN_CERTIFICATE len=%d rev=0x%x type=0x%x" % (dwLength, wRev, wType))

ci = cms.ContentInfo.load(pkcs7)
sd = ci["content"]

def fp(cert):
    return ":".join(hashlib.sha256(cert.dump()).hexdigest()[i:i+2] for i in range(0, 64, 2))

def dump_cert(c, tag=""):
    nb = c["tbs_certificate"]["validity"]["not_before"].native
    na = c["tbs_certificate"]["validity"]["not_after"].native
    print("   [%s] %s" % (tag, c.subject.human_friendly))
    print("        issuer : %s" % c.issuer.human_friendly)
    print("        有效期 : %s -> %s" % (nb, na))
    print("        指纹   : %s" % fp(c))

print("\n=== 签名者信息 ===")
for si in sd["signer_infos"]:
    print("  sid serial:", si["sid"].chosen.native.get("serial_number"))
    print("  digest:", si["digest_algorithm"]["algorithm"].native,
          " sig:", si["signature_algorithm"]["algorithm"].native)
    for a in si["signed_attrs"]:
        if a["type"].native == "message_digest":
            md = a["values"][0].native
            print("  message_digest:", md.hex() if isinstance(md, bytes) else md)
    for a in si["unsigned_attrs"] or []:
        if a["type"].native == "counter_signature":
            for cs in a["values"]:
                print("  [RFC3161/countersign] 摘要:",
                      [x["digest_algorithm"]["algorithm"].native for x in cs["signer_infos"]])
                for c in cs["certificates"]:
                    dump_cert(c.chosen, "时间戳")

print("\n=== 证书链 ===")
for c in sd["certificates"]:
    dump_cert(c.chosen)
