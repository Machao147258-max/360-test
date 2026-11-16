import struct, os, hashlib
import pefile
from asn1crypto import cms
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

P = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"
pe = pefile.PE(P, fast_load=True)
raw = pe.__data__

# ---- 1) Authenticode 哈希（按微软规范：跳过 checksum 与 security 目录项，段按 offset 排序，排除证书表）----
oh = pe.OPTIONAL_HEADER
e_lfanew = pe.DOS_HEADER.e_lfanew
oh_off = e_lfanew + 4 + 20                     # PE sig(4) + FileHeader(20)
ck_off = oh_off + 64                            # CheckSum 在可选头 +64
datadir_off = oh_off + (96 if oh.Magic == 0x10b else 112)
sec_entry_off = datadir_off + 4 * 8             # DataDirectory[4] = Security
size_of_headers = oh.SizeOfHeaders
cert_file_off = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].VirtualAddress
cert_size = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size

h = hashlib.sha256()
h.update(raw[0:ck_off])                      # 到 CheckSum 前
h.update(raw[ck_off+4:sec_entry_off])        # 跳过 4 字节 checksum
h.update(raw[sec_entry_off+8:size_of_headers])  # 跳过 8 字节 security 目录项，到 headers 末尾
secs = sorted(pe.sections, key=lambda s: s.PointerToRawData)
end = 0
for s in secs:
    data = s.get_data()
    h.update(data)
    end = max(end, s.PointerToRawData + s.SizeOfRawData)
if cert_file_off > end:
    h.update(raw[end:cert_file_off])         # 段后的额外数据（不碰证书表）
calc = h.hexdigest()

# ---- 2) 取签名里的 message_digest ----
sec = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
blob = raw[sec.VirtualAddress:sec.VirtualAddress+sec.Size]
p7 = blob[8:struct.unpack_from("<I", blob, 0)[0]]
sd = cms.ContentInfo.load(p7)["content"]
si = sd["signer_infos"][0]
md = None
for a in si["signed_attrs"]:
    if a["type"].native == "message_digest":
        md = a["values"][0].native
        break

import hashlib as _h
econt = sd["encap_content_info"]["content"].contents        # SpcIndirectDataContent 的 DER（原始字节）
print("sha256(eContent)          :", _h.sha256(econt).hexdigest())
print("signed_attrs.message_digest:", md.hex() if isinstance(md, bytes) else md)
print("  → SignedData 完整性:", _h.sha256(econt).hexdigest() == (md.hex() if isinstance(md, bytes) else md))

# 扫 eContent 里的 32 字节 OCTET STRING（sha256 的 PE 哈希）
pe_hash = None
for i in range(len(econt) - 33):
    if econt[i] == 0x04 and econt[i+1] == 0x20:
        pe_hash = econt[i+2:i+34]
        break
print("\n签名内 PE 哈希     :", pe_hash.hex() if pe_hash else "(未找到)")
print("我重算的 PE 哈希   :", calc)
print("  → PE 哈希一致:", (pe_hash.hex() == calc) if pe_hash else False)

# ---- 3) RSA 验签（对 signed_attrs）----
sa = si["signed_attrs"].dump()
if sa[0] == 0xA0:               # [0] IMPLICIT -> SET OF
    sa = b"\x31" + sa[1:]
sig = si["signature"].native
signer_cert = None
for c in sd["certificates"]:
    cert = c.chosen
    if cert.subject.human_friendly.startswith("Common Name: Beijing Qihu"):
        signer_cert = cert
        break
pub = x509.load_der_x509_certificate(signer_cert.dump()).public_key()
try:
    pub.verify(sig, sa, padding.PKCS1v15(), hashes.SHA256())
    print("RSA-SHA256 验签: ✅ 通过")
except Exception as e:
    print("RSA-SHA256 验签: ❌", e)

# ---- 4) 导出全套证书 ----
out = r"C:\Users\20751\Desktop\360逆向\签名"
print("\n=== 签名里的全部证书 ===")
for i, c in enumerate(sd["certificates"]):
    cert = c.chosen
    x = x509.load_der_x509_certificate(cert.dump())
    der = cert.dump()
    pem = x.public_bytes(serialization.Encoding.PEM)
    open(os.path.join(out, "cert_%d.cer" % i), "wb").write(der)
    open(os.path.join(out, "cert_%d.pem" % i), "wb").write(pem)
    print("--- cert_%d ---" % i)
    print("  Subject :", x.subject.rfc4514_string())
    print("  Issuer  :", x.issuer.rfc4514_string())
    print("  Serial  :", hex(x.serial_number))
    print("  有效期  :", x.not_valid_before_utc, "->", x.not_valid_after_utc)
    print("  KeyAlgo :", x.public_key().__class__.__name__, getattr(x.public_key(), "key_size", ""))
    print("  SigAlgo :", x.signature_hash_algorithm.name)
    print("  SHA256  :", hashlib.sha256(der).hexdigest())
print("\n证书已存 -> 签名/cert_*.cer / *.pem")

# 自签检查
print("\n=== 是否自签 ===")
for i, c in enumerate(sd["certificates"]):
    x = x509.load_der_x509_certificate(c.chosen.dump())
    print("  cert_%d 自签:" % i, x.subject == x.issuer)
