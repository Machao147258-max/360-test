import struct, os, hashlib
import pefile
from asn1crypto import cms, core
from cryptography import x509

P = r"C:\Users\20751\Downloads\setupbeta_jisu.exe"
OUT = r"C:\Users\20751\Desktop\360逆向\签名"
pe = pefile.PE(P, fast_load=True)
sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
blob = pe.__data__[sec.VirtualAddress:sec.VirtualAddress+sec.Size]
p7 = blob[8:struct.unpack_from("<I", blob, 0)[0]]
sd = cms.ContentInfo.load(p7)["content"]
si = sd["signer_infos"][0]

for a in si["unsigned_attrs"]:
    if a["type"].native == "microsoft_time_stamp_token":
        token = a["values"][0]                     # ContentInfo (时间戳 PKCS7)
        ts = cms.ContentInfo.load(token.dump())
        ts_sd = ts["content"]
        tst_der = ts_sd["encap_content_info"]["content"].contents   # TSTInfo
        # 找 GeneralizedTime (tag 0x18)
        i = tst_der.find(b"\x18")
        tlen = tst_der[i+1]
        gentime = tst_der[i+2:i+2+tlen].decode()
        print("[时间戳] genTime:", gentime)
        # TSA 证书
        print("[时间戳] TSA 证书:")
        for c in ts_sd["certificates"]:
            x = x509.load_der_x509_certificate(c.chosen.dump())
            print("   ", x.subject.rfc4514_string())
            print("    issuer:", x.issuer.rfc4514_string())
            print("    有效期:", x.not_valid_before_utc, "->", x.not_valid_after_utc)
            print("    SHA256:", hashlib.sha256(c.chosen.dump()).hexdigest())
            open(os.path.join(OUT, "tsa.cer"), "wb").write(c.chosen.dump())
        open(os.path.join(OUT, "timestamp_token.p7b"), "wb").write(token.dump())
        print("\n时间戳 token 已存 -> 签名/timestamp_token.p7b ; TSA 证书 -> 签名/tsa.cer")
