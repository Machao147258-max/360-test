"""360 引擎容器（1EF17ADA 魔数）与病毒库格式探测 —— 纯本地只读

已知：qex.vdb.enc / patt.enc / MacroDef.enc 三个文件头部都是 `1E F1 7A DA`。
本脚本：解析容器头字段、判断载荷是压缩还是加密、并在各引擎模块里定位引用该魔数的代码位置。
"""
import math
import os
import sys
from collections import Counter

MAGIC = bytes.fromhex("1ef17ada")
ENGINE_FILES = [
    "deepscan/qex/qex.dll", "deepscan/deepscan.dll", "deepscan/AVE/AVEngine.dll",
    "deepscan/AVE/AVEI.dll", "deepscan/QVM/360QVM.dll", "deepscan/cloudcom2.dll",
    "deepscan/Cloudsec3.dll", "deepscan/jcloudscan.dll", "deepscan/BAPI.dll",
    "deepscan/avescan.dll", "deepscan/DSFScan.dll",
]
DB_FILES = ["deepscan/qex/qex.vdb.enc", "deepscan/qex/patt.enc", "deepscan/qex/MacroDef.enc"]


def ent(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def u32(b, off):
    return int.from_bytes(b[off:off + 4], "little")


def main():
    root = sys.argv[1]
    print("== 一、容器头解析（magic + 三个 u32 字段）==")
    for rel in DB_FILES:
        p = os.path.join(root, *rel.split("/"))
        data = open(p, "rb").read()
        size = len(data)
        print(f"\n{rel}  文件 {size:,} B  熵(全文件) {ent(data):.2f}")
        print(f"  magic      : {data[:4].hex()}  ({'命中 1EF17ADA' if data[:4] == MAGIC else '不同'})")
        for off in (4, 8, 12):
            v = u32(data, off)
            print(f"  u32@{off:<3}    : {v:#010x} = {v:,}")
        payload = data[16:]
        print(f"  载荷(16+)   : {len(payload):,} B  熵 {ent(payload[:200000]):.2f}")
        heads = {"zlib": b"\x78\x9c", "zlib-low": b"\x78\x01", "lzma": b"\x5d\x00\x00",
                 "7z": b"7z\xbc\xaf", "zip": b"PK\x03\x04", "pe": b"MZ",
                 "sqlite": b"SQLite format 3"}
        hit = [k for k, m in heads.items() if payload.startswith(m)]
        print(f"  载荷头部     : {payload[:16].hex()}  {'→ ' + ','.join(hit) if hit else '（无已知压缩/文件魔数）'}")
        # 单字节 XOR 是否能露出已知头部
        xor_hits = []
        for b in range(1, 256):
            if (payload[0] ^ b) == 0x78 and (payload[1] ^ b) in (0x9C, 0x01, 0xDA):
                xor_hits.append(f"XOR 0x{b:02x} → zlib")
            if (payload[0] ^ b) == 0x50 and (payload[1] ^ b) == 0x4B:
                xor_hits.append(f"XOR 0x{b:02x} → PK")
            if (payload[0] ^ b) == 0x4D and (payload[1] ^ b) == 0x5A:
                xor_hits.append(f"XOR 0x{b:02x} → MZ")
        print(f"  单字节 XOR  : {', '.join(xor_hits) if xor_hits else '无命中（非单字节异或）'}")
        # 16 字节块重复率（ECB 迹象）
        blocks = [payload[i:i + 16] for i in range(0, min(len(payload), 400000) - 15, 16)]
        c = Counter(blocks)
        dup = sum(v - 1 for v in c.values() if v > 1)
        print(f"  16B 块重复  : {dup} / {len(blocks)}（重复率 {dup / max(1, len(blocks)):.4f}）→ "
              f"{'ECB 类分组加密迹象' if dup > len(blocks) * 0.01 else '不像 ECB（更像流加密或压缩）'}")

    print("\n== 二、各引擎模块里对魔数 1EF17ADA 的引用 ==")
    for rel in ENGINE_FILES:
        p = os.path.join(root, *rel.split("/"))
        if not os.path.exists(p):
            continue
        data = open(p, "rb").read()
        poses = []
        i = data.find(MAGIC)
        while i >= 0 and len(poses) < 6:
            poses.append(i)
            i = data.find(MAGIC, i + 1)
        rev = MAGIC[::-1]
        j = data.find(rev)
        print(f"  {rel:32s} 直接字节命中 {poses if poses else '无'}"
              + (f"  反向 {hex(j)}" if j >= 0 else ""))


if __name__ == "__main__":
    main()
