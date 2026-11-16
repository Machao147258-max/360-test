"""360 载荷里的内核/命名对象接口提取（宽串形式）"""
import collections
import os
import re
import sys

ROOT_PREFIXES = ["\\Device\\", "\\DosDevices\\", "\\BaseNamedObjects\\", "\\RPC Control\\", "\\pipe\\"]


def W(s):
    return s.encode("utf-16-le")


def main():
    root = sys.argv[1]
    dev_key = "\\Device\\"
    buckets = {k: (set() if k != dev_key else collections.Counter()) for k in ROOT_PREFIXES}
    for base, _d, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            try:
                data = open(p, "rb").read(12_000_000)
            except Exception:                                     # noqa: BLE001
                continue
            for k in ROOT_PREFIXES:
                pat = re.escape(W(k)) + rb"(?:[\x20-\x7e]\x00){2,40}"
                for m in re.finditer(pat, data):
                    s = m.group(0).decode("utf-16-le", "ignore")
                    if k == dev_key:
                        buckets[k][s] += 1
                    else:
                        buckets[k].add(s)
    for k in ROOT_PREFIXES:
        v = buckets[k]
        print(f"== {k} ==")
        if isinstance(v, collections.Counter):
            for s, c in v.most_common(50):
                print(f"   {s:44s} ×{c}")
        else:
            for s in sorted(v)[:40]:
                print(f"   {s}")
        if not v:
            print("   （无）")
        print()


if __name__ == "__main__":
    main()
