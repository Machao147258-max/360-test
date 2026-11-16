#!/usr/bin/env python3
"""lab-c2/tools/setcfg.py - 生成 implant/c2conf.h (C2 地址 / 端口 / 协议)

用法: python tools/setcfg.py <host> <port> [--tls]

为什么要有这个工具: C2_HOST 是宽字符串字面量 (L"..."), 在 cl 命令行上写
/DC2_HOST=L"x" 要过 cmd 与 CRT 两轮引号解析, 极易踩坑; 生成头文件最干净。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "implant", "c2conf.h")

TPL = """#pragma once
// 由 tools/setcfg.py 生成 - 不要手改
// 靶场默认: 宿主机在 vmnet8 NAT 里的网关地址; 克隆靶机 192.168.253.140 可直接回连宿主。
#define C2_HOST L"{host}"
#define C2_PORT {port}
#define C2_SECURE {secure}
"""


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    host = sys.argv[1]
    port = int(sys.argv[2])
    secure = 1 if "--tls" in sys.argv[3:] else 0
    with open(OUT, "w", encoding="ascii") as f:
        f.write(TPL.format(host=host, port=port, secure=secure))
    print(f"[+] c2conf.h -> C2_HOST={host} C2_PORT={port} C2_SECURE={secure}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
