# -*- coding: utf-8 -*-
# packer.py -- 加壳器: 把 payload 加密后写成资源(.rc), 供壳(stub)运行时解密加载
# 用法: python tools\packer.py [payload路径]   默认 bin\payload_dll.dll
# 教学件; 只做"隐藏+内存执行", 不含任何反杀软/对抗特性。
import sys, os

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)
XOR_KEY = 0x5A
RES_ID  = 100

payload = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "bin", "payload_dll.dll")
if not os.path.isabs(payload):
    payload = os.path.join(ROOT, payload)
data = open(payload, "rb").read()

enc = bytes(b ^ XOR_KEY for b in data)
encpath = os.path.join(ROOT, "build", "payload.enc")
rcpath  = os.path.join(ROOT, "build", "packed.rc")
os.makedirs(os.path.dirname(encpath), exist_ok=True)
open(encpath, "wb").write(enc)
open(rcpath, "w", newline="\n").write(f'{RES_ID} RCDATA "payload.enc"\n')

print(f"[packer] payload : {os.path.basename(payload)} ({len(data)} bytes)")
print(f"[packer] encrypt : XOR 0x{XOR_KEY:02X} -> build\\payload.enc")
print(f"[packer] resource: {RES_ID} RCDATA -> build\\packed.rc")
