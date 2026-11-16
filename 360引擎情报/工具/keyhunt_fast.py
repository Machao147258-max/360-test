"""私钥猎取（快速版 v2）—— 限读 + 廉价预筛 + 实时进度

改进点（针对 Desktop 12.2 万文件 / 15.9 GB 的规模）：
  1. 每文件只读首 4 MB + 末 1 MB（私钥都在文件头尾）
  2. **廉价预筛**：先用 bytes.find 找几个高区分度标记（C 速度），只有命中才跑正则
     —— 避免对全部二进制都做多趟正则扫描（这是上一版慢的根因）
  3. 进度按"已处理 MB / 命中数 / 当前目录 / ETA"逐行 flush，同时追加写日志文件

用法： python keyhunt_fast.py <目录> [日志文件]
"""
import os
import re
import sys
import time

HEAD = 4 * 1024 * 1024
TAIL = 1024 * 1024
SKIP_EXT = (".mp3", ".mp4", ".mkv", ".avi", ".mov", ".flv", ".wav", ".png", ".jpg", ".jpeg",
            ".gif", ".webp", ".ico", ".ttf", ".otf", ".woff", ".woff2", ".iso", ".vmdk")
KEY_EXT = (".key", ".pem", ".pfx", ".p12", ".p8", ".pk8", ".jks", ".keystore", ".ppk", ".pptx")

# 高区分度廉价标记（find 即可，C 速度）
CHEAP = [
    b"PRIVATE KEY",
    b"PuTTY-User-Key-File",
    b"openssh-key-v1",
    b"\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",   # PKCS#8 AlgorithmIdentifier
    b"\x02\x01\x00\x02\x82",                                                # PKCS#1 / RSAPrivateKey
    b"\x02\x01\x03\x30\x82",                                                # PKCS#12 版本头
    b"ssh-rsa AAAA",
]
PEM_PRIV = re.compile(rb"-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY[ A-Z0-9]{0,20})-----")
DER_PKCS8 = re.compile(rb"\x30\x82(..)\x02\x01\x00\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x04\x82")
DER_PKCS1 = re.compile(rb"\x30\x82(..)\x02\x01\x00\x02\x82")
DER_EC = re.compile(rb"\x30[\x70-\x7e]\x02\x01\x01\x04\x20")
OTHER = {"PKCS12": rb"\x30\x82(..)\x02\x01\x03\x30\x82", "PuTTY": rb"PuTTY-User-Key-File",
         "openssh-key": rb"openssh-key-v1", "ssh-rsa-public": rb"ssh-rsa AAAA"}

LOG = None


def say(msg):
    print(msg, flush=True)
    if LOG:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(msg + "\n")


def scan(data, where):
    hits = []
    for m in PEM_PRIV.finditer(data):
        end = data.find(b"-----END", m.end())
        body = data[m.end():end if end > 0 else m.end() + 4096]
        clean = re.sub(rb"[^A-Za-z0-9+/=]", b"", body)
        hits.append(f"{where} | PEM {m.group(1).decode('latin1','ignore')} @{m.start()} "
                    f"base64 {len(clean)} → 约 {len(clean)//4*3} B | END={'有' if end>0 else '无'}")
    for name, rx in (("PKCS8-RSA", DER_PKCS8), ("PKCS1-RSA", DER_PKCS1), ("EC-PRIV", DER_EC)):
        for m in rx.finditer(data):
            dec = (int.from_bytes(m.group(1), "big") + 4) if m.groups() else None
            hits.append(f"{where} | DER {name} @{m.start()} 声明 {dec} B")
    for name, rx in OTHER.items():
        for m in re.finditer(rx, data):
            hits.append(f"{where} | {name} @{m.start()}")
    return hits


def parts(path, size):
    with open(path, "rb") as fh:
        head = fh.read(min(HEAD, size))
        tail = b""
        if size > HEAD:
            fh.seek(max(0, size - TAIL))
            tail = fh.read(TAIL)
    return head, tail


def main():
    global LOG
    root = sys.argv[1]
    LOG = sys.argv[2] if len(sys.argv) > 2 else None
    if LOG:
        open(LOG, "w", encoding="utf-8").close()
    t0 = time.time()
    n = hits = mb = 0
    t0_mb = time.time()
    say(f"[start] {root} | 首 {HEAD//1048576}MB + 末 {TAIL//1024}KB | 预筛标记 {len(CHEAP)} 个")
    for base, _dirs, names in os.walk(root):
        for nm in names:
            ext = os.path.splitext(nm)[1].lower()
            if ext in SKIP_EXT:
                continue
            p = os.path.join(base, nm)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            n += 1
            mb += size / 1048576
            if ext in KEY_EXT:
                say(f"[扩展名] {p} ({size:,} B)")
            if size == 0:
                continue
            try:
                head, tail = parts(p, size)
            except OSError as exc:
                say(f"[!] {p}: {exc}")
                continue
            for blob, tag in ((head, p), (tail, p + "#tail")):
                if not blob:
                    continue
                if not any(mark in blob for mark in CHEAP):      # 廉价预筛，未命中直接跳过
                    continue
                for h in scan(blob, tag):
                    say("[命中] " + h)
                    hits += 1
            if n % 500 == 0:
                el = time.time() - t0_mb
                say(f"[进度] {n} 文件 / {mb:.0f} MB / 命中 {hits} / {time.time()-t0:.0f}s / "
                    f"{mb/max(el,1e-9):.0f} MB/s / 当前 {base}")
    el = time.time() - t0
    say(f"[done] {n} 文件 / {mb:.0f} MB / 命中 {hits} / 用时 {el:.0f}s / 均速 {mb/max(el,1e-9):.0f} MB/s")


if __name__ == "__main__":
    main()
