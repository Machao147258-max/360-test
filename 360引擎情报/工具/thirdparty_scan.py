"""360 载荷 · 第三方组件/SDK 清单（纯静态指纹）

做法：按"库特征串 + 版本正则 + 符号名"三类指纹扫全载荷，产出组件清单与版本，
      便于后续对 N-day（这是"绕过/攻击面"最实际的一条线）。

指纹来源：
  · 版本串（每个库自己打印的版本格式）
  · 版权/项目串
  · 导出符号特征（如 sqlite3_*、BZ2_*、inflate*、png_*）
"""
import os
import re
import sys
from collections import Counter, defaultdict

import pefile

LIBS = [
    ("SQLite", r"SQLite version|sqlite3_libversion|SQLITE_SOURCE_ID|sqlite3_sourceid"),
    ("OpenSSL", r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)|openssl_lib|OpenSSL_add_all_algorithms"),
    ("zlib", r"inflate\s+(\d+\.\d+\.\d+)|zlib\s+(\d+\.\d+\.\d+)|deflate\s+\d+\.\d+\.\d+"),
    ("libpng", r"libpng version\s+(\d+\.\d+\.\d+)|png_\w+_version"),
    ("libjpeg", r"libjpeg|Independent JPEG Group|jpeg-(\d+[a-z]?)"),
    ("protobuf", r"protobuf|google::protobuf|Protocol Buffers|proto3"),
    ("PCRE", r"PCRE\s+(\d+\.\d+)|pcre_compile|pcre2_compile|PCRE2"),
    ("libcurl", r"libcurl/(\d+\.\d+\.\d+)|curl_easy_"),
    ("Boost", r"boost_(\d+_\d+)|Boost\.(?:Program_options|Filesystem)"),
    ("ICU", r"ICU\s+(\d+\.\d+)|u_strToUTF8|icuuc|icuin"),
    ("Qt", r"Qt\s+(\d+\.\d+\.\d+)|QtCore|QtGui|Qt5|Qt6"),
    ("Chromium/CEF", r"Chrome/(\d+\.\d+\.\d+\.\d+)|Chromium|CEF\s+(\d+)|libcef"),
    ("Detours", r"Detours|detour_\w+|DetourTransaction"),
    ("Lua", r"Lua\s+(\d+\.\d+(?:\.\d+)?)|lua_pcall|luaL_newstate"),
    ("BZip2", r"BZ2_\w+|bzip2"),
    ("7-Zip/LZMA", r"LZMA\s+(\d+\.\d+)|7-Zip|LzmaDec"),
    ("unrar", r"unrar|RARLAB|UnRAR"),
    ("libxml2", r"libxml2|xmlParseDocument|LIBXML_DOTTED_VERSION"),
    ("expat", r"expat_|XML_ParserCreate|expat\s+(\d+\.\d+\.\d+)"),
    ("ImageMagick", r"ImageMagick|MagickCore"),
    ("FFmpeg", r"FFmpeg|libavcodec|avcodec_"),
    ("NSS/NSPR", r"NSS\s+(\d+\.\d+)|NSPR|nspr4"),
    ("python", r"Python\s+(\d+\.\d+\.\d+)|python3\d"),
    ("node/v8", r"v8::|node\.js|V8 version"),
    ("TinyXML/rapidjson", r"tinyxml|rapidjson"),
    ("libevent", r"libevent|event_base_new"),
    ("libssh2", r"libssh2|SSH2_"),
    ("sqlcipher", r"sqlcipher|PRAGMA key"),
    ("BerkeleyDB", r"Berkeley DB|db_create"),
    ("Microsoft Detours/crt", r"microsoft corporation\. all rights reserved"),
    ("Adobe/Flash", r"Adobe|Shockwave"),
    ("WPS/Office SDK", r"Kingsoft|WPS Office|wpsapi"),
    ("Chrome NativeMsg/WebRTC", r"webrtc|NativeMessaging"),
    ("Nvidia/Intel codec", r"nvEncodeAPI|MediaSDK"),
    ("libyaml/jsoncpp", r"jsoncpp|yaml_parser"),
    ("SVM/libsvm (ML)", r"libsvm|svm_predict|SVM\s+(\d)"),
    ("OpenCV", r"OpenCV|opencv_|cv::"),
    ("crypto libs (mbedTLS)", r"mbedtls|mbed TLS"),
    ("libsodium", r"libsodium|sodium_init|NaCl"),
    ("wolfSSL", r"wolfSSL|wolfssl"),
    ("Botan", r"Botan\s+(\d+\.\d+)|\bBotan::"),
    ("cryptopp", r"Crypto\+\+|cryptopp"),
    ("7z SDK", r"7zIn|7zAlloc"),
    ("RapidOCR/onnx", r"onnxruntime|onnx::"),
    ("TensorFlow/tflite", r"tensorflow::|tflite|TFLite"),
    ("NSIS/InstallShield", r"NSIS|Nullsoft|InstallShield"),
    ("WinPcap/npcap", r"WinPcap|npcap|pcap_next_ex"),
    ("nmap-ish/libnet", r"libnet_|nmap"),
    ("OpenVPN/wintun", r"OpenVPN|wintun|Wintun"),
    ("TAP/wireguard", r"WireGuard|wireguard|wg-quick"),
]

VER_RX = re.compile(rb"(?:version|v)\s*[=: ]?\s*(\d+\.\d+(?:\.\d+)*[a-z]?)", re.I)


def main():
    root = sys.argv[1]
    hits = defaultdict(lambda: defaultdict(set))
    exports_by_mod = {}
    ext_stat = Counter()
    for base, _d, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            rel = os.path.relpath(p, root).replace("\\", "/")
            try:
                data = open(p, "rb").read(20_000_000)
            except Exception:                                     # noqa: BLE001
                continue
            ext = os.path.splitext(n)[1].lower()
            ext_stat[ext] += 1
            for lib, pat in LIBS:
                rx = re.compile(pat.encode() if isinstance(pat, str) else pat, re.I)
                m = rx.search(data)
                if m:
                    ctx = data[max(0, m.start() - 40):m.end() + 60]
                    ctx = re.sub(rb"[^\x20-\x7e]", b".", ctx).decode("latin1")
                    hits[lib][rel].add(ctx[:110])
            if ext in (".dll", ".exe", ".ocx", ".cpl", ".tpi"):
                try:
                    pe = pefile.PE(p, fast_load=True)
                    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
                    exps = [s.name.decode("latin1") for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name] \
                        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else []
                    pe.close()
                    exports_by_mod[rel] = exps
                except Exception:                                 # noqa: BLE001
                    pass
    # 用导出符号把库归属钉死
    sym_rules = {
        "sqlite3_": "SQLite", "BZ2_": "BZip2", "inflate": "zlib", "deflate": "zlib",
        "png_": "libpng", "lua": "Lua", "curl_": "libcurl", "pcre": "PCRE",
        "xml": "libxml2/expat", "avcodec": "FFmpeg", "sqlcipher": "sqlcipher",
    }
    sym_hits = defaultdict(set)
    for rel, exps in exports_by_mod.items():
        for pre, lib in sym_rules.items():
            if any(e.lower().startswith(pre) for e in exps):
                sym_hits[lib].add(f"{rel}（导出符号）")

    print("== 第三方组件指纹命中 ==")
    for lib, files in sorted(hits.items(), key=lambda kv: -len(kv[1])):
        print(f"\n### {lib}  —— {len(files)} 个文件")
        for rel in sorted(files)[:6]:
            for ctx in list(files[rel])[:2]:
                print(f"   {rel:52s} | {ctx}")
        if len(files) > 6:
            print(f"   …另有 {len(files)-6} 个文件")
    if sym_hits:
        print("\n== 用导出符号钉死的组件 ==")
        for lib, mods in sorted(sym_hits.items()):
            print(f"   {lib}: {', '.join(sorted(mods)[:6])}")


if __name__ == "__main__":
    main()
