"""Module dossier: static facts + categorized strings for a list of PEs.

Read-only. Usage:
  python dossier.py <root> <listfile|relpath...> [--outdir DIR]

Writes one text dossier per module and prints a short summary.
"""
import os
import re
import sys

import pefile

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

CATEGORIES = [
    ("device", re.compile(r"\\\\[?.]?\\?(?:Device|GLOBALROOT|KernelObjects|BaseNamedObjects)?\\?[A-Za-z0-9_\\{}.-]{3,}", re.I)),
    ("dosdev", re.compile(r"\\\\[.?]\\(?:[A-Za-z0-9_]{2,})", re.I)),
    ("registry", re.compile(r"(?:SOFTWARE|SYSTEM|HARDWARE|SECURITY|SAM)\\[A-Za-z0-9_\\ .{}-]{3,120}", re.I)),
    ("service", re.compile(r"[A-Za-z0-9_]{2,40}\d?\.sys\b", re.I)),
    ("url", re.compile(r"https?://[A-Za-z0-9_.:/?=&%#@!~+-]{4,160}", re.I)),
    ("mutex", re.compile(r"(?:Global|Local|Session)\\\\[A-Za-z0-9_@{}.$-]{3,80}", re.I)),
    ("guid", re.compile(r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}")),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("path", re.compile(r"[A-Za-z]:\\[A-Za-z0-9_\\ .-]{4,120}")),
    ("api", re.compile(r"\b(?:Nt|Zw)[A-Z][A-Za-z0-9]{3,40}\b")),
    ("ioctl_hint", re.compile(r"(?:IOCTL|CTL_CODE|DeviceIoControl)[A-Za-z0-9_]{0,40}", re.I)),
    ("protect", re.compile(r"(?:SelfProtect|AntiHack|AntiExploit|AntiSteal|AntiHijack|DisProc|hookport|blacklist|whitelist|protect)[A-Za-z0-9_]{0,40}", re.I)),
]

NOISE = re.compile(r"^(?:[A-Za-z]{1,4}|\.{2,}|[0-9]+)$")


def strings_of(path):
    data = open(path, "rb").read()
    out = set()
    for m in ASCII_RE.finditer(data):
        out.add(m.group().decode("latin1"))
    for m in WIDE_RE.finditer(data):
        out.add(m.group().decode("utf-16-le", "ignore").rstrip("\x00"))
    return out


def categorize(items):
    buckets = {name: set() for name, _ in CATEGORIES}
    for s in items:
        s = s.strip()
        if len(s) < 4 or NOISE.match(s):
            continue
        for name, rx in CATEGORIES:
            if rx.search(s):
                buckets[name].add(s[:240])
    return buckets


def dossier(path, root):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
    ])
    lines = [f"### {os.path.relpath(path, root)}",
             f"- arch: {'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'}  size: {os.path.getsize(path):,}",
             f"- entry: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}"]
    lines.append("- sections: " + ", ".join(
        f"{s.Name.rstrip(chr(0).encode()).decode('latin1','replace')}({s.Misc_VirtualSize}B)" for s in pe.sections))
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        lines.append("- imports:")
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            names = [i.name.decode("latin1", "replace") for i in e.imports if i.name]
            lines.append(f"  - {e.dll.decode('latin1','replace')}: {', '.join(names[:40])}"
                         + (" ..." if len(names) > 40 else ""))
    buckets = categorize(strings_of(path))
    for name, _ in CATEGORIES:
        vals = sorted(buckets[name])
        if not vals:
            continue
        lines.append(f"- {name} ({len(vals)}):")
        for v in vals[:60]:
            lines.append(f"  - {v}")
    pe.close()
    return "\n".join(lines)


def main():
    root = sys.argv[1]
    args = [a for a in sys.argv[2:] if not a.startswith("--")]
    outdir = None
    if "--outdir" in sys.argv:
        outdir = sys.argv[sys.argv.index("--outdir") + 1]
        args = [a for a in args if a != outdir]
    if len(args) == 1 and args[0].endswith(".txt"):
        targets = [l.strip() for l in open(args[0], encoding="utf-8") if l.strip()]
    else:
        targets = args
    blocks = []
    for rel in targets:
        path = rel if os.path.isabs(rel) else os.path.join(root, rel)
        try:
            blocks.append(dossier(path, root))
        except Exception as exc:  # noqa: BLE001
            blocks.append(f"### {rel}\n- ERROR {type(exc).__name__}: {exc}")
    text = "# module dossiers\n\n" + "\n\n".join(blocks) + "\n"
    if outdir:
        os.makedirs(outdir, exist_ok=True)
        dest = os.path.join(outdir, "dossier.md")
        with open(dest, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print(f"modules={len(targets)} -> {dest}")
    else:
        print(text)


if __name__ == "__main__":
    main()
