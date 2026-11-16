"""Batch PE profiling for the unpacked 360 payload.

Emits a TSV with static facts + packing heuristics. No execution, read-only.
Usage: python pe_scan.py <root_dir> <out.tsv>
"""
import hashlib
import math
import os
import sys
import datetime

import pefile

PE_EXT = {".exe", ".dll", ".sys", ".cpl", ".ocx", ".scr", ".efi"}

# APIs whose presence tells us what a module actually does.
INTEREST = [
    "DeviceIoControl", "NtQueryInformationProcess", "NtQuerySystemInformation",
    "CreateServiceW", "CreateServiceA", "OpenSCManagerW", "RegSetValueExW",
    "RegCreateKeyExW", "WinHttpConnect", "WinHttpSendRequest", "InternetOpenW",
    "BCryptEncrypt", "CryptEncrypt", "LoadDriver", "NtLoadDriver", "ZwLoadDriver",
    "MiniDumpWriteDump", "SetWindowsHookExW", "CreateRemoteThread",
    "WriteProcessMemory", "AdjustTokenPrivileges", "SetFileCompletionNotificationModes",
    "GetSystemFirmwareTable", "CreateToolhelp32Snapshot", "WTSQuerySessionInformationW",
]

PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx0": "UPX", ".upx1": "UPX",
    "vmp0": "VMProtect", "vmp1": "VMProtect", "vmp2": "VMProtect",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".themida": "Themida", ".winlice": "Themida", ".enigma1": "Enigma",
    ".enigma2": "Enigma", ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".petite": "Petite", ".aspack": "ASPack", ".adata": "ASPack",
    ".nsp0": "NsPack", ".boom": "Themida/Boom", "pec1": "PECompact",
    ".packed": "packed?", "protect": "protect?",
    # 360 house style: .wow0/.wow1 carry original/custom-packed payload
    ".wow0": "360-wow", ".wow1": "360-wow",
    ".enigma": "Enigma", ".vmp": "VMProtect",
}


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def ts(value):
    if not value:
        return ""
    try:
        return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return f"raw:{value}"


VERSION_MAP = {
    "CompanyName": "company",
    "ProductName": "product",
    "FileVersion": "file_version",
    "ProductVersion": "product_version",
    "InternalName": "internal",
    "OriginalFilename": "orig_name",
    "FileDescription": "desc",
}


def version_fields(pe):
    """VS_VERSIONINFO -> rec-style keys (CompanyName -> company, ...)."""
    out = {}
    raw = {}
    if not hasattr(pe, "FileInfo"):
        return out
    for group in pe.FileInfo:
        for entry in (group if isinstance(group, list) else [group]):
            if getattr(entry, "Key", None) != b"StringFileInfo":
                continue
            for table in getattr(entry, "StringTable", []):
                for key, val in table.entries.items():
                    k = key.decode("latin1", "replace")
                    if k in VERSION_MAP:
                        raw[k] = val.decode("latin1", "replace").strip("\x00 ")
    for k, v in raw.items():
        out[VERSION_MAP[k]] = v
    return out


def scan(path, root):
    rec = {k: "" for k in (
        "rel", "ext", "arch", "subsystem", "is_dll", "size", "md5", "file_ts",
        "linker", "sections", "max_entropy", "packer", "ep_section",
        "import_dlls", "import_funcs", "tls", "dotnet", "signed_dir", "overlay",
        "pdb", "company", "product", "file_version", "internal", "orig_name",
        "desc", "interesting", "notes",
    )}
    size = os.path.getsize(path)
    rec["rel"] = os.path.relpath(path, root).replace("\\", "/")
    rec["ext"] = os.path.splitext(path)[1].lower()
    rec["size"] = size
    with open(path, "rb") as fh:
        rec["md5"] = hashlib.md5(fh.read()).hexdigest().upper()

    # Full parse (no fast_load): VS_VERSIONINFO / FileInfo is only populated by
    # the default full walk in pefile >= 2023.
    pe = pefile.PE(path)
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER
    machine = fh.Machine
    rec["arch"] = {0x14c: "x86", 0x8664: "x64", 0x1c0: "arm", 0xaa64: "arm64", 0x200: "ia64"}.get(machine, hex(machine))
    rec["subsystem"] = {2: "GUI", 3: "CONSOLE", 1: "NATIVE"}.get(oh.Subsystem, str(oh.Subsystem))
    rec["is_dll"] = "1" if fh.Characteristics & 0x2000 else "0"
    rec["file_ts"] = ts(fh.TimeDateStamp)
    linker_major = getattr(oh, "MajorLinkerVersion", None)
    if linker_major:
        rec["linker"] = f"{linker_major}.{getattr(oh, 'MinorLinkerVersion', 0)}"

    ep = oh.AddressOfEntryPoint
    secs = []
    max_ent = 0.0
    ent_by_name = {}
    declared = set()
    packers = set()
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin1", "replace")
        declared.add(name.lower())
        data = s.get_data() or b""
        e = entropy(data)
        ent_by_name[name] = e
        max_ent = max(max_ent, e)
        secs.append(f"{name}({e:.2f})")
        if name.lower() in PACKER_SECTIONS:
            packers.add(PACKER_SECTIONS[name.lower()])
    rec["sections"] = " ".join(secs)
    rec["max_entropy"] = f"{max_ent:.2f}"
    rec["packer"] = ",".join(sorted(packers))

    ep_sec = ""
    for s in pe.sections:
        if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            ep_sec = s.Name.rstrip(b"\x00").decode("latin1", "replace")
            break
    rec["ep_section"] = ep_sec

    imports = []
    funcs = 0
    hits = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports.append(entry.dll.decode("latin1", "replace"))
            for imp in entry.imports:
                funcs += 1
                if imp.name:
                    nm = imp.name.decode("latin1", "replace")
                    if nm in INTEREST:
                        hits.append(nm)
    rec["import_dlls"] = len(imports)
    rec["import_funcs"] = funcs
    rec["interesting"] = ",".join(sorted(set(hits)))
    rec["tls"] = "1" if hasattr(pe, "DIRECTORY_ENTRY_TLS") else "0"
    rec["dotnet"] = "1" if hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR") else "0"
    # DIRECTOR[4] (Security) holds a *file offset*, not an RVA; pefile does not
    # always materialize DIRECTORY_ENTRY_SECURITY, so read the raw directory.
    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    if sec_dir.VirtualAddress and sec_dir.Size:
        rec["signed_dir"] = f"{sec_dir.Size}B@{hex(sec_dir.VirtualAddress)}"

    if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
        for d in pe.DIRECTORY_ENTRY_DEBUG:
            try:
                if getattr(d.entry, "PdbFileName", None):
                    rec["pdb"] = d.entry.PdbFileName.rstrip(b"\x00").decode("latin1", "replace")
                    break
            except Exception:
                continue

    # overlay = bytes after the last raw section (how the installer payload was found)
    raw_end = 0
    for s in pe.sections:
        raw_end = max(raw_end, s.PointerToRawData + s.SizeOfRawData)
    if raw_end and size > raw_end:
        rec["overlay"] = size - raw_end

    notes = []
    if funcs == 0:
        notes.append("NO_IMPORTS")
    if max_ent > 7.2:
        notes.append("HIGH_ENTROPY")
    if rec["ep_section"] and rec["ep_section"].lower() not in (".text", "code", ".itext"):
        notes.append("EP_OUTSIDE_TEXT")
    if rec["signed_dir"]:
        notes.append("SIGNED")
    rec["notes"] = "|".join(notes)

    rec.update(version_fields(pe))
    pe.close()
    return rec


def main():
    root = sys.argv[1]
    out = sys.argv[2]
    cols = ["rel", "ext", "arch", "subsystem", "is_dll", "size", "file_ts", "linker",
            "sections", "max_entropy", "packer", "ep_section", "import_dlls", "import_funcs",
            "tls", "dotnet", "signed_dir", "overlay", "notes", "pdb", "company", "product",
            "file_version", "internal", "orig_name", "desc", "interesting", "md5"]
    rows = []
    errors = []
    for base, _dirs, files in os.walk(root):
        for name in files:
            if os.path.splitext(name)[1].lower() not in PE_EXT:
                continue
            path = os.path.join(base, name)
            try:
                rows.append(scan(path, root))
            except Exception as exc:  # noqa: BLE001 - report and continue
                errors.append(f"{os.path.relpath(path, root)}\t{type(exc).__name__}: {exc}")
    rows.sort(key=lambda r: (r["ext"], r["rel"]))
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\t".join(cols) + "\n")
        for r in rows:
            fh.write("\t".join(str(r[c]).replace("\t", " ") for c in cols) + "\n")
    print(f"scanned={len(rows)} errors={len(errors)} -> {out}")
    for line in errors[:20]:
        print("  ERR", line)


if __name__ == "__main__":
    main()
