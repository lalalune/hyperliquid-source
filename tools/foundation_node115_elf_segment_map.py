#!/usr/bin/env python3
"""RE-002/RE-001 prerequisite: node #115 ELF load map and VA-to-file-offset translation.

Bounded question: for the pinned Linux x86-64 node #115 ELF, what is the exact
virtual-address (VA) to file-offset translation for each PT_LOAD program header
and for the .text section?

Why it is a prerequisite: an authenticated FDE window (RE-001) or any other
recorded target window can only be read from pinned bytes once the mapping from
the recorded VA to a file offset is established from the target ELF itself.
RE-002 needs the same map to describe the loaded image.

This checker reads artifacts/node/115/hl-node as bytes only. It never executes
or copies the target. It claims no first-party component bytes, no acceptance
gate and no upstream dependency code.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

SCHEMA = "node115-elf-load-map/v1"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_REL = "artifacts/node/115/hl-node"

PT_LOAD = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
EM_X86_64 = 62
SHT_NOBITS = 8
EHDR_SIZE = 64
PHDR_SIZE = 56
SHDR_SIZE = 64
NON_DERIVED_KEYS = ("schema", "question", "claims", "limitations", "notes")


class ElfFormatError(ValueError):
    """Bytes are not a well-formed 64-bit little-endian x86-64 ELF."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def parse_header(data):
    if len(data) < EHDR_SIZE:
        raise ElfFormatError("file shorter than a 64-bit ELF header")
    if data[:4] != b"\x7fELF":
        raise ElfFormatError("bad ELF magic")
    if data[4] != ELFCLASS64:
        raise ElfFormatError("not ELFCLASS64")
    if data[5] != ELFDATA2LSB:
        raise ElfFormatError("not ELFDATA2LSB")
    if data[6] != 1:
        raise ElfFormatError("unsupported e_ident version")
    raw = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    header = dict(zip(
        ("type", "machine", "version", "entry", "phoff", "shoff", "flags",
         "ehsize", "phentsize", "phnum", "shentsize", "shnum", "shstrndx"),
        raw))
    if header["machine"] != EM_X86_64:
        raise ElfFormatError("not EM_X86_64")
    if header["ehsize"] != EHDR_SIZE:
        raise ElfFormatError("unexpected e_ehsize: %d" % header["ehsize"])
    return header


def parse_program_headers(data, header):
    if header["phnum"] == 0:
        raise ElfFormatError("no program headers")
    if header["phentsize"] != PHDR_SIZE:
        raise ElfFormatError("unexpected e_phentsize: %d" % header["phentsize"])
    if header["phoff"] + header["phnum"] * PHDR_SIZE > len(data):
        raise ElfFormatError("program header table exceeds file")
    segments = []
    for index in range(header["phnum"]):
        raw = struct.unpack_from("<IIQQQQQQ", data, header["phoff"] + index * PHDR_SIZE)
        item = dict(zip(("type", "flags", "offset", "vaddr", "paddr",
                         "filesz", "memsz", "align"), raw))
        item["index"] = index
        if item["offset"] + item["filesz"] > len(data):
            raise ElfFormatError("segment %d exceeds file extent" % index)
        if item["type"] == PT_LOAD:
            if item["filesz"] > item["memsz"]:
                raise ElfFormatError("PT_LOAD %d has p_filesz above p_memsz" % index)
            if item["align"] and (item["align"] & (item["align"] - 1)):
                raise ElfFormatError("PT_LOAD %d p_align is not a power of two" % index)
        segments.append(item)
    return segments


def parse_sections(data, header):
    if header["shnum"] == 0:
        raise ElfFormatError("no section headers")
    if header["shentsize"] != SHDR_SIZE:
        raise ElfFormatError("unexpected e_shentsize: %d" % header["shentsize"])
    if header["shoff"] + header["shnum"] * SHDR_SIZE > len(data):
        raise ElfFormatError("section header table exceeds file")
    if header["shstrndx"] >= header["shnum"]:
        raise ElfFormatError("e_shstrndx out of range")
    sections = []
    for index in range(header["shnum"]):
        raw = struct.unpack_from("<IIQQQQIIQQ", data, header["shoff"] + index * SHDR_SIZE)
        sections.append(dict(zip(
            ("name", "type", "flags", "addr", "offset", "size", "link",
             "info", "addralign", "entsize"), raw)))
    strtab = sections[header["shstrndx"]]
    if strtab["offset"] + strtab["size"] > len(data):
        raise ElfFormatError("section name table exceeds file")
    names = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
    for item in sections:
        if item["name"] >= len(names):
            raise ElfFormatError("section name offset out of range")
        stop = names.find(b"\x00", item["name"])
        if stop < 0:
            raise ElfFormatError("unterminated section name")
        item["name"] = names[item["name"]:stop].decode("ascii", "replace")
        if item["type"] != SHT_NOBITS and item["offset"] + item["size"] > len(data):
            raise ElfFormatError("section %s exceeds file extent" % item["name"])
    return sections


def va_to_offset(loads, va):
    """Translate one VA through the PT_LOAD table, or raise."""
    for seg in loads:
        if seg["vaddr"] <= va < seg["vaddr"] + seg["filesz"]:
            return seg["offset"] + (va - seg["vaddr"])
    for seg in loads:
        if seg["vaddr"] <= va < seg["vaddr"] + seg["memsz"]:
            raise ElfFormatError(
                "VA 0x%x is in the zero-fill tail of PT_LOAD %d" % (va, seg["index"]))
    raise ElfFormatError("VA 0x%x is not inside any PT_LOAD" % va)


def derive_from_bytes(data):
    header = parse_header(data)
    segments = parse_program_headers(data, header)
    sections = parse_sections(data, header)
    loads = [s for s in segments if s["type"] == PT_LOAD]
    if not loads:
        raise ElfFormatError("no PT_LOAD segments")
    text = None
    for item in sections:
        if item["name"] == ".text":
            text = item
            break
    if text is None:
        raise ElfFormatError("no .text section")
    text_load = None
    for seg in loads:
        if seg["vaddr"] <= text["addr"] < seg["vaddr"] + seg["filesz"]:
            text_load = seg
            break
    if text_load is None:
        raise ElfFormatError(".text is not inside a file-backed PT_LOAD")
    return {
        "target": {"sha256": sha256_bytes(data), "size": len(data)},
        "entry": {"va": header["entry"],
                  "file_offset": va_to_offset(loads, header["entry"])},
        "loads": [{"index": s["index"], "vaddr": s["vaddr"],
                   "offset": s["offset"], "filesz": s["filesz"],
                   "memsz": s["memsz"], "flags": s["flags"],
                   "align": s["align"]} for s in loads],
        "text": {"addr": text["addr"],
                 "offset": va_to_offset(loads, text["addr"]),
                 "size": text["size"], "addralign": text["addralign"],
                 "load_index": text_load["index"]},
    }


def derive_map(path):
    return derive_from_bytes(Path(path).read_bytes())


def diff_values(recorded, derived, path="$"):
    out = []
    if isinstance(recorded, dict) and isinstance(derived, dict):
        for key in sorted(set(recorded) | set(derived)):
            if key not in recorded:
                out.append((path + "." + key, "<missing>", derived[key]))
            elif key not in derived:
                out.append((path + "." + key, recorded[key], "<not-derived>"))
            else:
                out.extend(diff_values(recorded[key], derived[key], path + "." + key))
    elif isinstance(recorded, list) and isinstance(derived, list):
        if len(recorded) != len(derived):
            out.append((path, "len %d" % len(recorded), "len %d" % len(derived)))
        else:
            for index, pair in enumerate(zip(recorded, derived)):
                out.extend(diff_values(pair[0], pair[1], "%s[%d]" % (path, index)))
    elif recorded != derived:
        out.append((path, recorded, derived))
    return out


def check(packet_dir, target_path):
    evidence_path = Path(packet_dir) / "evidence.json"
    if not evidence_path.is_file():
        raise AssertionError("missing packet file: %s" % evidence_path)
    recorded = json.loads(evidence_path.read_text(encoding="utf-8"))
    if recorded.get("schema") != SCHEMA:
        raise AssertionError("unexpected evidence schema: %r" % recorded.get("schema"))
    derived = derive_map(target_path)
    body = dict((k, v) for k, v in recorded.items() if k not in NON_DERIVED_KEYS)
    mismatches = diff_values(body, derived)
    if mismatches:
        shown = ["%s recorded=%r derived=%r" % item for item in mismatches[:12]]
        raise AssertionError("; ".join(shown))
    return derived


def main(argv):
    root = Path(__file__).resolve().parents[1]
    args = list(argv[1:])
    if args and args[0] == "--check":
        packet = Path(args[1])
        target = Path(args[2]) if len(args) > 2 else root / TARGET_REL
        derived = check(packet, target)
        print("check ok: %d PT_LOAD segments, .text at file offset 0x%x"
              % (len(derived["loads"]), derived["text"]["offset"]))
        return 0
    target = Path(args[0]) if args else root / TARGET_REL
    print(json.dumps(derive_map(target), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
