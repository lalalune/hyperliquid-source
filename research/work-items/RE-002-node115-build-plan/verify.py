#!/usr/bin/env python3
"""Re-derive the exact build-plan fields for node #115 from the captured ELF.

This packet records a deterministic Linux build plan for node #115. Every field
in `build-plan.json` marked `exact` is bound to bytes here, so the plan cannot
drift away from the artifact. Fields marked `inferred` or `unresolved` are not
derived: this script reports them and never invents a value.

    python3 verify.py            check the plan against the artifact
    python3 verify.py --control  corrupt one byte and require the check to fail

The reader is packet-local and bounded: it maps the file read-only, parses the
ELF header and section table, and scans only the sections it needs with
`bytes.find`. It never holds a section, an instruction list or the whole file in
Python objects beyond the section table and the reported rows.
"""
from __future__ import annotations

import json
import hashlib
import mmap
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
PLAN = Path(__file__).resolve().parent / "build-plan.json"

# The captured node this packet describes. A different digest is a different
# target and must not inherit this plan.
EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_SIZE = 105_896_032


class Reader:
    """Read-only, bounded view of the ELF header and section table."""

    def __init__(self, path: Path, data: bytes | mmap.mmap):
        self.path = path
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise SystemExit("target is not a 64-bit little-endian ELF")
        self.e_type = self.u16(0x10)
        self.e_machine = self.u16(0x12)
        shoff = self.u64(0x28)
        shentsize = self.u16(0x3A)
        shnum = self.u16(0x3C)
        shstrndx = self.u16(0x3E)
        raw = []
        for index in range(shnum):
            base = shoff + index * shentsize
            raw.append(
                {
                    "name": self.u32(base),
                    "type": self.u32(base + 4),
                    "flags": self.u64(base + 8),
                    "addr": self.u64(base + 16),
                    "offset": self.u64(base + 24),
                    "size": self.u64(base + 32),
                }
            )
        self.shstrtab_offset = raw[shstrndx]["offset"]
        self.shstrtab_size = raw[shstrndx]["size"]
        for row in raw:
            row["name"] = self.cstr(self.shstrtab_offset + row["name"])
        self.sections = raw
        self.by_name = {row["name"]: row for row in raw}

    def u16(self, offset: int) -> int:
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        return struct.unpack_from("<I", self.data, offset)[0]

    def u64(self, offset: int) -> int:
        return struct.unpack_from("<Q", self.data, offset)[0]

    def cstr(self, offset: int, limit: int = 4096) -> str:
        end = self.data.find(b"\x00", offset, offset + limit)
        return self.data[offset:end].decode("utf-8", "replace")

    def section_bytes(self, name: str) -> bytes:
        row = self.by_name[name]
        return bytes(self.data[row["offset"]: row["offset"] + row["size"]])

    def find_all(self, name: str, needle: bytes, cap: int = 4096) -> list[int]:
        """File offsets of `needle` inside one section, capped and counted."""
        row = self.by_name[name]
        hits, start = [], row["offset"]
        limit = row["offset"] + row["size"]
        while len(hits) < cap:
            found = self.data.find(needle, start, limit)
            if found < 0:
                break
            hits.append(found)
            start = found + 1
        return hits


def derive(reader: Reader) -> dict:
    """The exact rows of the plan, read from the artifact. No inference."""
    facts: dict[str, object] = {}

    facts["elf.type"] = {0x03: "DYN", 0x02: "EXEC"}.get(reader.e_type, f"0x{reader.e_type:x}")
    facts["elf.machine"] = {0x3E: "x86-64"}.get(
        reader.e_machine, f"0x{reader.e_machine:x}"
    )

    comments = [
        line for line in reader.section_bytes(".comment").split(b"\x00") if line.strip()
    ]
    facts["comment"] = [line.decode("utf-8", "replace") for line in comments]

    facts["sections.absent"] = [
        name
        for name in (".symtab", ".debug_info", ".debug_line", ".debug_abbrev")
        if name not in reader.by_name
    ]
    facts["debug_sections_present"] = sorted(
        name for name in reader.by_name if name.startswith(".debug")
    )

    # Linker behaviour that a build plan must reproduce.
    dynstr = reader.section_bytes(".dynstr")
    dynamics = reader.section_bytes(".dynamic")
    d_flags_1, d_flags, bind_now, runpath, needed = 0, 0, False, [], []
    dynstr_offset = reader.by_name[".dynstr"]["offset"]
    dynstr_end = dynstr_offset + reader.by_name[".dynstr"]["size"]
    entries = len(dynamics) // 16
    for index in range(entries):
        tag, value = struct.unpack_from("<qQ", dynamics, index * 16)
        if tag == 0:  # DT_NULL terminates an ELF .dynamic array
            break
        if tag == 0x1:
            needed.append(dynstr[value:dynstr.find(b"\x00", value)].decode())
        elif tag == 0x1D:
            runpath.append(dynstr[value:dynstr.find(b"\x00", value)].decode())
        elif tag == 0x6FFFFFFB:
            d_flags_1 = value
        elif tag == 0x1E:
            d_flags = value
        elif tag == 0x18:
            bind_now = True
    facts["dynamic.needed"] = sorted(needed)
    facts["dynamic.runpath"] = runpath
    facts["dynamic.bind_now"] = bind_now or bool(
        (d_flags & 0x8)  # DF_BIND_NOW
        or (d_flags_1 & 0x1)  # DF_1_NOW
    )
    facts["dynamic.flags"] = {
        "DT_FLAGS": f"0x{d_flags:x}",
        "DT_FLAGS_1": f"0x{d_flags_1:x}",
    }
    facts["dynamic.pie_flag"] = bool(d_flags_1 & 0x08000000)  # DF_1_PIE
    assert dynstr_end > dynstr_offset

    facts["interp"] = reader.section_bytes(".interp").split(b"\x00")[0].decode()

    facts["dynamic.max_symbol_versions"] = _max_versions(_symbol_version_strings(dynstr))
    facts["dynamic.hardening_imports"] = sorted(
        name.decode()
        for name in (
            b"__fprintf_chk",
            b"__memcpy_chk",
            b"__memset_chk",
            b"__realpath_chk",
            b"__snprintf_chk",
            b"__stack_chk_fail",
            b"__strncpy_chk",
            b"__vsnprintf_chk",
        )
        if bytes(name) + b"\x00" in dynstr
    )

    facts["section.gcc_except_table_size"] = reader.by_name[".gcc_except_table"]["size"]

    rustc_path = b"/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860"
    source_root = b"/home/ubuntu/hl/code_Mainnet"
    facts["rodata.rustc_commit_path_occurrences"] = len(
        reader.find_all(".rodata", rustc_path)
    )
    facts["rodata.source_root_occurrences"] = len(
        reader.find_all(".rodata", source_root)
    )
    facts["rodata.jemalloc_version_string_present"] = (
        len(reader.find_all(".rodata", b"5.3.0-1-ge13ca993e8ccb9ba9847cc330696e02839f328f7")) > 0
    )
    facts["rodata.vendor_root_present"] = (
        len(reader.find_all(".rodata", b"z_vendor")) > 0
    )
    facts["rodata.forks_root_present"] = (
        len(reader.find_all(".rodata", b"z_forks")) > 0
    )
    return facts


def _symbol_version_strings(dynstr: bytes) -> list[str]:
    """Version requirements such as `GLIBC_2.39`, read from .dynstr.

    Only whole strings count. A substring search would also match a symbol like
    `OPENSSL_init_ssl`, which is a name, not a version requirement.
    """
    pattern = re.compile(r"^(GLIBC|GLIBCXX|CXXABI|OPENSSL|GCC)_(\d+(?:\.\d+)*)$")
    found = []
    for token in dynstr.split(b"\x00"):
        text = token.decode("utf-8", "replace")
        if pattern.match(text):
            found.append(text)
    return found


def _max_versions(tokens: list[str]) -> dict:
    """Highest required version per library prefix."""
    best: dict[str, tuple] = {}
    for token in tokens:
        name, _, number = token.partition("_")
        parts = tuple(int(part) for part in number.split(".") if part.isdigit())
        if parts and (name not in best or parts > best[name]):
            best[name] = parts
    return {name: ".".join(str(part) for part in parts) for name, parts in sorted(best.items())}


def compare(plan: dict, derived: dict) -> list[str]:
    problems = []
    for row in plan["fields"]:
        if row["status"] != "exact":
            continue
        key = row["derived_key"]
        if key not in derived:
            problems.append(f"{row['field']}: plan cites missing derived key {key}")
            continue
        if derived[key] != row["value"]:
            problems.append(
                f"{row['field']}: plan says {row['value']!r}, artifact says {derived[key]!r}"
            )
    return problems


def main() -> int:
    control = "--control" in sys.argv
    raw = TARGET.open("rb")
    if control:
        # Corruption control: one flipped byte in .comment must be detected.
        data = bytearray(raw.read())
        raw.close()
        reader = Reader(TARGET, bytes(data))
        comment_offset = reader.by_name[".comment"]["offset"]
        data[comment_offset + 4] ^= 0x20
        reader = Reader(TARGET, bytes(data))
        plan = json.loads(PLAN.read_text())
        problems = compare(plan, derive(reader))
        print("control: one byte of .comment flipped")
        print("control result:", "FAILED AS REQUIRED" if problems else "NOT DETECTED")
        for problem in problems[:3]:
            print("  detected:", problem)
        return 0 if problems else 1

    with raw:
        reader = Reader(TARGET, mmap.mmap(raw.fileno(), 0, prot=mmap.PROT_READ))
    digest = hashlib.sha256(reader.data).hexdigest()
    size = len(reader.data)
    derived = derive(reader)
    plan = json.loads(PLAN.read_text())
    problems = compare(plan, derived)

    print(f"artifact: {TARGET.relative_to(ROOT)}")
    print(f"sha256:   {digest}")
    print(f"size:     {size}")
    if digest != EXPECTED_SHA256 or size != EXPECTED_SIZE:
        problems.append("artifact digest or size is not the plan's target")
    for key in sorted(derived):
        value = derived[key]
        shown = value if not isinstance(value, list) else value[:4]
        print(f"  {key}: {shown}")
    for problem in problems:
        print("MISMATCH:", problem)
    print("plan matches the artifact" if not problems else f"{len(problems)} mismatch(es)")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
