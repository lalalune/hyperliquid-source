#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-counted-ptr-dispose-94/verify.py \\
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. This script checks semantic records only: the target
digest, the dispose/guard carve ranges and SHAs, the int3 padding,
the branch/call targets re-derived from raw encodings, the GOT
guard and vtable relocations, the FDE records, the caller censuses
(byte-level scan of .text for direct calls), and the packet
manifest hashes. It never lists instruction mnemonics: the raw
disassembly lives in window.objdump.txt and guard.objdump.txt, and
the byte content of those excerpts is checked against the binary
by the independent checker in tools/foundation_counted_ptr_dispose.py.
"""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    "README.md", "export_excerpts.py", "frames.txt",
    "guard.objdump.txt", "records.json", "relocations.txt",
    "verify.py", "window.objdump.txt",
})


class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping and RELA sections."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", data, 0x36)
        (self.e_shoff,) = struct.unpack_from("<Q", data, 0x28)
        (self.e_shentsize, self.e_shnum) = struct.unpack_from("<HH", data, 0x3A)
        (self.e_shstrndx,) = struct.unpack_from("<H", data, 0x3E)
        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, _flags, p_offset, p_vaddr, _paddr,
             p_filesz, _memsz, _align) = struct.unpack_from(
                "<IIQQQQQQ", data, off)
            if p_type == 1:
                self.loads.append((p_vaddr, p_offset, p_filesz))
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            (name, sh_type, _flags, _addr, sh_offset,
             sh_size, _link, _info, _align,
             _entsize) = struct.unpack_from("<IIQQQQIIQQ", data, off)
            self.sections.append((name, sh_type, sh_offset, sh_size))
        shstr_off = self.sections[self.e_shstrndx][2]
        self.names = {}
        for i, (name, _t, _o, _s) in enumerate(self.sections):
            end = data.index(b"\x00", shstr_off + name)
            self.names[i] = data[shstr_off + name:end].decode()

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x not in any PT_LOAD segment" % va)

    def read(self, va, size):
        return self.data[self.va_to_offset(va):self.va_to_offset(va) + size]

    def sha(self, va, size):
        return hashlib.sha256(self.read(va, size)).hexdigest()

    def relocations(self):
        out = {}
        for _name, sh_type, sh_offset, sh_size in self.sections:
            if sh_type != 4:  # SHT_RELA
                continue
            for j in range(sh_size // 24):
                off = sh_offset + j * 24
                (r_offset, r_info, r_addend) = struct.unpack_from(
                    "<QQq", self.data, off)
                out[r_offset] = (r_info & 0xFFFFFFFF, r_addend)

        return out

    def text_scan_calls(self, target):
        text_sec = None
        for i, (_name, _t, sh_offset, sh_size) in enumerate(self.sections):
            if self.names.get(i) == ".text":
                text_sec = (sh_offset, sh_size)
                break
        if text_sec is None:
            raise ValueError("no .text section")
        off, size = text_sec
        blob = self.data[off:off + size]
        base_va = None
        for vaddr, poff, filesz in self.loads:
            if poff <= off < poff + filesz:
                base_va = vaddr + (off - poff)
                break
        if base_va is None:
            raise ValueError(".text not in any PT_LOAD segment")
        hits = []
        for j in range(len(blob) - 5):
            if blob[j] == 0xE8:
                (rel,) = struct.unpack_from("<i", blob, j + 1)
                site = base_va + j
                if site + 5 + rel == target:
                    hits.append(site)
        return hits


def branch_target(elf, site):
    """Resolve a conditional branch at site to its target."""
    b = elf.read(site, 6)
    if b[0] == 0x0F and b[1] in (0x84, 0x85):
        (rel,) = struct.unpack_from("<i", b, 2)
        return site + 6 + rel
    if b[0] in (0x74, 0x75):
        rel = b[1] if b[1] < 0x80 else b[1] - 0x100
        return site + 2 + rel
    raise ValueError("not a conditional branch at %#x" % site)


def rip_target(elf, site):
    """Resolve a 48 3b rip-relative compare at site to its target."""
    b = elf.read(site, 7)
    if b[0] != 0x48 or b[1] != 0x3B or (b[2] & 0xC7) != 0x05:
        raise ValueError("not a rip-relative cmp at %#x" % site)
    (rel,) = struct.unpack_from("<i", b, 3)
    return site + 7 + rel


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=DEFAULT_BINARY)
    args = parser.parse_args(argv)
    errors = []
    with open(os.path.join(PACKET_DIR, "records.json")) as f:
        records = json.load(f)
    try:
        with open(args.binary, "rb") as f:
            data = f.read()
    except OSError as e:
        print("cannot read binary: %s" % e)
        return 1
    if hashlib.sha256(data).hexdigest() != records["target_sha256"]:
        errors.append("target digest mismatch")
        print("\n".join(errors))
        return 1
    elf = Elf(data)
    for key in ("dispose", "guard"):
        rec = records[key]
        start = int(rec["start_va"], 16)
        end = int(rec["end_va_exclusive"], 16)
        if elf.sha(start, end - start) != rec["sha256"]:
            errors.append("%s carve SHA mismatch" % key)
        if end - start != rec["bytes"]:
            errors.append("%s byte count mismatch" % key)
    guard = records["guard"]
    pad = elf.read(int(guard["end_va_exclusive"], 16),
                   guard["padding_bytes"])
    if pad != b"\xcc" * guard["padding_bytes"]:
        errors.append("guard padding is not int3")
    if elf.read(int(records["dispose"]["end_va_exclusive"], 16),
                 0) != b"":
        errors.append("unreachable")
    # Branch targets re-derived from raw encodings.
    for site, want in records["branches"].items():
        try:
            got = branch_target(elf, int(site, 16))
        except ValueError as e:
            errors.append(str(e))
            continue
        if got != int(want, 16):
            errors.append("branch %s -> %#x, want %s" % (site, got, want))
    # GOT compare targets re-derived from raw encodings.
    for site, want in records["got_compares"].items():
        try:
            got = rip_target(elf, int(site, 16))
        except ValueError as e:
            errors.append(str(e))
            continue
        if got != int(want, 16):
            errors.append("GOT compare %s -> %#x, want %s"
                          % (site, got, want))
    # Relocations.
    relocs = elf.relocations()
    got = relocs.get(int(records["got"]["slot"], 16))
    if got != (8, int(records["got"]["addend"], 16)):
        errors.append("GOT guard relocation mismatch: %r" % (got,))
    for slot, want in records["vtable"]["slots"].items():
        entry = relocs.get(int(slot, 16))
        if entry is None or entry[1] != int(want, 16):
            errors.append("vtable slot %s mismatch: %r" % (slot, entry))
    # FDE records via readelf.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames", args.binary],
        capture_output=True, text=True)
    for key in ("dispose", "guard"):
        rec = records[key]
        want = "pc=%s..%s" % (rec["start_va"].replace("0x", "000000000"),
                              rec["end_va_exclusive"].replace(
                                  "0x", "000000000"))
        # readelf prints 16-hex-digit VAs; normalize both sides.
        found = False
        for line in frames.stdout.splitlines():
            if "FDE" in line and "pc=" in line:
                m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
                if m and int(m.group(1), 16) == int(rec["start_va"], 16) \
                        and int(m.group(2), 16) == int(
                            rec["end_va_exclusive"], 16):
                    parts = line.split()
                    if int(parts[0], 16) != int(
                            rec["fde_section_offset"], 16) or \
                            int(parts[1], 16) != rec["fde_length"] or \
                            "cie=%s" % rec["fde_cie_offset"].replace(
                                "0x", "") not in line:
                        errors.append("%s FDE fields mismatch: %s"
                                      % (key, line.strip()))
                    found = True
        if not found:
            errors.append("%s FDE record not found" % key)
    # Caller censuses.
    for key, target in (("dispose_direct_callers",
                         records["dispose"]["start_va"]),
                        ("guard_direct_callers",
                         records["guard"]["start_va"])):
        want = [int(x, 16) for x in records["censuses"][key]]
        got_sites = elf.text_scan_calls(int(target, 16))
        if got_sites != want:
            errors.append("%s census mismatch: got %s want %s"
                          % (key, [hex(x) for x in got_sites], want))
    # Manifest hashes. The manifest pins every packet file except
    # itself, so the listed set must equal the pinned packet files and
    # the files actually present (the admission check the RE-012/RE-009
    # packet verifiers spell out). Hashing only the listed rows admits
    # an unlisted payload, a duplicated row, a symlinked entry, or an
    # evidence file deleted together with its row.
    manifest = os.path.join(PACKET_DIR, "MANIFEST.sha256")
    listed = {}
    if not os.path.exists(manifest):
        errors.append("MANIFEST.sha256 missing")
        listed = None
    else:
        try:
            with open(manifest) as f:
                for line in f:
                    if not line.strip():
                        continue
                    parts = line.split()
                    if len(parts) != 2:
                        errors.append(
                            "malformed manifest line: %r" % line.strip())
                        continue
                    digest, name = parts
                    if name in listed:
                        errors.append("manifest lists %s twice" % name)
                        continue
                    listed[name] = digest
        except OSError as exc:
            errors.append("cannot verify MANIFEST: %s" % exc)
            listed = None
    if listed is not None:
        present = set()
        for entry in sorted(os.listdir(PACKET_DIR)):
            path = os.path.join(PACKET_DIR, entry)
            if os.path.islink(path):
                errors.append("packet entry is a symlink: %s" % entry)
            elif os.path.isdir(path):
                if entry != "__pycache__" or not all(
                        name.endswith(".pyc")
                        and not os.path.islink(os.path.join(path, name))
                        for name in os.listdir(path)):
                    errors.append(
                        "unexpected directory in packet: %s" % entry)
            else:
                present.add(entry)
        present.discard("MANIFEST.sha256")
        if set(listed) != PACKET_FILES:
            errors.append(
                "manifest file set differs from the pinned packet "
                "files: missing rows %s, unexpected rows %s"
                % (sorted(PACKET_FILES - set(listed)),
                   sorted(set(listed) - PACKET_FILES)))
        if set(listed) != present:
            errors.append(
                "manifest file set differs from packet contents: "
                "unlisted %s, missing %s"
                % (sorted(present - set(listed)),
                   sorted(set(listed) - present)))
        for name, digest in sorted(listed.items()):
            if name not in present:
                continue
            try:
                with open(os.path.join(PACKET_DIR, name), "rb") as pf:
                    actual = hashlib.sha256(pf.read()).hexdigest()
            except OSError as exc:
                errors.append("cannot verify MANIFEST: %s" % exc)
                continue
            if actual != digest:
                errors.append("MANIFEST mismatch for %s" % name)
    if errors:
        print("FAILED")
        for e in errors:
            print(" - %s" % e)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
