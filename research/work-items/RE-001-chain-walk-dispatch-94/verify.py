#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-chain-walk-dispatch-94/verify.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. This script checks semantic records only: the target
digest, the walker/helper/sentinel/caller carve ranges and SHAs, the
int3 padding, the branch/call targets re-derived from raw encodings,
the GOT sentinel relocation, the PLT stubs with their GOT slots, the
FDE records, the caller censuses (full disassembly scan for direct
calls), and the packet manifest hashes. It never lists instruction
mnemonics: the raw disassembly lives in window.objdump.txt,
helper.objdump.txt, sentinel.objdump.txt, caller.objdump.txt and
plt.objdump.txt, and the byte content of those excerpts is checked
against the binary by the independent checker in
tools/foundation_chain_walk_dispatch.py.
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    "README.md", "caller.objdump.txt", "export_excerpts.py",
    "frames.txt", "helper.objdump.txt", "plt.objdump.txt",
    "records.json", "sentinel.objdump.txt", "verify.py",
    "window.objdump.txt",
})


class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping only."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", data, 0x36)
        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, _flags, p_offset, p_vaddr, _paddr,
             p_filesz, _memsz, _align) = struct.unpack_from(
                "<IIQQQQQQ", data, off)
            if p_type == 1:
                self.loads.append((p_vaddr, p_offset, p_filesz))

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x not in any PT_LOAD segment" % va)

    def offset_to_va(self, off):
        for vaddr, offset, filesz in self.loads:
            if offset <= off < offset + filesz:
                return vaddr + (off - offset)
        raise ValueError("file offset %#x not in any PT_LOAD segment" % off)

    def read(self, va, size):
        return self.data[self.va_to_offset(va):self.va_to_offset(va) + size]

    def sha(self, va, size):
        return hashlib.sha256(self.read(va, size)).hexdigest()


def branch_target(elf, site):
    """Resolve a conditional/unconditional branch at site to its target."""
    b = elf.read(site, 6)
    if b[0] == 0x0F and b[1] in (0x84, 0x85):
        (rel,) = struct.unpack_from("<i", b, 2)
        return site + 6 + rel
    if b[0] in (0x74, 0x75):
        rel = b[1] if b[1] < 0x80 else b[1] - 0x100
        return site + 2 + rel
    if b[0] == 0xE9:
        (rel,) = struct.unpack_from("<i", b, 1)
        return site + 5 + rel
    if b[0] == 0xEB:
        rel = b[1] if b[1] < 0x80 else b[1] - 0x100
        return site + 2 + rel
    raise ValueError("unsupported branch encoding at %#x: %s" % (site, b.hex()))


def call_target(elf, site):
    """Resolve a direct rel32 call at site to its target."""
    b = elf.read(site, 5)
    if b[0] != 0xE8:
        raise ValueError("not a direct call at %#x: %s" % (site, b.hex()))
    (rel,) = struct.unpack_from("<i", b, 1)
    return site + 5 + rel


def scan_direct_callers(elf, text_off, text_size, target):
    """All direct rel32 call sites in the .text file range to target."""
    found = []
    blob = elf.data[text_off:text_off + text_size]
    for i in range(text_size - 5):
        if blob[i] == 0xE8:
            (rel,) = struct.unpack_from("<i", blob, i + 1)
            site_va = elf.offset_to_va(text_off + i)
            if site_va + 5 + rel == target:
                found.append(site_va)
    return found


def text_range(binary):
    """File offset and size of .text (from section headers)."""
    out = subprocess.run(["readelf", "-S", binary], capture_output=True,
                         text=True, check=True).stdout
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if "] .text " in line:
            parts = line.split()
            # Addr and Off are on this line; Size is the first token
            # of the continuation line.
            off = int(parts[4], 16)
            size = int(lines[i + 1].split()[0], 16)
            return off, size
    raise ValueError(".text section not found")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    args = ap.parse_args(argv)
    with open(os.path.join(PACKET_DIR, "records.json")) as f:
        rec = json.load(f)
    errors = []
    with open(args.binary, "rb") as f:
        data = f.read()
    elf = Elf(data)
    tgt = rec["target"]
    if hashlib.sha256(data).hexdigest() != tgt["sha256"]:
        errors.append("target digest mismatch")
    if len(data) != tgt["size"]:
        errors.append("target size mismatch: %d" % len(data))

    # Carve ranges, SHAs, padding.
    for key, excerpt_end in (("walker", None), ("helper", None),
                             ("sentinel", None), ("caller", None)):
        fn = rec[key]
        start = int(fn["start_va"], 16)
        end = int(fn["end_va_exclusive"], 16)
        if elf.sha(start, end - start) != fn["sha256"]:
            errors.append("%s carve SHA mismatch" % key)
        if end - start != fn["bytes"]:
            errors.append("%s byte count mismatch" % key)
        nxt = int(fn["next_fde_start"], 16)
        pad = elf.read(end, nxt - end)
        if len(pad) != fn["padding_bytes"] or any(c != 0xCC for c in pad):
            errors.append("%s padding mismatch" % key)

    # Walker branches.
    for br in rec["walker_branches"]:
        site = int(br["site"], 16)
        try:
            if branch_target(elf, site) != int(br["target"], 16):
                errors.append("branch %s target mismatch" % br["site"])
        except ValueError as e:
            errors.append(str(e))

    # Direct calls.
    for call in rec["walker_calls"] + rec["sentinel_calls"] + rec["helper_calls"]:
        if "encoding" in call and call["encoding"] == "rel32":
            site = int(call["site"], 16)
            try:
                if call_target(elf, site) != int(call["target"], 16):
                    errors.append("call %s target mismatch" % call["site"])
            except ValueError as e:
                errors.append(str(e))
    for call in rec["walker_calls"]:
        if call["target"].startswith("indirect"):
            site = int(call["site"], 16)
            if elf.read(site, 6) != bytes.fromhex("ff9088000000"):
                errors.append("indirect vcall at %s mismatch" % call["site"])
    site = int(rec["sentinel_calls"][1]["site"], 16)
    if elf.read(site, 6) != bytes.fromhex("ff9088000000"):
        errors.append("sentinel indirect vcall mismatch")

    # Walker GOT compare: rip-relative operand must resolve to the slot.
    got_cmp = elf.read(0x514BA3F, 7)
    if got_cmp[:3] != bytes.fromhex("4c3b25"):
        errors.append("walker GOT compare encoding mismatch")
    else:
        (disp,) = struct.unpack_from("<i", got_cmp, 3)
        if 0x514BA3F + 7 + disp != int(rec["sentinel"]["got_slot"], 16):
            errors.append("walker GOT compare target mismatch")
    if elf.read(int(rec["sentinel"]["got_slot"], 16), 8) != bytes(8):
        errors.append("GOT sentinel slot file bytes are not zero")

    # Relocations via readelf.
    relocs = subprocess.run(["readelf", "-r", args.binary],
                            capture_output=True, text=True, check=True).stdout
    reloc_lines = relocs.splitlines()
    slot = rec["sentinel"]["got_slot"][2:]
    addend = rec["sentinel"]["got_relocation"]["addend"][2:]
    sentinel_line = [l for l in reloc_lines if l.startswith("00000" + slot)]
    if (len(sentinel_line) != 1 or "R_X86_64_RELATIVE" not in sentinel_line[0]
            or not sentinel_line[0].rstrip().endswith(addend)):
        errors.append("sentinel GOT relocation line not found")
    for plt in rec["plt"]:
        stub = int(plt["stub"], 16)
        b = elf.read(stub, 6)
        if b[0] != 0xFF or b[1] != 0x25:
            errors.append("PLT stub %s encoding mismatch" % plt["stub"])
            continue
        (disp,) = struct.unpack_from("<i", b, 2)
        if stub + 6 + disp != int(plt["got_slot"], 16):
            errors.append("PLT stub %s slot mismatch" % plt["stub"])
        slot_hex = plt["got_slot"][2:]
        plines = [l for l in reloc_lines if l.startswith("00000" + slot_hex)]
        match = plt.get("reloc_match", plt["symbol"].split("@")[0])
        if (len(plines) != 1 or "R_X86_64_JUMP_SLO" not in plines[0]
                or match not in plines[0]):
            errors.append("PLT relocation for %s not found" % plt["stub"])

    # FDE lines verbatim.
    frames = subprocess.run(["readelf", "--debug-dump=frames", args.binary],
                            capture_output=True, text=True, check=True).stdout
    with open(os.path.join(PACKET_DIR, "frames.txt")) as f:
        for line in f:
            line = line.strip()
            if line and line not in frames:
                errors.append("FDE line not in binary: %s" % line)

    # Censuses: full .text direct-call scan.
    toff, tsize = text_range(args.binary)
    cens = rec["censuses"]
    got = scan_direct_callers(elf, toff, tsize, int(rec["walker"]["start_va"], 16))
    if got != [int(x, 16) for x in cens["walker_direct_callers"]]:
        errors.append("walker census mismatch: %s" % [hex(x) for x in got])
    got = scan_direct_callers(elf, toff, tsize, int(rec["helper"]["start_va"], 16))
    if got != [int(x, 16) for x in cens["helper_direct_callers"]]:
        errors.append("helper census mismatch: %s" % [hex(x) for x in got])
    got = scan_direct_callers(elf, toff, tsize, int(rec["sentinel"]["start_va"], 16))
    if got != [int(x, 16) for x in cens["sentinel_direct_callers"]]:
        errors.append("sentinel census mismatch: %s" % [hex(x) for x in got])

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
            print(" - " + e)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
