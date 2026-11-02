#!/usr/bin/env python3
"""Verify the semantic records in records.json against a node #94 binary.

Stdlib only. Run from the repository root:

    python3 research/work-items/RE-001-recursive-destructor-94/verify.py \
        --binary work/hl-node-94.bin

``--binary`` defaults to artifacts/node/94/hl-node; pass the
digest-verified work copy on checkouts where that path is still an
LFS pointer. This script checks semantic records only: the target
digest, the function carve range and SHA, the int3 padding, the
branch/call targets re-derived from raw encodings, the delete PLT
stub with its GOT relocation, the caller census, the FDE records,
and the packet manifest hashes. It never lists instruction
mnemonics: the raw disassembly lives in window.objdump.txt,
callers.objdump.txt and plt.objdump.txt, and the byte content of
those excerpts is checked against the binary by the independent
checker in tools/foundation_recursive_destructor.py.
"""

import argparse
import hashlib
import json
import os
import struct
import sys

DEFAULT_BINARY = os.path.join("artifacts", "node", "94", "hl-node")
PACKET_DIR = os.path.dirname(os.path.abspath(__file__))

# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    "README.md", "callers.objdump.txt", "frames.txt", "plt.objdump.txt",
    "records.json", "verify.py", "window.objdump.txt",
})

FUNC_START = 0x514B690
FUNC_END = 0x514B6C1
FUNC_NEXT_FDE = 0x514B6D0
DELETE_PLT = 0x5660440
DELETE_GOT = 0x5778F48


class Elf:
    """Minimal ELF64 reader: PT_LOAD mapping and section lookup."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_shoff,) = struct.unpack_from("<Q", data, 0x28)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", data, 0x36)
        (self.e_shentsize, self.e_shnum) = struct.unpack_from("<HH", data, 0x3A)
        (self.e_shstrndx,) = struct.unpack_from("<H", data, 0x3E)
        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, _flags, p_offset, p_vaddr, _paddr,
             p_filesz, _memsz, _align) = struct.unpack_from("<IIQQQQQQ", data, off)
            if p_type == 1:  # PT_LOAD
                self.loads.append((p_vaddr, p_offset, p_filesz))
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            self.sections.append(struct.unpack_from("<IIQQQQIIQQ", data, off))
        shstr_off = self.sections[self.e_shstrndx][4]
        self.names = {}
        for idx, sec in enumerate(self.sections):
            end = data.index(b"\x00", shstr_off + sec[0])
            self.names[idx] = data[shstr_off + sec[0]:end].decode()

    def va_to_offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        raise ValueError("VA %#x is not in any PT_LOAD segment" % va)

    def read_at(self, va, length):
        off = self.va_to_offset(va)
        return self.data[off:off + length]

    def section(self, name):
        for idx, sec in enumerate(self.sections):
            if self.names.get(idx) == name:
                return sec
        raise ValueError("no %s section" % name)

    def text_range(self):
        sec = self.section(".text")
        return (sec[3], sec[4], sec[5])

    def plt_symbol(self, got_slot):
        """(reloc_type, symbol) for a GOT slot via .rela.plt/.dynsym/.dynstr."""
        rela = self.section(".rela.plt")
        dynsym = self.section(".dynsym")
        dynstr = self.section(".dynstr")
        symtab = self.data[dynsym[4]:dynsym[4] + dynsym[5]]
        strtab = self.data[dynstr[4]:dynstr[4] + dynstr[5]]
        for i in range(rela[5] // 24):
            r_offset, r_info, _add = struct.unpack_from(
                "<QQq", self.data, rela[4] + i * 24)
            if r_offset != got_slot:
                continue
            sym = r_info >> 32
            st_name, = struct.unpack_from("<I", symtab, sym * 24)
            end = strtab.index(b"\x00", st_name)
            return (r_info & 0xFFFFFFFF, strtab[st_name:end].decode())
        raise ValueError("no .rela.plt entry for %#x" % got_slot)


def e8_callers(text, text_addr, target):
    hits = []
    pos = 0
    while True:
        pos = text.find(b"\xe8", pos)
        if pos < 0 or pos + 5 > len(text):
            break
        (rel,) = struct.unpack_from("<i", text, pos + 1)
        if text_addr + pos + 5 + rel == target:
            hits.append(text_addr + pos)
        pos += 1
    return hits


def check(records_path, binary_path):
    failures = []

    def need(cond, msg):
        if not cond:
            failures.append(msg)

    with open(records_path) as f:
        rec = json.load(f)
    with open(binary_path, "rb") as f:
        data = f.read()
    elf = Elf(data)

    need(hashlib.sha256(data).hexdigest() == rec["target"]["sha256"],
         "target digest mismatch")
    need(len(data) == rec["target"]["size"], "target size mismatch")

    func = rec["function"]
    need(int(func["start_va"], 16) == FUNC_START, "function start mismatch")
    need(int(func["end_va_exclusive"], 16) == FUNC_END, "function end mismatch")
    body = elf.read_at(FUNC_START, FUNC_END - FUNC_START)
    need(len(body) == func["bytes"], "function byte count mismatch")
    need(hashlib.sha256(body).hexdigest() == func["sha256"],
         "function SHA mismatch")
    need(int(func["next_fde_start"], 16) == FUNC_NEXT_FDE,
         "next FDE start mismatch")
    need(all(b == 0xCC for b in elf.read_at(FUNC_END, FUNC_NEXT_FDE - FUNC_END)),
         "function padding is not all int3")
    need(FUNC_NEXT_FDE - FUNC_END == func["padding_bytes"],
         "padding byte count mismatch")

    for br in rec["branches"]:
        site = int(br["site"], 16)
        raw = elf.read_at(site, 2)
        (rel,) = struct.unpack_from("<b", raw, 1)
        need(site + 2 + rel == int(br["target"], 16),
             "branch target mismatch at %#x" % site)
    for call in rec["calls"]:
        site = int(call["site"], 16)
        raw = elf.read_at(site, 5)
        need(raw[0] == 0xE8, "call opcode mismatch at %#x" % site)
        (rel,) = struct.unpack_from("<i", raw, 1)
        need(site + 5 + rel == int(call["target"], 16),
             "call target mismatch at %#x" % site)

    plt = rec["delete_plt"]
    stub = elf.read_at(DELETE_PLT, 6)
    need(stub.hex() == plt["stub_bytes"], "delete PLT stub bytes mismatch")
    (disp,) = struct.unpack_from("<i", stub, 2)
    need(DELETE_PLT + 6 + disp == int(plt["got_slot"], 16),
         "delete PLT GOT slot mismatch")
    try:
        r_type, sym = elf.plt_symbol(DELETE_GOT)
    except ValueError as exc:
        failures.append(str(exc))
        r_type, sym = None, None
    need(r_type == 7, "delete GOT relocation is not R_X86_64_JUMP_SLOT")
    need(sym == plt["symbol"], "delete GOT symbol mismatch")
    need(elf.read_at(DELETE_GOT, 8).hex() == plt["got_slot_file_bytes"],
         "delete GOT slot file bytes mismatch")

    text_addr, text_off, text_size = elf.text_range()
    text = data[text_off:text_off + text_size]
    found = ["%#x" % a for a in e8_callers(text, text_addr, FUNC_START)]
    need(found == rec["callers_e8"], "caller census mismatch")
    need([a for a in found if a != "%#x" % 0x514B69D]
         == rec["callers_external"], "external caller census mismatch")

    with open(os.path.join(PACKET_DIR, "frames.txt")) as f:
        frames = f.read()
    need("pc=%016x..%016x" % (FUNC_START, FUNC_END) in frames,
         "function FDE missing")
    need("pc=%016x..%016x" % (FUNC_NEXT_FDE, 0x514B7B3) in frames,
         "next FDE missing")
    for fn in rec["caller_functions"]:
        rng = "pc=%016x..%016x" % (
            int(fn["enclosing_start"], 16), int(fn["enclosing_end"], 16))
        need(rng in frames, "caller FDE missing: %s" % rng)

    # The manifest pins every packet file except itself, so the listed
    # set must equal the pinned packet files and the files actually
    # present (the admission check the RE-012/RE-009 packet verifiers
    # spell out). Hashing only the listed rows admits an unlisted
    # payload, a duplicated row, a symlinked entry, or an evidence file
    # deleted together with its row.
    manifest = os.path.join(PACKET_DIR, "MANIFEST.sha256")
    if not os.path.exists(manifest):
        failures.append("MANIFEST.sha256 missing")
        return failures
    listed = {}
    with open(manifest) as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) != 2:
                failures.append("malformed manifest line: %r" % line.strip())
                continue
            digest, name = parts
            if name in listed:
                failures.append("manifest lists %s twice" % name)
                continue
            listed[name] = digest
    present = set()
    for entry in sorted(os.listdir(PACKET_DIR)):
        path = os.path.join(PACKET_DIR, entry)
        if os.path.islink(path):
            failures.append("packet entry is a symlink: %s" % entry)
        elif os.path.isdir(path):
            if entry != "__pycache__" or not all(
                    name.endswith(".pyc")
                    and not os.path.islink(os.path.join(path, name))
                    for name in os.listdir(path)):
                failures.append("unexpected directory in packet: %s" % entry)
        else:
            present.add(entry)
    present.discard("MANIFEST.sha256")
    if set(listed) != PACKET_FILES:
        failures.append(
            "manifest file set differs from the pinned packet files: "
            "missing rows %s, unexpected rows %s"
            % (sorted(PACKET_FILES - set(listed)),
               sorted(set(listed) - PACKET_FILES)))
    if set(listed) != present:
        failures.append(
            "manifest file set differs from packet contents: "
            "unlisted %s, missing %s"
            % (sorted(present - set(listed)),
               sorted(set(listed) - present)))
    for name, digest in sorted(listed.items()):
        if name not in present:
            continue
        with open(os.path.join(PACKET_DIR, name), "rb") as pf:
            need(hashlib.sha256(pf.read()).hexdigest() == digest,
                 "manifest hash mismatch: %s" % name)
    return failures


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--records",
                    default=os.path.join(PACKET_DIR, "records.json"))
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    args = ap.parse_args(argv)
    failures = check(args.records, args.binary)
    if failures:
        print("CHECK FAILED")
        for failure in failures:
            print(" -", failure)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
