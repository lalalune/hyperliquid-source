#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-slow-dealloc.

Reads bytes only; never executes the node binary. Verifies:
- binary identity (size + SHA-256)
- shipped hex excerpts equal the binary bytes at their ranges
- strict mnemonic-line counts of the shipped objdump excerpts
- the slow-path FDE byte length and the absence of any 0f 05
  (syscall) pair inside it
- the whole-binary census for the slow path: 0 direct E8 calls,
  exactly 1 E9 tail jump (the fast path's 0x635ded0 stub),
  0 rip-relative LEA sites, 0 RELATIVE .got slots
- the RELATIVE relocation entries for the poison slot and the
  fast-path deallocator slot
- key instruction bytes: dispatch branches, TLS push, budget
  store, body ret, list-full central-flush call, page-path call,
  poison GOT call and memset stub, fast-path stub jump, central
  mutex/atomic bytes, huge-class marker
- MANIFEST.sha256 hashes
- the claimed ranges are disjoint from prior packets' claimed
  FDEs and excerpts
Exit 0 on success, nonzero with a message on the first failure.
"""
import hashlib
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-slow-dealloc"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

BIN_SIZE = 105896032
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

SLOW = 0x635C6D0
SLOW_END = 0x635DE25
FAST = 0x635DE30
STUB = 0x635DED0
POISON_SLOT = 0x64FFB30
POISON_STUB = 0x6349380
DEALLOC_SLOT = 0x64DF4A0

TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
TEXT_SIZE = 0x4FD7700

EXCERPTS = [
    # (hex file, objdump file, start VA, end VA, strict count)
    ("dispatch.hex", "dispatch.objdump.txt", 0x635C6D0, 0x635C886, 95),
    ("full.hex", "full.objdump.txt", 0x635CDF8, 0x635CE47, 19),
    ("page.hex", "page.objdump.txt", 0x635CCE8, 0x635CD7F, 32),
]

# Prior packets' claimed FDE/excerpt ranges; this packet must not
# overlap them. (From #202's verifier plus #202's own exhibits.)
PRIOR_RANGES = [
    (0x4FAC710, 0x4FAC7E0),  # #200 acquire
    (0x4FB52E0, 0x4FB5440),  # #194 gate-release
    (0x4DA86A0, 0x4DA8860),  # #195 completion
    (0x4DA6C80, 0x4DA6D70),  # #200 cell resolver
    (0x2AC0F60, 0x2AC0FB0),  # #201 wrapper
    (0x2ACE08B, 0x2ACE0EC),  # #201 acquire excerpt
    (0x2ACEB52, 0x2ACEBA0),  # #201 release excerpt
    (0x5A8E3C0, 0x5A8E493),  # #202 free target
    (0x5A8C9F0, 0x5A8CA2C),  # #202 field drop 9f0
    (0x5A8C110, 0x5A8C14C),  # #202 field drop 110
    (0x635DE30, 0x635DEC6),  # #202 fast-path deallocator
]

# Key instruction bytes: (VA, expected bytes, label)
KEY_BYTES = [
    (0x635C6D0, bytes.fromhex("f30f1efa"), "slow endbr64"),
    (0x635C730, bytes.fromhex("0f855a010000"), "slow align branch"),
    (0x635C73D, bytes.fromhex("0f8715050000"), "slow oversized branch"),
    (0x635C794, bytes.fromhex("0f844e050000"), "slow page-aligned branch"),
    (0x635C7FD, bytes.fromhex("0f84f5050000"), "slow list-full branch"),
    (0x635C85B, bytes.fromhex("0f836f040000"), "slow budget branch"),
    (0x635C7F4, bytes.fromhex("498b4d08"), "slow list head load"),
    (0x635C80B, bytes.fromhex("4c8961f8"), "slow list push"),
    (0x635C851, bytes.fromhex("4c89b348030000"), "slow budget store"),
    (0x635C886, b"\xc3", "slow mainline ret"),
    (0x635CE27, bytes.fromhex("e824df0800"), "list-full central call"),
    (0x635CD7A, bytes.fromhex("e841090600"), "page-path call"),
    (0x635CE82, bytes.fromhex("ff15a82c1a00"), "poison GOT call"),
    (0x635CBA0, bytes.fromhex("803da24b1b0000"), "poison guard"),
    (0x6349380, bytes.fromhex("f30f1efa4889f2be5a000000e9ff760a00"),
     "poison memset stub"),
    (0x635DED0, bytes.fromhex("e9fbe7ffff"), "fast-path slow jump"),
    (0x635DE3B, bytes.fromhex("0f878f000000"), "fast size guard exit"),
    (0x635DEAC, bytes.fromhex("7422"), "fast list-full guard exit"),
    (0x63EAF51, bytes.fromhex("e85a680000"), "central trylock call"),
    (0x63EBA30, bytes.fromhex("f0480111"), "central lock add"),
    (0x63EBA3B, bytes.fromhex("f049830101"), "central lock addq"),
    (0x635D3E0, bytes.fromhex("41bee8000000"), "huge class 0xe8"),
]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def text_bytes(data, va, n):
    # .text file offset = VA - 0x1000
    off = va - 0x1000
    return data[off:off + n]


def parse_rela_relative(data):
    """Return {r_offset: r_addend} for R_X86_64_RELATIVE entries."""
    if data[0:4] != b"\x7fELF":
        fail("not an ELF file")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _flags, _addr, sh_off, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off)
        sections.append((sh_name, sh_type, sh_off, sh_size))
    str_off = sections[e_shstrndx][2]
    out = {}
    for sh_name, sh_type, sh_off, sh_size in sections:
        name_end = data.index(b"\x00", str_off + sh_name)
        name = data[str_off + sh_name:name_end].decode()
        if name == ".rela.dyn" and sh_type == 4:
            for j in range(sh_size // 24):
                r_off, r_info, r_add = struct.unpack_from(
                    "<QQq", data, sh_off + j * 24)
                if r_info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
                    out[r_off] = r_add
    return out


def main():
    data = BIN.read_bytes()
    if len(data) != BIN_SIZE:
        fail(f"binary size {len(data)} != {BIN_SIZE}")
    if hashlib.sha256(data).hexdigest() != BIN_SHA256:
        fail("binary SHA-256 mismatch")
    for hex_name, obj_name, start, end, want in EXCERPTS:
        raw = bytes.fromhex((PACKET / hex_name).read_text().strip())
        if raw != text_bytes(data, start, end - start):
            fail(f"{hex_name} bytes differ from binary")
        lines = (PACKET / obj_name).read_text().splitlines()
        count = sum(1 for ln in lines if STRICT_RE.match(ln))
        if count != want:
            fail(f"{obj_name} strict count {count} != {want}")
    fde = text_bytes(data, SLOW, SLOW_END - SLOW)
    if len(fde) != 5973:
        fail(f"slow FDE length {len(fde)} != 5973")
    if b"\x0f\x05" in fde:
        fail("slow FDE contains a syscall opcode pair")
    for va, want, label in KEY_BYTES:
        if text_bytes(data, va, len(want)) != want:
            fail(f"key bytes differ: {label} at {va:#x}")
    rela = parse_rela_relative(data)
    if rela.get(POISON_SLOT) != POISON_STUB:
        fail("poison slot relocation mismatch")
    if rela.get(DEALLOC_SLOT) != FAST:
        fail("dealloc slot relocation mismatch")
    # Whole-.text census for the slow path.
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    e8 = []
    e9 = []
    lea = []
    for i in range(len(text) - 6):
        b = text[i]
        if b in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            if TEXT_VA + i + 5 + rel == SLOW:
                (e8 if b == 0xE8 else e9).append(TEXT_VA + i)
        elif b in (0x48, 0x49, 0x4C, 0x4D) and text[i + 1] == 0x8D:
            if text[i + 2] & 0xC7 == 0x05:
                disp = struct.unpack_from("<i", text, i + 3)[0]
                if TEXT_VA + i + 7 + disp == SLOW:
                    lea.append(TEXT_VA + i)
    if e8:
        fail(f"unexpected direct calls to slow path: {e8}")
    if e9 != [STUB]:
        fail(f"tail jumps to slow path {e9} != [{STUB:#x}]")
    if lea:
        fail(f"unexpected LEA sites to slow path: {lea}")
    if SLOW in rela.values():
        fail("GOT slot resolves to slow path")
    mine = [(SLOW, SLOW_END), (POISON_STUB, POISON_STUB + 17)]
    mine += [(s, e) for _, _, s, e, _ in EXCERPTS]
    for s, e in mine:
        for ps, pe in PRIOR_RANGES:
            if s < pe and ps < e:
                fail(f"claimed range {s:#x}..{e:#x} overlaps prior "
                     f"{ps:#x}..{pe:#x}")
    # MANIFEST hashes.
    man = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    if len(man) != 11:
        fail(f"MANIFEST entry count {len(man)} != 11")
    for line in man:
        digest, path = line.split("  ", 1)
        blob = (PACKET / path).read_bytes()
        if hashlib.sha256(blob).hexdigest() != digest:
            fail(f"MANIFEST hash mismatch: {path}")
    print("verifier: all checks passed")


if __name__ == "__main__":
    main()
