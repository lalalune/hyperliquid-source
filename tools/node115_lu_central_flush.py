#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-central-flush.

Reads bytes only; never executes the node binary. Verifies:
- binary identity (size + SHA-256)
- shipped hex excerpts equal the binary bytes at their ranges
- strict mnemonic-line counts of the shipped objdump excerpts
- FDE entry bytes (endbr64) and main ret bytes for all four targets
- key instruction bytes: small C computation + trylock + counters,
  small unlock + memmove tail, large threshold gate + lock atomics,
  large lock + flag + conditional unlock, push-small core, push-large
  core + fallback, seg-drain call, census-site calls
- the whole-binary census for all four targets: exact direct E8 site
  lists, 0 E9 tail jumps, 0 rip-relative LEA sites, 0 RELATIVE .got
  slots (RELATIVE .got slots are zero-filled in the file, so the
  census goes through .rela.dyn addends, never file content)
- the RELATIVE relocation entry for the small per-class array base
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
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-central-flush"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

BIN_SIZE = 105896032
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

SMALL = 0x63EAD50
LARGE = 0x63EB870
PUSH_SMALL = 0x63612B0
PUSH_LARGE = 0x63BD640

EXCERPTS = [
    # (hex file, objdump file, start VA, end VA, strict count)
    ("small_lock.hex", "small_lock.objdump.txt", 0x63EAEF0, 0x63EAF7E, 33),
    ("large_gate.hex", "large_gate.objdump.txt", 0x63EB9D0, 0x63EBA48, 25),
    ("push_large.hex", "push_large.objdump.txt", 0x63BD640, 0x63BD687, 16),
    ("large_tail.hex", "large_tail.objdump.txt", 0x63EC019, 0x63EC068, 18),
]

# Prior packets' claimed FDE/excerpt ranges; this packet must not
# overlap them. (From #203's verifier plus #203's own exhibits.)
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
    (0x635C6D0, 0x635DE25),  # #203 slow-path FDE (covers its excerpts)
]

# Key instruction bytes: (VA, expected bytes, label)
KEY_BYTES = [
    (0x63EAD50, bytes.fromhex("f30f1efa"), "small endbr64"),
    (0x63EB870, bytes.fromhex("f30f1efa"), "large endbr64"),
    (0x63612B0, bytes.fromhex("f30f1efa"), "push-small endbr64"),
    (0x63BD640, bytes.fromhex("f30f1efa"), "push-large endbr64"),
    (0x63EB586, b"\xc3", "small main ret"),
    (0x63EC0AE, b"\xc3", "large main ret"),
    (0x6361303, b"\xc3", "push-small ret"),
    (0x63BD6A4, b"\xc3", "push-large ret"),
    (0x63EAEF3, bytes.fromhex("488d1dc6e71100"), "small seg-table lea"),
    (0x63EAF1C, bytes.fromhex("4c8d255d681200"), "small class-table lea"),
    (0x63EAF48, bytes.fromhex("498d7c2440"), "small mutex arg C+0x40"),
    (0x63EAF51, bytes.fromhex("e85a680000"), "small trylock call"),
    (0x63EAF62, bytes.fromhex("498344243801"), "small C+0x38"),
    (0x63EAF73, bytes.fromhex("498344242801"), "small C+0x28"),
    (0x63EAF79, bytes.fromhex("4d894c2430"), "small C+0x30"),
    (0x63EB238, bytes.fromhex("4d015c2478"), "small C+0x78"),
    (0x63EB23D, bytes.fromhex("4d299c2488000000"), "small C+0x88"),
    (0x63EB245, bytes.fromhex("41c644246800"), "small flag clear"),
    (0x63EB24F, bytes.fromhex("e81c590000"), "small unlock call"),
    (0x63EB538, bytes.fromhex("e833550000"), "small memmove call"),
    (0x63EB9F4, bytes.fromhex("488d35a1dc1100"), "large threshold lea"),
    (0x63EB9FD, bytes.fromhex("41398050340100"), "large seg+0x13450 cmp"),
    (0x63EBA30, bytes.fromhex("f0480111"), "large lock add"),
    (0x63EBA3B, bytes.fromhex("f049830101"), "large lock addq"),
    (0x63EBA40, bytes.fromhex("49c7430800000000"), "large slot zero"),
    (0x63EBEA8, bytes.fromhex("498db868290000"), "large mutex arg seg+0x2968"),
    (0x63EBEBA, bytes.fromhex("e8f1580000"), "large trylock call"),
    (0x63EBECB, bytes.fromhex("4983806029000001"), "large C+0x38"),
    (0x63EBEE0, bytes.fromhex("4983805029000001"), "large C+0x28"),
    (0x63EBEE8, bytes.fromhex("4d89a058290000"), "large C+0x30"),
    (0x63EC0BC, bytes.fromhex("41c6809029000001"), "large flag set"),
    (0x63EBC6A, bytes.fromhex("e8014f0000"), "large unlock call"),
    (0x63EC055, bytes.fromhex("e8164a0000"), "large memmove call"),
    (0x63612B8, bytes.fromhex("4881c698290000"), "push-small seg+0x2998"),
    (0x63612E1, bytes.fromhex("e85af00500"), "push-small inner call"),
    (0x636130E, bytes.fromhex("e8fdf2ffff"), "push-small fallback call"),
    (0x63BD650, bytes.fromhex("488d0d69c01400"), "push-large seg-table lea"),
    (0x63BD67B, bytes.fromhex("488db598290000"), "push-large seg+0x2998"),
    (0x63BD682, bytes.fromhex("e8b92c0000"), "push-large inner call"),
    (0x63BD6AE, bytes.fromhex("e85d2ffaff"), "push-large fallback call"),
    (0x6363435, bytes.fromhex("e836840800"), "seg-drain large call"),
    (0x635D3C0, bytes.fromhex("e88bd90800"), "small second slow-FDE call"),
    (0x635C111, bytes.fromhex("e85af70800"), "large slow-FDE call"),
    (0x635CE27, bytes.fromhex("e824df0800"), "small slow-FDE call"),
    (0x635C97E, bytes.fromhex("e8edee0800"), "large slow-FDE call"),
    (0x63EBD6C, bytes.fromhex("e8cf18fdff"), "push-large flush call"),
]

CENSUS = {
    SMALL: [0x6351525, 0x6351599, 0x635210B, 0x635219B, 0x635B3A6,
            0x635CE27, 0x635D3C0, 0x6365FE1, 0x63BDD75, 0x63EB83B,
            0x63EC643, 0x63EC957],
    LARGE: [0x635120D, 0x63521F8, 0x63526F6, 0x6352BE4, 0x635C111,
            0x635C97E, 0x635CC2D, 0x6363435, 0x636675E, 0x63BE137,
            0x63EC337, 0x63EC4A7, 0x63EC668, 0x63ECAE0],
    PUSH_SMALL: [0x63EA7F3, 0x63EA81D, 0x63EA847, 0x63EA885, 0x63EA8AA,
                 0x63EA8CE, 0x63EA8F2, 0x63EB3F1, 0x63EB41C, 0x63EB446,
                 0x63EB472, 0x63EB493, 0x63EB4B4, 0x63EB4D5],
    PUSH_LARGE: [0x63EA536, 0x63EA569, 0x63EA59A, 0x63EA5CA, 0x63EA600,
                 0x63EA632, 0x63EA65D, 0x63EBCBF, 0x63EBCF4, 0x63EBD2C,
                 0x63EBD6C, 0x63EBD94, 0x63EBDB8, 0x63EBDDF],
}

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def text_bytes(data, va, n):
    return data[va - 0x1000:va - 0x1000 + n]


def sections(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    raw = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _f, _a, sh_off, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off)
        raw.append((sh_name, sh_type, sh_off, sh_size))
    str_off = raw[e_shstrndx][2]
    out = {}
    for sh_name, sh_type, sh_off, sh_size in raw:
        end = data.index(b"\x00", str_off + sh_name)
        out[data[str_off + sh_name:end].decode()] = (sh_type, sh_off, sh_size)
    return out


def main():
    data = BIN.read_bytes()
    if len(data) != BIN_SIZE:
        fail(f"binary size {len(data)} != {BIN_SIZE}")
    if hashlib.sha256(data).hexdigest() != BIN_SHA256:
        fail("binary SHA-256 mismatch")
    secs = sections(data)
    text_off, text_size = secs[".text"][1], secs[".text"][2]
    # .text VA: file offset + 0x1000 per the coordinate system.
    text_va = text_off + 0x1000
    tdata = data[text_off:text_off + text_size]

    for name, obj, start, end, want in EXCERPTS:
        raw = bytes.fromhex((PACKET / name).read_text().strip())
        if raw != text_bytes(data, start, end - start):
            fail(f"excerpt bytes mismatch: {name}")
        lines = (PACKET / obj).read_text().splitlines()
        count = sum(1 for ln in lines if STRICT_RE.match(ln))
        if count != want:
            fail(f"strict count {obj}: {count} != {want}")
        for s2, e2 in PRIOR_RANGES:
            if start < e2 and s2 < end:
                fail(f"excerpt {name} overlaps prior range {hex(s2)}")

    for va, want, label in KEY_BYTES:
        if text_bytes(data, va, len(want)) != want:
            fail(f"key bytes mismatch: {label} at {hex(va)}")

    # Whole-.text census: E8/E9 rel32 + REX LEA (rip-relative).
    for target, want_e8 in CENSUS.items():
        e8, e9, lea = [], [], []
        for i in range(len(tdata) - 7):
            op = tdata[i]
            if op in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", tdata, i + 1)[0]
                if text_va + i + 5 + rel == target:
                    (e8 if op == 0xE8 else e9).append(text_va + i)
            if 0x40 <= op <= 0x4F and tdata[i + 1] == 0x8D:
                modrm = tdata[i + 2]
                if (modrm >> 6) == 0 and (modrm & 7) == 5:
                    disp = struct.unpack_from("<i", tdata, i + 3)[0]
                    if text_va + i + 7 + disp == target:
                        lea.append(text_va + i)
        if e8 != want_e8:
            fail(f"census E8 mismatch for {hex(target)}: "
                 f"{[hex(x) for x in e8]}")
        if e9:
            fail(f"unexpected E9 sites for {hex(target)}")
        if lea:
            fail(f"unexpected LEA sites for {hex(target)}: "
                 f"{[hex(x) for x in lea]}")

    # .rela.dyn RELATIVE addends: no GOT slot points at a target,
    # and the small per-class array base resolves to 0x6711b40.
    rela_type, rela_off, rela_size = secs[".rela.dyn"]
    got = {}
    for j in range(rela_size // 24):
        r_off, r_info, r_add = struct.unpack_from(
            "<QQq", data, rela_off + j * 24)
        if r_info & 0xFFFFFFFF == 8:
            got[r_off] = r_add
    for target in CENSUS:
        hits = [k for k, v in got.items() if v == target]
        if hits:
            fail(f"unexpected GOT slots for {hex(target)}: {hits}")
    if got.get(0x64EE138) != 0x6711B40:
        fail("per-class array GOT slot 0x64ee138 addend mismatch")

    # MANIFEST hashes.
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    entries = []
    for line in manifest:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, rel = line.split("  ", 1)
        entries.append((digest, rel))
    if len(entries) != 13:
        fail(f"MANIFEST entry count {len(entries)} != 13")
    for digest, rel in entries:
        path = (PACKET / rel).resolve()
        if not path.is_file():
            fail(f"MANIFEST lists missing file: {rel}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            fail(f"MANIFEST digest mismatch: {rel}")

    print("verifier: all checks passed "
          f"(4 excerpts, {len(KEY_BYTES)} key-byte sites, "
          f"census {sum(len(v) for v in CENSUS.values())} E8 sites, "
          f"MANIFEST 13/13)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
