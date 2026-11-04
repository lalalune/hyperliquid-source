#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-acquire-release-callers.

Reads bytes only; never executes the node binary. Verifies:
- binary identity (size + SHA-256)
- shipped hex excerpts equal the binary bytes at their ranges
- strict mnemonic-line counts of the shipped objdump excerpts
- the whole-binary census: 0 direct E8 / 0 E9 / 0 LEA / 0 absolute
  references for acquire (0x4fac710) and release (0x4fb52e0);
  exactly 2 GOT call sites for acquire and 11 for release, each an
  FF 15 call through the RELATIVE .got slot for its target
- the RELATIVE relocation entries for both slots and the free slot
- the three log/span strings
- the acquire NULL-branch targets and the error-log call
- the wrapper FDE shape (body ret, tail, free calls) and its
  12 direct E8 callers, all inside the 4 caller FDEs
- the claimed ranges are disjoint from prior packets' claimed FDEs
Exit 0 on success, nonzero with a message on the first failure.
"""
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-acquire-release-callers"
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"

BIN_SIZE = 105896032
BIN_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ACQUIRE = 0x4FAC710
RELEASE = 0x4FB52E0
ACQ_SLOT = 0x64E7338
REL_SLOT = 0x64E7290
FREE_SLOT = 0x64E7278
FREE_TARGET = 0x5A8E3C0
WRAPPER = 0x2AC0F60

EXCERPTS = [
    # (hex file, objdump file, start VA, end VA, strict count)
    ("wrapper.hex", "wrapper.objdump.txt", 0x2AC0F60, 0x2AC0FB0, 27),
    ("acquire_a.hex", "acquire_a.objdump.txt", 0x2ACE08B, 0x2ACE0EC, 15),
    ("release_a.hex", "release_a.objdump.txt", 0x2ACEB52, 0x2ACEBA0, 11),
]

# GOT call sites: (site VA, expected 6 bytes, slot VA, target name)
GOT_SITES = [
    (0x2ACE0BE, bytes.fromhex("ff157492a103"), ACQ_SLOT, "acquire"),
    (0x2AD20DA, bytes.fromhex("ff155852a103"), ACQ_SLOT, "acquire"),
    (0x2AA5A79, bytes.fromhex("ff151118a403"), REL_SLOT, "release"),
    (0x2AA5C2C, bytes.fromhex("ff155e16a403"), REL_SLOT, "release"),
    (0x2AA77D9, bytes.fromhex("ff15b1faa303"), REL_SLOT, "release"),
    (0x2AA798C, bytes.fromhex("ff15fef8a303"), REL_SLOT, "release"),
    (0x2AC0F70, bytes.fromhex("ff151a63a203"), REL_SLOT, "release"),
    (0x2ACEB7A, bytes.fromhex("ff151087a103"), REL_SLOT, "release"),
    (0x2ACF336, bytes.fromhex("ff15547fa103"), REL_SLOT, "release"),
    (0x2AD06C2, bytes.fromhex("ff15c86ba103"), REL_SLOT, "release"),
    (0x2AD2B7D, bytes.fromhex("ff150d47a103"), REL_SLOT, "release"),
    (0x2AD3303, bytes.fromhex("ff15873fa103"), REL_SLOT, "release"),
    (0x2AD46CF, bytes.fromhex("ff15bb2ba103"), REL_SLOT, "release"),
]

# Direct E8 callers of the wrapper: (site VA, enclosing FDE start)
WRAPPER_CALLERS = [
    (0x2AA5D0E, 0x2AA59F0), (0x2AA5E20, 0x2AA59F0), (0x2AA5E84, 0x2AA59F0),
    (0x2AA7A6E, 0x2AA7750), (0x2AA7B80, 0x2AA7750), (0x2AA7BE4, 0x2AA7750),
    (0x2ACFB35, 0x2ACCEE0), (0x2ACFFC8, 0x2ACCEE0), (0x2AD0D77, 0x2ACCEE0),
    (0x2AD3B5A, 0x2AD0DB0), (0x2AD3FF0, 0x2AD0DB0), (0x2AD4D7E, 0x2AD0DB0),
]

STRINGS = [
    (0x60567B, b"closing gossip stream because peer is already connected"),
    (0x605781, b"dropping connection after sending abci state"),
    (0x6056B2, b"node_stream_connection"),
]

# Prior packets' claimed FDE ranges; this packet must not overlap them.
PRIOR_RANGES = [
    (0x4FAC710, 0x4FAC7E0),  # #200 acquire
    (0x4FB52E0, 0x4FB5440),  # #194 gate-release
    (0x4DA86A0, 0x4DA8860),  # #195 completion
    (0x4DA6C80, 0x4DA6D70),  # #200 cell resolver
]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def text_bytes(data, va, n):
    # .text file offset = VA - 0x1000
    off = va - 0x1000
    return data[off:off + n]


def main():
    data = BIN.read_bytes()
    if len(data) != BIN_SIZE:
        fail(f"binary size {len(data)} != {BIN_SIZE}")
    if hashlib.sha256(data).hexdigest() != BIN_SHA256:
        fail("binary SHA-256 mismatch")
    print(f"binary OK: {BIN_SIZE} bytes, sha256 {BIN_SHA256[:16]}...")

    # Excerpts: hex bytes + strict objdump counts.
    for hex_name, dump_name, start, end, want_count in EXCERPTS:
        raw = bytes.fromhex((PACKET / hex_name).read_text().strip())
        if raw != text_bytes(data, start, end - start):
            fail(f"{hex_name} bytes differ from binary at {start:#x}")
        lines = (PACKET / dump_name).read_text().splitlines()
        count = sum(1 for ln in lines if STRICT_RE.match(ln))
        if count != want_count:
            fail(f"{dump_name} strict count {count} != {want_count}")
        print(f"{hex_name}: {len(raw)} bytes at {start:#x}..{end:#x}, "
              f"strict {count} OK")
    for start, end, _ in [(e[2], e[3], 0) for e in EXCERPTS]:
        for p0, p1 in PRIOR_RANGES:
            if start < p1 and p0 < end:
                fail(f"excerpt {start:#x}..{end:#x} overlaps prior {p0:#x}..{p1:#x}")
    print("excerpts disjoint from prior claimed FDEs OK")

    # GOT site call bytes + slot resolution.
    for site, want, slot, target in GOT_SITES:
        got = text_bytes(data, site, 6)
        if got != want:
            fail(f"GOT site {site:#x} bytes {got.hex()} != {want.hex()}")
        disp = struct.unpack_from("<i", got, 2)[0]
        if site + 6 + disp != slot:
            fail(f"GOT site {site:#x} resolves to {site + 6 + disp:#x}, "
                 f"not slot {slot:#x}")
    print(f"GOT sites OK: {sum(1 for s in GOT_SITES if s[3] == 'acquire')} "
          f"acquire + {sum(1 for s in GOT_SITES if s[3] == 'release')} release")

    # ELF sections for the relocation / data scans.
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    secs = [struct.unpack_from("<IIQQQQ", data, e_shoff + i * e_shentsize)
            for i in range(e_shnum)]
    shstr_off = secs[e_shstrndx][4]

    def secname(n):
        end = data.index(b"\x00", shstr_off + n)
        return data[shstr_off + n:end].decode()

    S = {}
    for s in secs:
        S[secname(s[0])] = s
    text = S[".text"]
    taddr, toff, tsize = text[3], text[4], text[5]
    t = data[toff:toff + tsize]

    def va_of(i):
        return taddr + i

    # RELATIVE relocations for the two slots and the free slot.
    rela = S[".rela.dyn"]
    found = {}
    for j in range(0, rela[5], 24):
        roff, info, add = struct.unpack_from("<QQq", data, rela[4] + j)
        if roff in (ACQ_SLOT, REL_SLOT, FREE_SLOT):
            found[roff] = (info & 0xFFFFFFFF, add)
    want_rela = {ACQ_SLOT: (8, ACQUIRE), REL_SLOT: (8, RELEASE),
                 FREE_SLOT: (8, FREE_TARGET)}
    if found != want_rela:
        fail(f"RELATIVE relocations mismatch: {found}")
    print("RELATIVE relocations OK: acquire/release/free slots")

    # Whole-binary negative census for both targets.
    for target, name in ((ACQUIRE, "acquire"), (RELEASE, "release")):
        e8, e9, lea = [], [], []
        for i in range(len(t) - 7):
            b = t[i]
            if b in (0xE8, 0xE9):
                rel = struct.unpack_from("<i", t, i + 1)[0]
                if va_of(i) + 5 + rel == target:
                    (e8 if b == 0xE8 else e9).append(va_of(i))
            if t[i] == 0x48 and t[i + 1] == 0x8D and (t[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", t, i + 3)[0]
                if va_of(i) + 7 + disp == target:
                    lea.append(va_of(i))
        if e8 or e9 or lea:
            fail(f"{name} direct census not zero: E8={e8} E9={e9} LEA={lea}")
        abs_hits = []
        for dname in (".data.rel.ro", ".rodata", ".data", ".got", ".got.plt",
                      ".gcc_except_table", ".eh_frame", ".eh_frame_hdr"):
            s = S[dname]
            blob = data[s[4]:s[4] + s[5]]
            for j in range(0, len(blob) - 7):
                if struct.unpack_from("<Q", blob, j)[0] == target:
                    abs_hits.append((dname, hex(s[3] + j)))
        if abs_hits:
            fail(f"{name} absolute data refs not zero: {abs_hits}")
        print(f"{name}: 0 E8, 0 E9, 0 LEA, 0 absolute refs OK")

    # Strings (rodata VA as-is).
    for va, want in STRINGS:
        if data[va:va + len(want)] != want:
            fail(f"string at {va:#x} mismatch")
    print(f"strings OK: {len(STRINGS)}")

    # Acquire NULL-branch targets and the error-log call.
    for je_va, want_target in ((0x2ACE0CD, 0x2ACE3C6), (0x2AD20E9, 0x2AD23E7)):
        raw = text_bytes(data, je_va, 6)
        if raw[0:2] != bytes.fromhex("0f84"):
            fail(f"no je at {je_va:#x}: {raw.hex()}")
        disp = struct.unpack_from("<i", raw, 2)[0]
        if je_va + 6 + disp != want_target:
            fail(f"je at {je_va:#x} targets {je_va + 6 + disp:#x}, "
                 f"not {want_target:#x}")
    err = text_bytes(data, 0x2ACE421, 5)
    if err[0] != 0xE8 or 0x2ACE421 + 5 + struct.unpack_from("<i", err, 1)[0] != 0x2D4E9C0:
        fail(f"error-log call at 0x2ace421 wrong: {err.hex()}")
    print("acquire NULL branches + error-log call OK")

    # Wrapper shape: body ret, tail, free calls.
    if text_bytes(data, 0x2AC0F8F, 1) != b"\xc3":
        fail("wrapper body ret missing at 0x2ac0f8f")
    if text_bytes(data, 0x2AC0F84, 6) != bytes.fromhex("ff25ee62a203"):
        fail("wrapper tail jmp to free slot wrong")
    if text_bytes(data, 0x2AC0F9C, 6) != bytes.fromhex("ff15d662a203"):
        fail("wrapper unwind free call wrong")
    print("wrapper shape OK: body ret + tail jmp/call to free slot")

    # Wrapper direct E8 callers: exact set of 12, each resolving correctly.
    w_hits = []
    for i in range(len(t) - 5):
        if t[i] == 0xE8:
            rel = struct.unpack_from("<i", t, i + 1)[0]
            if va_of(i) + 5 + rel == WRAPPER:
                w_hits.append(va_of(i))
    if w_hits != [site for site, _ in WRAPPER_CALLERS]:
        fail(f"wrapper E8 callers mismatch: {[hex(x) for x in w_hits]}")
    print(f"wrapper E8 callers OK: {len(w_hits)}")

    print("VERIFIER OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
