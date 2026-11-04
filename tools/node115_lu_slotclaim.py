#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-slotclaim (node #115, static only).

Checks: binary SHA/size, 5 exhibits byte-exact, key-byte sites, key
calls, census (slot-claim 20 E8 / 0 E9 / 0 LEA / 0 GOT via .rela.dyn
addends), FDE bounds, MANIFEST 15/15.
Exits 0 only when every check passes.
"""
import hashlib
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-node115-lu-slotclaim")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032

EXHIBITS = {
    "sc_entry": (0x63ac480, 0x63ac4a1, 12),
    "sc_clear": (0x63ac4a1, 0x63ac4b6, 4),
    "sc_cmp": (0x63ac50f, 0x63ac520, 6),
    "sc_splice": (0x63ac538, 0x63ac557, 8),
    "sc_exit": (0x63ac937, 0x63ac948, 9),
}

# (va, expected bytes) key-byte sites, not excerpted
KEY_BYTES = {
    0x63acb20: bytes.fromhex("31c0"),        # NULL return: xor %eax,%eax
    0x63ac947: bytes.fromhex("c3"),          # main ret
    0x63ac4c2: bytes.fromhex("0f114228"),    # pair zero: movups %xmm0,0x28(%rdx)
    0x63ac990: bytes.fromhex("498b4210"),    # single-node alt-link follow
    0x63ac5b6: bytes.fromhex("488b4730"),    # chain walk load
    0x636a78f: bytes.fromhex("4889ef"),      # scan slot setup: mov %rbp,%rdi
    0x636a792: bytes.fromhex("e8e91c0400"),  # scan call -> slot-claim
}

# (call site va, target va) key calls
KEY_CALLS = [
    (0x636a792, 0x63ac480),  # allocator scan call
    (0x63615b1, 0x63ac480),  # non-allocator caller, FDE 0x6361320
    (0x636aa33, 0x63ac480),  # allocator scan tail call
]

CLAIM_E8 = [0x63615b1, 0x636161d, 0x6362347, 0x63649e8, 0x6364d4d,
            0x636a792, 0x636a7a7, 0x636a7bc, 0x636a7d1, 0x636a7e6,
            0x636a7fb, 0x636a81a, 0x636a82c, 0x636a83e, 0x636a850,
            0x636a862, 0x636a874, 0x636a886, 0x636a898, 0x636aa33]

TEXT_VA, TEXT_OFF = 0x1419300, 0x1418300


def fail(msg):
    print("FAIL:", msg)
    sys.exit(1)


def read_at(data, va, n):
    return data[va - 0x1000: va - 0x1000 + n]


def main():
    with open(BIN, "rb") as f:
        data = f.read()
    if len(data) != SIZE:
        fail(f"binary size {len(data)} != {SIZE}")
    if hashlib.sha256(data).hexdigest() != SHA:
        fail("binary sha mismatch")
    print(f"binary sha ok ({SIZE} bytes)")

    total_bytes = 0
    total_strict = 0
    for name, (s, e, strict) in EXHIBITS.items():
        with open(os.path.join(PACKET, name + ".hex")) as f:
            claimed = bytes.fromhex("".join(f.read().split()))
        if len(claimed) != e - s:
            fail(f"{name}: hex length {len(claimed)} != {e - s}")
        if read_at(data, s, e - s) != claimed:
            fail(f"{name}: bytes mismatch at {hex(s)}")
        od = subprocess.run(["objdump", "-d", f"--start-address={hex(s)}",
                             f"--stop-address={hex(e)}", BIN],
                            capture_output=True, text=True).stdout
        lines = [l for l in od.splitlines()
                 if l.strip() and l.strip()[0].isdigit()
                 and ":" in l.split()[0]]
        got_strict = 0
        for l in lines:
            parts = l.split("\t")
            if len(parts) >= 3 and parts[2].strip():
                got_strict += 1
        if got_strict != strict:
            fail(f"{name}: strict {got_strict} != {strict}")
        total_bytes += e - s
        total_strict += strict
    print(f"exhibits ok: {len(EXHIBITS)} excerpts, {total_bytes} bytes, "
          f"{total_strict} strict")

    for va, want in KEY_BYTES.items():
        if read_at(data, va, len(want)) != want:
            fail(f"key byte mismatch at {hex(va)}")
    print(f"key bytes ok: {len(KEY_BYTES)} sites")

    for site, target in KEY_CALLS:
        b = read_at(data, site, 5)
        if b[0] != 0xe8:
            fail(f"call opcode at {hex(site)}")
        got = site + 5 + struct.unpack("<i", b[1:5])[0]
        if got != target:
            fail(f"call at {hex(site)} -> {hex(got)} != {hex(target)}")
    print(f"key calls ok: {len(KEY_CALLS)} calls")

    # Census: whole-.text E8/E9 scan via find-loop over the file range.
    text = data[TEXT_OFF:TEXT_OFF + 0x4fd7700]

    def scan(opcode, target):
        hits = []
        i = text.find(bytes([opcode]))
        while i != -1:
            if i + 5 <= len(text):
                rel = struct.unpack("<i", text[i + 1:i + 5])[0]
                va = TEXT_VA + i
                if va + 5 + rel == target:
                    hits.append(va)
            i = text.find(bytes([opcode]), i + 1)
        return hits

    claim_e8 = scan(0xe8, 0x63ac480)
    if claim_e8 != CLAIM_E8:
        fail(f"claim E8 census mismatch: {len(claim_e8)} sites")
    claim_e9 = scan(0xe9, 0x63ac480)
    if claim_e9:
        fail(f"claim E9 census mismatch: {claim_e9}")
    # LEA rip-relative scan: 48/4c 8d with modrm mod=00 reg=any rm=101.
    lea_hits = []
    for i in range(len(text) - 7):
        if text[i] in (0x48, 0x4c) and text[i + 1] == 0x8d \
                and (text[i + 2] & 0xc7) == 0x05:
            rel = struct.unpack("<i", text[i + 3:i + 7])[0]
            va = TEXT_VA + i
            if va + 7 + rel == 0x63ac480:
                lea_hits.append(va)
    if lea_hits:
        fail(f"claim LEA census mismatch: {lea_hits}")
    print(f"census ok: claim {len(claim_e8)} E8, 0 E9, 0 LEA/GOT (below)")

    # .rela.dyn addend scan via direct ELF section parse.
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", data[0x3a:0x40])
    hdrs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, flags, addr, off, size = struct.unpack("<IIQQQQ", data[o:o + 40])
        hdrs.append((name, typ, addr, off, size))
    str_off = hdrs[e_shstrndx][3]
    strtab = data[str_off:]

    def sec_name(n):
        end = strtab.find(b"\x00", n)
        return strtab[n:end].decode()

    rela = None
    for (name, typ, addr, off, size) in hdrs:
        if sec_name(name) == ".rela.dyn":
            rela = (off, size)
            break
    if rela is None:
        fail("no .rela.dyn section")
    off, size = rela
    entries = size // 24
    got_hits = 0
    for i in range(entries):
        o = off + i * 24
        _r_off, _r_info, r_add = struct.unpack("<QQq", data[o:o + 24])
        if r_add == 0x63ac480:
            got_hits += 1
    if got_hits:
        fail(f"GOT addend hits: {got_hits}")
    print(f"rela ok: {entries} .rela.dyn entries, 0 GOT hits")

    # FDE bounds via objdump frames.
    frames = subprocess.run(["objdump", "--dwarf=frames", BIN],
                            capture_output=True, text=True).stdout
    if "pc=00000000063ac480..00000000063acb33" not in frames:
        fail("slot-claim FDE bounds")
    print("FDE bounds ok: slot-claim 435B")

    # MANIFEST.
    man = os.path.join(PACKET, "MANIFEST.sha256")
    with open(man) as f:
        lines = [l.strip() for l in f if l.strip()]
    if len(lines) != 15:
        fail(f"MANIFEST entries {len(lines)} != 15")
    rc = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"],
                        cwd=PACKET, capture_output=True, text=True)
    if rc.returncode != 0:
        fail("MANIFEST check failed:\n" + rc.stdout + rc.stderr)
    print("MANIFEST ok: 15/15 entries")
    print(f"verifier: all checks passed ({len(EXHIBITS)} excerpts, "
          f"{total_strict} strict, census {len(claim_e8)} "
          f"E8 sites, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
