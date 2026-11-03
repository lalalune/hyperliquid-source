#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-rem (node #115, static only).

Checks: binary SHA/size, 5 exhibits byte-exact, key-byte sites, key
calls, census (remainder helper 2 E8 / 0 E9 / 0 LEA / 0 GOT via .rela.dyn
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
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-node115-lu-rem")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032

EXHIBITS = {
    "rm_entry": (0x6369fe0, 0x636a00a, 14),
    "rm_small": (0x636a010, 0x636a032, 7),
    "rm_call": (0x636a032, 0x636a047, 5),
    "rm_large": (0x636a0df, 0x636a12c, 18),
    "rm_acct": (0x636a095, 0x636a0bf, 7),
}

# (va, expected bytes) key-byte sites, not excerpted
KEY_BYTES = {
    0x6369fe0: bytes.fromhex("41554989d5"),    # entry: push r13; mov rdx,r13 (no endbr64)
    0x6369ff6: bytes.fromhex("488b4610"),        # remainder load [node+0x10]
    0x6369ffd: bytes.fromhex("743b"),            # zero-remainder skip -> accounting
    0x636a047: bytes.fromhex("8b3de77a3a00"),    # flag load .bss 0x6711b34
    0x636a078: bytes.fromhex("488d15f5823a00"),  # flag lea .bss 0x6712374
    0x636a0c9: bytes.fromhex("c3"),              # single ret
    0x636a0d0: bytes.fromhex("48b90000000000000070"),  # huge threshold movabs
    0x636a12c: bytes.fromhex("bf180f0000"),      # huge case: last slot 0xf18
    0x636a06d: bytes.fromhex("4801b5300f0000"),  # pool+0xf30 add
    0x636a0b8: bytes.fromhex("48019d400f0000"),  # pool+0xf40 add
    0x636a9b7: bytes.fromhex("4829fa"),          # carve: rdx = aligned - old +0x8
    0x636a9cc: bytes.fromhex("4c896010"),        # carve: store remainder [block+0x10]
}

# (call site va, target va) key calls
KEY_CALLS = [
    (0x636a035, 0x63ac0d0),  # remainder -> insert helper
    (0x636a9d0, 0x6369fe0),  # allocator carve -> remainder
    (0x636b2b3, 0x6369fe0),  # second caller -> remainder
]

REM_E8 = [0x636a9d0, 0x636b2b3]

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

    rem_e8 = scan(0xe8, 0x6369fe0)
    if rem_e8 != REM_E8:
        fail(f"remainder E8 census mismatch: {rem_e8}")
    rem_e9 = scan(0xe9, 0x6369fe0)
    if rem_e9:
        fail(f"remainder E9 census mismatch: {rem_e9}")
    # LEA rip-relative scan: 48/4c 8d with modrm mod=00 reg=any rm=101.
    lea_hits = []
    for i in range(len(text) - 7):
        if text[i] in (0x48, 0x4c) and text[i + 1] == 0x8d \
                and (text[i + 2] & 0xc7) == 0x05:
            rel = struct.unpack("<i", text[i + 3:i + 7])[0]
            va = TEXT_VA + i
            if va + 7 + rel == 0x6369fe0:
                lea_hits.append(va)
    if lea_hits:
        fail(f"remainder LEA census mismatch: {lea_hits}")
    print(f"census ok: remainder {len(rem_e8)} E8, 0 E9, 0 LEA/GOT (below)")

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
        if r_add == 0x6369fe0:
            got_hits += 1
    if got_hits:
        fail(f"GOT addend hits: {got_hits}")
    print(f"rela ok: {entries} .rela.dyn entries, 0 GOT hits")

    # FDE bounds via objdump frames.
    frames = subprocess.run(["objdump", "--dwarf=frames", BIN],
                            capture_output=True, text=True).stdout
    if "pc=0000000006369fe0..000000000636a136" not in frames:
        fail("remainder FDE bounds")
    print("FDE bounds ok: remainder 342B")

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
          f"{total_strict} strict, census {len(rem_e8)} "
          f"E8 sites, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
