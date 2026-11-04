#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-alloc (node #115, static only).

Checks: binary SHA/size, 5 exhibits byte-exact, key-byte sites, key
calls, census (thunk 19 E8 / worker 1 E8 + thunk E9 tail jump /
0 GOT via .rela.dyn addends), FDE bounds, MANIFEST 15/15.
Exits 0 only when every check passes.
"""
import hashlib
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-node115-lu-alloc")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIZE = 105896032

EXHIBITS = {
    "al_thunk": (0x636b370, 0x636b37c, 3),
    "al_head": (0x636a680, 0x636a6b5, 18),
    "al_scan": (0x636a737, 0x636a75d, 8),
    "al_fresh": (0x636a8b4, 0x636a8e4, 11),
    "al_found": (0x636a97e, 0x636a9d0, 21),
}

# (va, expected bytes) key-byte sites, not excerpted
KEY_BYTES = {
    0x636b377: bytes.fromhex("e904f3ffff"),      # thunk tail jmp -> worker
    0x636a6d0: bytes.fromhex("e8db700800"),      # trylock call
    0x636aa0b: bytes.fromhex("c3"),              # worker ret
    0x63d9803: bytes.fromhex("e8681bf9ff"),      # miss-handler thunk call
    0x636b3a5: bytes.fromhex("e8d6f2ffff"),      # direct worker call
    0x636a9e7: bytes.fromhex("49894d00"),        # mode store [r13],rcx
    0x636aa7d: bytes.fromhex("4d0fbdc8"),        # large-path bsr
    0x636a6ff: bytes.fromhex("488d35bad03b00"),  # .bss table lea
    0x636a8e4: bytes.fromhex("e857f8ffff"),      # fresh helper call
    0x636a9d0: bytes.fromhex("e80bf6ffff"),      # split helper call
    0x636aa15: bytes.fromhex("e8664c0500"),      # contention call 1
    0x636aab5: bytes.fromhex("e8c64b0500"),      # contention call 2
    0x636a8be: bytes.fromhex("e8ad620800"),      # unlock call
}

# (call site va, target va) key calls
KEY_CALLS = [
    (0x636b377, 0x636a680),  # E9 tail jump (handled separately below)
    (0x636a6d0, 0x63f17b0),
    (0x63d9803, 0x636b370),
    (0x636b3a5, 0x636a680),
    (0x636a8e4, 0x636a140),
    (0x636a9d0, 0x6369fe0),
    (0x636aa15, 0x63bf680),
    (0x636aab5, 0x63bf680),
    (0x636a8be, 0x63f0b70),
]

THUNK_E8 = [0x636448f, 0x636454b, 0x6369ec6, 0x63a5625, 0x63a8335,
            0x63a83f5, 0x63a8442, 0x63a848d, 0x63a84c5, 0x63b868c,
            0x63b8763, 0x63b8790, 0x63c43e9, 0x63c4445, 0x63d7f1b,
            0x63d9803, 0x63dafea, 0x63ee1a0, 0x63ee411]
WORKER_E8 = [0x636b3a5]
WORKER_E9 = [0x636b377]

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
        if site == 0x636b377:
            if b[0] != 0xe9:
                fail("thunk tail jump opcode")
            got = site + 5 + struct.unpack("<i", b[1:5])[0]
        else:
            if b[0] != 0xe8:
                fail(f"call opcode at {hex(site)}")
            got = site + 5 + struct.unpack("<i", b[1:5])[0]
        if got != target:
            fail(f"call at {hex(site)} -> {hex(got)} != {hex(target)}")
    print(f"key calls ok: {len(KEY_CALLS)} calls")

    # Census: whole-.text E8/E9 scan via find-loop over the file range.
    text = data[TEXT_OFF:TEXT_OFF + 0x4fd7700]
    text_end = TEXT_OFF + 0x4fd7700

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

    thunk_e8 = scan(0xe8, 0x636b370)
    if thunk_e8 != THUNK_E8:
        fail(f"thunk E8 census mismatch: {len(thunk_e8)} sites")
    worker_e8 = scan(0xe8, 0x636a680)
    if worker_e8 != WORKER_E8:
        fail(f"worker E8 census mismatch: {worker_e8}")
    worker_e9 = scan(0xe9, 0x636a680)
    if worker_e9 != WORKER_E9:
        fail(f"worker E9 census mismatch: {worker_e9}")
    print(f"census ok: thunk {len(thunk_e8)} E8, worker "
          f"{len(worker_e8)} E8 + {len(worker_e9)} E9, 0 LEA/GOT (below)")

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
        if r_add in (0x636b370, 0x636a680):
            got_hits += 1
    if got_hits:
        fail(f"GOT addend hits: {got_hits}")
    print(f"rela ok: {entries} .rela.dyn entries, 0 GOT hits")

    # FDE bounds via objdump frames.
    frames = subprocess.run(["objdump", "--dwarf=frames", BIN],
                            capture_output=True, text=True).stdout
    if "pc=000000000636b370..000000000636b37c" not in frames:
        fail("thunk FDE bounds")
    if "pc=000000000636a680..000000000636aad8" not in frames:
        fail("worker FDE bounds")
    print("FDE bounds ok: thunk 12B, worker 1112B")

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
          f"{total_strict} strict, census {len(thunk_e8)}/{len(worker_e8)} "
          f"E8 sites, MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
