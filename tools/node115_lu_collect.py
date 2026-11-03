#!/usr/bin/env python3
"""Static verifier for the node #115 lu collect packet (RE-001-node115-lu-collect).

Byte reads only. Never executes the node binary.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-collect"

EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032
FDE_START = 0x6363560
FDE_END = 0x636365A
REMOVE_HELPER = 0x63ACB40
TABLE_BASE = 0x6711B40
GLOBAL_WORD = 0x650969C
EXPECT_INCOMING = [0x63EAB9E, 0x63EAC11, 0x63EACF9, 0x63EB656, 0x63EB6C9, 0x63EB74C]
EXPECT_RELA_ENTRIES = 60723

RECORDS = json.loads((PACKET / "records.json").read_text())


def va_to_off(va):
    return va - 0x1000  # .text file offset convention


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def main():
    data = BIN.read_bytes()
    if len(data) != EXPECT_SIZE:
        fail(f"binary size {len(data)} != {EXPECT_SIZE}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECT_SHA:
        fail("binary sha mismatch")
    print(f"binary sha ok ({len(data)} bytes)")

    exhibits = RECORDS["exhibits"]
    total_bytes = 0
    total_strict = 0
    for name, ex in exhibits.items():
        start = int(ex["range"][0], 16)
        end = int(ex["range"][1], 16)
        raw = data[va_to_off(start):va_to_off(end)]
        if len(raw) != ex["bytes"] or len(raw) != end - start:
            fail(f"exhibit {name} length {len(raw)} != {ex['bytes']}")
        hexfile = (PACKET / f"{name}.hex").read_text().strip()
        if bytes.fromhex(hexfile) != raw:
            fail(f"exhibit {name} hex mismatch")
        # Strict mnemonic lines: address + bytes field + tab + mnemonic.
        # Objump byte-continuation lines carry no mnemonic and are excluded.
        strict = 0
        for line in (PACKET / f"{name}.objdump.txt").read_text().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2].strip():
                strict += 1
        if strict != ex["strict"]:
            fail(f"exhibit {name} strict {strict} != {ex['strict']}")
        total_bytes += len(raw)
        total_strict += strict
    print(f"exhibits ok: {len(exhibits)} excerpts, {total_bytes} bytes, "
          f"{total_strict} strict")

    # Key bytes: entry, table lea, gate lea, call target, head/anchor compares.
    if data[va_to_off(FDE_START):va_to_off(FDE_START) + 4] != bytes.fromhex("f30f1efa"):
        fail("entry is not endbr64")
    # Table lea at 0x6363578: 4c 8d 05 + disp32 -> 0x6711b40.
    o = va_to_off(0x6363578)
    if data[o:o + 3] != bytes.fromhex("4c8d05"):
        fail("table lea opcode mismatch")
    disp = struct.unpack("<i", data[o + 3:o + 7])[0]
    if 0x6363578 + 7 + disp != TABLE_BASE:
        fail("table lea target mismatch")
    # Gate lea at 0x63635c0: 4c 8d 15 + disp32 -> 0x650969c.
    o = va_to_off(0x63635C0)
    if data[o:o + 3] != bytes.fromhex("4c8d15"):
        fail("gate lea opcode mismatch")
    disp = struct.unpack("<i", data[o + 3:o + 7])[0]
    if 0x63635C0 + 7 + disp != GLOBAL_WORD:
        fail("gate lea target mismatch")
    # Head compare at 0x6363568: cmp 0xc0(%rcx),%rdx.
    if data[va_to_off(0x6363568):va_to_off(0x6363568) + 7] != bytes.fromhex("483b91c0000000"):
        fail("head cmp bytes mismatch")
    # Anchor compare at 0x63635d3: cmp 0xd8(%rbx),%rdx.
    if data[va_to_off(0x63635D3):va_to_off(0x63635D3) + 7] != bytes.fromhex("483b93d8000000"):
        fail("anchor cmp bytes mismatch")
    print("key bytes ok: 6 sites")

    # Key calls: exactly one call inside the FDE, targeting the remove
    # helper. Instruction boundaries come from objdump over the FDE range
    # (a raw byte scan would false-positive on E8 bytes embedded as
    # modrm/immediate bytes inside other instructions).
    import re
    import subprocess
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(FDE_START)}",
         f"--stop-address={hex(FDE_END)}", str(BIN)],
        capture_output=True, text=True).stdout
    calls = []
    for line in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\tcall\s+([0-9a-f]+)", line)
        if m:
            calls.append((int(m.group(1), 16), int(m.group(2), 16)))
    if calls != [(0x636359F, REMOVE_HELPER)]:
        fail(f"calls inside FDE {[(hex(a), hex(b)) for a, b in calls]}")
    print("key calls ok: 1 E8 inside FDE")

    # Census: whole-.text E8 scan for this FDE; .rela.dyn scan for GOT.
    # .text spans file offsets [0x1418300, 0x63f5a00) in this image.
    text_start, text_end = 0x1418300, 0x1418300 + 0x4FD7700
    incoming = []
    for i in range(text_start, text_end - 5):
        if data[i] == 0xE8:
            rel = struct.unpack("<i", data[i + 1:i + 5])[0]
            va = i + 0x1000
            if va + 5 + rel == FDE_START:
                incoming.append(va)
    if incoming != EXPECT_INCOMING:
        fail(f"incoming E8 {[hex(v) for v in incoming]}")
    rela_off, rela_size = 0x6BE8, 0x163CC8
    got = 0
    entries = rela_size // 24
    for i in range(entries):
        _off, _info, add = struct.unpack(
            "<QQq", data[rela_off + i * 24:rela_off + i * 24 + 24])
        if add == FDE_START:
            got += 1
    if got != 0 or entries != EXPECT_RELA_ENTRIES:
        fail(f"GOT {got}, rela entries {entries}")
    print(f"census ok: collect 6 E8, 0 GOT, {entries} rela entries")

    # FDE bounds.
    if FDE_END - FDE_START != 250:
        fail("FDE size mismatch")
    print("FDE bounds ok: collect 250B")

    # MANIFEST.
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    ok = 0
    for line in manifest:
        digest, path = line.split(None, 1)
        target = (PACKET / path).resolve() if not path.startswith("..") else \
            (PACKET / path).resolve()
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != digest:
            fail(f"MANIFEST mismatch {path}")
        ok += 1
    if ok != 15:
        fail(f"MANIFEST {ok} entries != 15")
    print("MANIFEST ok: 15/15 entries")
    print(f"verifier: all checks passed ({len(exhibits)} excerpts, "
          f"{total_bytes} bytes, {total_strict} strict, census 6 E8 sites, "
          f"MANIFEST 15 entries)")


if __name__ == "__main__":
    main()
