#!/usr/bin/env python3
"""Verifier for the RE-001-node115-lu-qtable-slot8 packet.

Re-checks the node #115 digest, the Q table record with all four RELATIVE
addends, all four slot body hashes and pinned hex files, the FDE ranges,
all GOT resolutions, the park.rs panic Location and message, the 11 table
lea sites, the 0/0/2/6 direct-E8 census lists, and both proceed call sites.
Read-only: never executes the node binary. Exits 0 on success, nonzero
naming the first failing check otherwise.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-qtable-slot8"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"
NODE_SIZE = 105896032
NODE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TABLE = 0x64C6EF8
TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
TEXT_LEN = 0x4FD7700


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    records = json.loads((PACKET / "records.json").read_text())
    data = NODE.read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if digest(NODE) != NODE_SHA:
        fail("node SHA-256 mismatch")
    print(f"node digest OK: {NODE_SIZE} bytes")

    # Relocations via readelf.
    out = subprocess.run(["readelf", "-r", str(NODE)],
                         capture_output=True, text=True).stdout
    relocs = {}
    for line in out.splitlines():
        m = re.match(r"^([0-9a-f]+)\s+\S+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", line)
        if m:
            relocs[int(m.group(1), 16)] = int(m.group(2), 16)
    for slot, target in records["table"]["slots"].items():
        off = int(slot, 16)
        want = int(target, 16)
        if relocs.get(TABLE + off) != want:
            fail(f"table slot {slot}: reloc {relocs.get(TABLE + off)} != {want}")
    for got, want in records["got"].items():
        if relocs.get(int(got, 16)) != int(want, 16):
            fail(f"GOT {got}: reloc != {want}")
    if relocs.get(0x64C6F60) != 0x447492:
        fail("panic Location file pointer != 0x447492")
    print("table slots + GOT + Location relocs OK")

    # Bodies: pinned hex + hashes.
    for name, b in records["bodies"].items():
        lo, hi = int(b["lo"], 16), int(b["hi"], 16)
        body = data[lo - 0x1000:hi - 0x1000]
        pinned = bytes.fromhex((PACKET / f"{name}.hex").read_text().strip())
        if pinned != body:
            fail(f"{name}.hex != binary body")
        if hashlib.sha256(body).hexdigest() != b["sha256"]:
            fail(f"{name} SHA-256 mismatch")
        if hi - lo != b["bytes"]:
            fail(f"{name} byte count mismatch")
    print("4 bodies OK: 20B + 209B + 160B + 27B")

    # FDE ranges via readelf frames dump.
    frames = subprocess.run(["readelf", "--debug-dump=frames", str(NODE)],
                            capture_output=True, text=True).stdout
    for name, f in records["fde"].items():
        lo, hi = f["range"]
        if f"pc=000000000{lo[2:]}..000000000{hi[2:]}" not in frames:
            fail(f"FDE range missing for {name}: {lo}..{hi}")
    print("FDE ranges OK")

    # Panic message bytes (.rodata offset == VA).
    loc = records["panic_location"]
    msg = data[0x94DC34:0x94DC34 + 57]
    if msg.decode("ascii", "replace") != loc["message"]:
        fail("panic message bytes mismatch")
    fstr = data[0x447492:0x447492 + 63].decode()
    if fstr != loc["file"]:
        fail("panic Location file string mismatch")
    print("panic Location + message OK")

    # One-pass census scan over .text.
    text = data[TEXT_OFF:TEXT_OFF + TEXT_LEN]
    lea_hits = []
    e8 = {t: [] for t in ["0x5cfdce0", "0x5cfd8c0", "0x5cfd600", "0x5cfd5e0", "0x5cfc310"]}
    for i in range(len(text) - 7):
        if text[i] in (0x48, 0x4C, 0x49, 0x4D) and text[i + 1] == 0x8D \
                and (text[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            if TEXT_VA + i + 7 + disp == TABLE:
                lea_hits.append(hex(TEXT_VA + i))
        if text[i] == 0xE8 and i <= len(text) - 5:
            disp = struct.unpack_from("<i", text, i + 1)[0]
            tgt = hex(TEXT_VA + i + 5 + disp)
            if tgt in e8:
                e8[tgt].append(hex(TEXT_VA + i))
    c = records["census"]
    if sorted(lea_hits) != sorted(c["lea_table"]):
        fail(f"lea census mismatch: {sorted(lea_hits)}")
    checks = [("e8_slot0_clone", "0x5cfdce0"), ("e8_slot8_wake", "0x5cfd8c0"),
              ("e8_slot2_wake_by_ref", "0x5cfd600"), ("e8_slot3_drop", "0x5cfd5e0"),
              ("e8_proceed", "0x5cfc310")]
    for key, tgt in checks:
        if sorted(e8[tgt]) != sorted(c[key]):
            fail(f"{key} census mismatch: {sorted(e8[tgt])}")
    print(f"lea sites: {len(lea_hits)}, E8: slot0 0, slot8 0, "
          f"slot2 {len(e8['0x5cfd600'])}, slot3 {len(e8['0x5cfd5e0'])}, "
          f"proceed {len(e8['0x5cfc310'])}")
    print("Verified node #115 lu.rs Q-table slot+0x8 packet: table 0x64c6ef8, "
          "slot+0x8 wake 0x5cfd8c0..0x5cfd991 (209B), clone 20B, "
          "wake-by-ref 160B, drop 27B")


if __name__ == "__main__":
    main()
