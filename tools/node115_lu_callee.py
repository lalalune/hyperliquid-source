#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-callee.

Reads only bytes from artifacts/node/115/hl-node; never executes it.
Checks: binary SHA-256, exhibit regeneration + strict counts, key-byte
sites, whole-.text census (E8/E9/LEA) + .rela.dyn GOT scan, FDE bounds,
and MANIFEST coverage. Exit 0 only if every check passes.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "artifacts/node/115/hl-node"
PACKET = ROOT / "research/work-items/RE-001-node115-lu-callee"
RECORDS = json.loads((PACKET / "records.json").read_text())

EXPECT_SHA = RECORDS["binary_sha256"]
EXHIBITS = RECORDS["exhibits"]
CALLEE = 0x63C1030
SELECTOR = 0x63B2630

# (VA, exact bytes) for non-call key sites; E8 sites are checked by target.
KEY_BYTES = {
    0x63C1340: "4c8bbd88ec0000",
    0x63C134D: "410f95c3",
    0x63C11CD: "4183bde04b000001",
    0x63C12DC: "41c644246801",
    0x63B26B0: "498b9c2410260000",
    0x63B2761: "4183bc24e04b000002",
    0x63B26F6: "4180bc24e84b000000",
    0x63B2701: "48f70300000100",
}
# (call VA, expected target) for E8 key sites.
KEY_CALLS = {
    0x63C1090: 0x63F0B70,
    0x63C109C: 0x636B340,
    0x63C112E: 0x636B340,
    0x63C11EF: 0x63B3C00,
    0x63C1215: 0x63B3B00,
    0x63C1194: 0x63B3080,
    0x63C128F: 0x63F17B0,
    0x63C12D3: 0x63BF680,
    0x63B266E: 0x63F17B0,
    0x63B26CB: 0x63B0510,
    0x63B26D8: 0x63B0510,
    0x63C1CAD: 0x63B2630,
    0x63C1989: 0x63C1030,
    0x63C1A89: 0x63C1030,
    0x63C1AE1: 0x63C1030,
}

FAILURES = []


def check(cond, msg):
    if not cond:
        FAILURES.append(msg)
        print(f"FAIL: {msg}")


def va_to_off(va):
    return va - 0x1000


def main():
    data = BIN.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    check(sha == EXPECT_SHA, f"binary sha mismatch: {sha}")
    print(f"binary sha ok ({len(data)} bytes)")

    # Exhibits: hex regeneration + strict counts from objdump.
    total_bytes = 0
    total_strict = 0
    for ex in EXHIBITS:
        s = int(ex["start"], 16)
        e = int(ex["end"], 16)
        raw = data[va_to_off(s):va_to_off(e)]
        stored = (PACKET / f"{ex['name']}.hex").read_text().strip()
        check(raw.hex() == stored, f"{ex['name']}.hex mismatch")
        check(len(raw) == ex["bytes"], f"{ex['name']} byte count")
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={hex(s)}",
             f"--stop-address={hex(e)}", str(BIN)],
            capture_output=True, text=True).stdout
        strict = [ln for ln in out.splitlines()
                  if re.match(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S", ln)]
        check(len(strict) == ex["strict_instrs"],
              f"{ex['name']} strict {len(strict)} != {ex['strict_instrs']}")
        # Stored objdump text must match the regenerated strict lines.
        stored_lines = [ln.strip() for ln in
                        (PACKET / f"{ex['name']}.objdump.txt")
                        .read_text().splitlines() if ln.strip()]
        regen_lines = [ln.strip() for ln in strict]
        check(stored_lines == regen_lines,
              f"{ex['name']}.objdump.txt mismatch")
        total_bytes += len(raw)
        total_strict += len(strict)
    check(total_bytes == RECORDS["total_exhibit_bytes"],
          f"total bytes {total_bytes}")
    check(total_strict == RECORDS["total_strict_instrs"],
          f"total strict {total_strict}")
    print(f"exhibits ok: {len(EXHIBITS)} excerpts, "
          f"{total_bytes} bytes, {total_strict} strict")

    # Key bytes.
    for va, hx in KEY_BYTES.items():
        got = data[va_to_off(va):va_to_off(va) + len(bytes.fromhex(hx))]
        check(got.hex() == hx, f"key bytes mismatch at {hex(va)}")
    for va, tgt in KEY_CALLS.items():
        b = data[va_to_off(va):va_to_off(va) + 5]
        ok = b[0] == 0xE8 and va + 5 + struct.unpack("<i", b[1:5])[0] == tgt
        check(ok, f"key call mismatch at {hex(va)} -> {hex(tgt)}")
    print(f"key bytes ok: {len(KEY_BYTES)} sites, {len(KEY_CALLS)} calls")

    # Census: whole .text byte scan + .rela.dyn addend scan.
    secs = {}
    out = subprocess.run(["readelf", "-SW", str(BIN)],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]+)\s+"
                     r"([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            secs[m.group(1)] = (int(m.group(3), 16),
                                int(m.group(4), 16),
                                int(m.group(5), 16))
    taddr, toff, tsize = secs[".text"]
    text = data[toff:toff + tsize]

    def scan(target):
        e8, e9, lea = [], [], []
        for i in range(len(text) - 8):
            b = text[i]
            va = taddr + i
            if b == 0xE8:
                rel = struct.unpack("<i", text[i + 1:i + 5])[0]
                if va + 5 + rel == target:
                    e8.append(hex(va))
            elif b == 0xE9:
                rel = struct.unpack("<i", text[i + 1:i + 5])[0]
                if va + 5 + rel == target:
                    e9.append(hex(va))
            elif b in (0x48, 0x4C) and text[i + 1] == 0x8D \
                    and (text[i + 2] & 0xC7) == 0x05:
                rel = struct.unpack("<i", text[i + 3:i + 7])[0]
                if va + 7 + rel == target:
                    lea.append(hex(va))
        return e8, e9, lea

    ce8, ce9, clea = scan(CALLEE)
    se8, se9, slea = scan(SELECTOR)
    check(ce8 == RECORDS["census"]["callee_e8"],
          f"callee E8 {ce8}")
    check(ce9 == [] and clea == [], f"callee E9/LEA {ce9} {clea}")
    check(se8 == RECORDS["census"]["selector_e8"],
          f"selector E8 {se8}")
    check(se9 == [] and slea == [], f"selector E9/LEA {se9} {slea}")
    raddr, roff, rsize = secs[".rela.dyn"]
    got = []
    for j in range(0, rsize, 24):
        off, info, add = struct.unpack("<QQq", data[roff + j:roff + j + 24])
        if add in (CALLEE, SELECTOR):
            got.append(hex(off))
    check(got == [], f"GOT hits {got}")
    check(rsize // 24 == RECORDS["census"]["rela_dyn_entries"],
          f"rela entries {rsize // 24}")
    print(f"census ok: callee {len(ce8)} E8, selector {len(se8)} E8, "
          f"0 E9/LEA/GOT, {rsize // 24} rela entries")

    # FDE bounds from .eh_frame.
    frames = subprocess.run(["objdump", "--dwarf=frames", str(BIN)],
                            capture_output=True, text=True).stdout
    for key, start, end in (
            ("callee", RECORDS["callee_fde"]["start"],
             RECORDS["callee_fde"]["end"]),
            ("selector", RECORDS["selector_fde"]["start"],
             RECORDS["selector_fde"]["end"])):
        pat = f"pc={int(start, 16):016x}..{int(end, 16):016x}"
        check(pat in frames, f"{key} FDE {start}..{end} not found")
    print("FDE bounds ok: callee 816B, selector 544B")

    # MANIFEST coverage.
    man = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    entries = [ln.split("  ", 1)[1] for ln in man if "  " in ln]
    import hashlib as hl
    ok = True
    for rel in entries:
        # MANIFEST paths are relative to the packet dir.
        p = PACKET / rel
        if not p.exists():
            ok = False
            break
        digest = hl.sha256(p.read_bytes()).hexdigest()
        want = [ln.split("  ", 1)[0] for ln in man
                if ln.endswith("  " + rel)][0]
        if digest != want:
            ok = False
            break
    check(ok, "MANIFEST entries mismatch")
    check(len(entries) == 15, f"MANIFEST count {len(entries)}")
    check(sorted(entries) == sorted(
        ["README.md", "EVIDENCE.md", "records.json",
         "loop_call.hex", "loop_call.objdump.txt",
         "callee_mode.hex", "callee_mode.objdump.txt",
         "callee_stats.hex", "callee_stats.objdump.txt",
         "base_gate.hex", "base_gate.objdump.txt",
         "callee_tail.hex", "callee_tail.objdump.txt",
         "../../../tools/node115_lu_callee.py",
         "../../../tests/test_node115_lu_callee.py"]),
        "MANIFEST file set mismatch")
    print(f"MANIFEST ok: {len(entries)}/15 entries")

    if FAILURES:
        print(f"verifier: {len(FAILURES)} check(s) failed")
        return 1
    print("verifier: all checks passed (5 excerpts, 36 strict, "
          "census 3/2 E8 sites, MANIFEST 15 entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
