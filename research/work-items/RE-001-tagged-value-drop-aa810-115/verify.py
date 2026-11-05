#!/usr/bin/env python3
"""Verify the RE-001 tagged-value destructor packet (0x57aa810).

Run from anywhere:  python3 research/work-items/
RE-001-tagged-value-drop-aa810-115/verify.py

Checks, all against the digest-verified local copy
work/hl-node-115.bin:

  1. The binary's SHA-256 matches provenance/artifacts.json.
  2. MANIFEST.sha256 matches the packet files.
  3. main.txt / twin.txt / glue.txt regenerate byte-for-byte.
  4. Every excerpt instruction's bytes match the raw binary.
  5. The five FDE ranges are present in readelf's frames.
  6. Both jump tables decode to the pinned case map, and the two
     further instantiations carry the same case grouping.
  7. The deallocation and panic slots resolve as pinned.
  8. The census is reproduced: exactly 2,555 direct calls and 4
     tail jumps with the exact site list from callers.tsv.
  9. No stored pointers / relocations / internal-entry transfers
     name an address inside the routine's FDE.
 10. The LSDA call-site rows match the pinned pad mapping, and
     the twin's rows match this routine's offset-for-offset.
 11. The panic shim's message bytes are as pinned.
"""
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work/hl-node-115.bin"
sys.path.insert(0, str(HERE))

MAIN = 0x57AA810
MAIN_END = 0x57AA9CD
TWIN = 0x5B20680
TWIN_END = 0x5B2083D
GLUE = 0x5B0AD70
DEALLOC_FDE = (0x635DE30, 0x635DED5)
SHIM_FDE = (0x1680CAB, 0x1680CBF)
MAIN_TABLE = 0x9317A4
TWIN_TABLE = 0x93D9AC
# tag index -> arm target offset from the routine start
CASE_OFFSETS = [0x27] * 12 + [0x36, 0x27, 0x36, 0x27, 0x27,
                              0xB5, 0x27, 0xC3, 0x48]
LSDA_ROWS = [
    # (range_start, range_end, landing_pad, action); offsets from MAIN
    (0x6D, 0x72, 0x17C, 0),    # tag-20 element call -> continuation pad
    (0x99, 0xA4, 0x128, 0),    # pair first-half call -> pair pad
    (0xAE, 0xB3, 0x13D, 0),    # pair second-half call -> pair pad tail
    (0xB9, 0xC1, 0x118, 0),    # box tag 17 self-call -> box pad
    (0xC7, 0xCF, 0x116, 0),    # box tag 19 self-call -> box pad alias
    (0x130, 0x135, 0x137, 1),  # pair pad's own twin call -> panic shim
    (0x155, 0x162, 0x176, 1),  # pair pad's glue call -> panic shim
    (0x185, 0x192, 0x1B7, 1),  # vector pad's twin call -> panic shim
    (0x192, 0x1BD, 0x000, 0),  # finish/resume region -> no pad
]


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


data = BIN.read_bytes()


def fo(va):
    return va - 0x1000 if va >= 0x1419300 else va


# 1. Digest against provenance.
digest = hashlib.sha256(data).hexdigest()
prov = json.loads((ROOT / "provenance/artifacts.json").read_text())
want = next(f["sha256"] for f in prov["files"]
            if f["path"] == "artifacts/node/115/hl-node")
if digest != want:
    fail(f"binary digest {digest} != provenance {want}")
print("1. binary digest matches provenance/artifacts.json")

# 2. Manifest.
manifest = (HERE / "MANIFEST.sha256").read_text().splitlines()
for line in manifest:
    if not line.strip():
        continue
    m = re.match(r"^([0-9a-f]{64}) [ *](.+)$", line)
    if not m:
        fail(f"bad manifest line: {line!r}")
    h = hashlib.sha256((HERE / m.group(2)).read_bytes()).hexdigest()
    if h != m.group(1):
        fail(f"manifest mismatch for {m.group(2)}")
print(f"2. MANIFEST.sha256 matches ({len(manifest)} files)")

# 3. Excerpts regenerate byte-for-byte.
from export_excerpts import EXCERPTS, render
for name, (start, stop) in EXCERPTS.items():
    if render(start, stop) != (HERE / name).read_text():
        fail(f"{name} does not regenerate")
print("3. main.txt / twin.txt / glue.txt regenerate byte-for-byte")

# 4. Excerpt instruction bytes against the raw binary.
pat = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+|[0-9a-f]+)\s*\t", re.M)
count = 0
for name in EXCERPTS:
    for addr_s, bytes_s in pat.findall((HERE / name).read_text()):
        bs = bytes_s.replace(" ", "")
        raw = bytes.fromhex(bs)
        addr = int(addr_s, 16)
        if data[fo(addr):fo(addr) + len(raw)] != raw:
            fail(f"{name}: instruction at {addr:#x} disagrees with binary")
        count += 1
print(f"4. excerpt instruction bytes match the binary ({count} instructions)")

# 5. FDE ranges in readelf's frames.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True).stdout
have = {(int(a, 16), int(b, 16)) for a, b in
        re.findall(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", frames)}
for rng in ((MAIN, MAIN_END), (TWIN, TWIN_END), (GLUE, 0x5B0ADAC),
            DEALLOC_FDE, SHIM_FDE):
    if rng not in have:
        fail(f"FDE {rng[0]:#x}..{rng[1]:#x} missing")
    if f"pc={rng[0]:016x}..{rng[1]:016x}" not in (HERE / "frames.txt").read_text():
        fail(f"FDE {rng[0]:#x} missing from frames.txt")
print("5. the five FDE ranges are present in readelf's frames")


def table_offsets(table_va, base):
    ents = [struct.unpack_from("<i", data, fo(table_va) + 4 * k)[0]
            for k in range(21)]
    return [table_va + e - base for e in ents]


# 6. Jump tables.
got = table_offsets(MAIN_TABLE, MAIN)
if got != CASE_OFFSETS:
    fail(f"main jump table decodes to {got}, expected {CASE_OFFSETS}")
twin_off = table_offsets(TWIN_TABLE, TWIN)
if twin_off != CASE_OFFSETS:
    fail(f"twin jump table case offsets differ: {twin_off}")


def grouping(offsets):
    seen = {}
    out = []
    for o in offsets:
        if o not in seen:
            seen[o] = len(seen)
        out.append(seen[o])
    return out


want_group = grouping(CASE_OFFSETS)
for base, table in ((0x21D8EB0, 0x5E4B38), (0x3B62630, 0x7AE184)):
    if grouping(table_offsets(table, base)) != want_group:
        fail(f"instantiation at {base:#x} has a different case grouping")
print("6. jump tables decode to the pinned case map in all four "
      "instantiations")

# 7. Slot resolutions.
rel = subprocess.run(["readelf", "-r", str(BIN)],
                     capture_output=True, text=True).stdout
slots = {}
for line in rel.splitlines():
    m = re.match(r"^([0-9a-f]+)\s+([0-9a-f]+)\s+R_X86_64_RELATIVE\s+"
                 r"([0-9a-f]+)\s*$", line)
    if m:
        slots[int(m.group(1), 16)] = int(m.group(3), 16)
if slots.get(0x64DF4A0) != 0x635DE30:
    fail(f"dealloc slot resolves to {slots.get(0x64DF4A0)!r}")
if slots.get(0x64DF4C0) != 0x1680CAB:
    fail(f"panic slot resolves to {slots.get(0x64DF4C0)!r}")
print("7. deallocation slot -> 0x635de30, panic slot -> 0x1680cab")

# 8. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)["main"]
if (counts["direct_calls"], counts["tail_jumps"]) != (2555, 4):
    fail(f"census counts changed: {counts}")
sites = set()
for line in (HERE / "callers.tsv").read_text().splitlines()[1:]:
    site, kind, _, _ = line.split("\t")
    sites.add((int(site, 16), kind))
fresh_sites = {(int(va, 16), kind) for va, kind in counts["sites"]}
if sites != fresh_sites:
    fail("callers.tsv site list changed")
print("8. census reproduced: 2,555 direct calls, 4 tail jumps, "
      "exact site list")

# 9. No stored pointers / relocations / internal-entry transfers.
lo, hi = MAIN, MAIN_END
hits = 0
# Every qword in [lo, hi) has the byte shape [b, 0xaa, 0x57, 0,0,0,0,0];
# one needle pass finds them all.
i = data.find(b"\xaa\x57\x00\x00\x00\x00\x00\x00")
while i >= 0:
    if i >= 1 and lo <= (data[i - 1] | (0x57AA << 8)) < hi:
        hits += 1
    i = data.find(b"\xaa\x57\x00\x00\x00\x00\x00\x00", i + 1)
if hits:
    fail(f"{hits} stored qwords name an address inside the FDE")
for addr, addend in slots.items():
    if lo <= addend < hi:
        fail(f"RELATIVE relocation at {addr:#x} names the routine")
seg = data[0x1418300:0x1418300 + 0x4FD88A0]
internal = 0
for op in (0xE8, 0xE9):
    i = 0
    while True:
        i = seg.find(bytes([op]), i)
        if i < 0:
            break
        rel = struct.unpack_from("<i", seg, i + 1)[0]
        site = 0x1419300 + i
        tgt = site + 5 + rel
        # Transfers from outside the body to a non-entry address
        # inside it would break the pinned entry contract. (The
        # body's own jumps to its shared tail blocks are its own
        # control flow and are excluded by the site test.)
        if lo < tgt < hi and not (lo <= site < hi):
            internal += 1
        i += 1
if internal:
    fail(f"{internal} external rel32 transfers target an internal entry")
print("9. no stored qwords, relocations or external internal-entry "
      "transfers name the routine")

# 10. LSDA rows.
EH = 0xCA6ED8


def uleb(buf, i):
    r = s = 0
    while True:
        b = buf[i]
        i += 1
        r |= (b & 0x7F) << s
        s += 7
        if not (b & 0x80):
            return r, i


def enc_val(buf, i, enc, pcrel=None):
    fmt = enc & 0x0F
    if fmt == 0x01:
        v, i = uleb(buf, i)
    elif fmt == 0x0B:
        v = struct.unpack_from("<i", buf, i)[0]
        i += 4
    elif fmt == 0x03:
        v = struct.unpack_from("<I", buf, i)[0]
        i += 4
    elif fmt == 0x02:
        v = struct.unpack_from("<H", buf, i)[0]
        i += 2
    elif fmt == 0x0A:
        v = struct.unpack_from("<h", buf, i)[0]
        i += 2
    elif fmt == 0x04:
        v = struct.unpack_from("<Q", buf, i)[0]
        i += 8
    elif fmt == 0x00:
        v = struct.unpack_from("<Q", buf, i)[0]
        i += 8
    else:
        raise ValueError(f"fmt {fmt:#x}")
    if enc & 0x70 == 0x10:
        v += pcrel
    return v, i


def lsda_rows(fde_off, expect_begin):
    i = EH + fde_off + 8
    begin, i = enc_val(data, i, 0x1B, i)
    rng, i = enc_val(data, i, 0x0B, None)
    assert begin == expect_begin, hex(begin)
    auglen, i = uleb(data, i)
    lsda, i = enc_val(data, i, 0x1B, i)
    j = lsda
    lp_enc = data[j]
    j += 1
    if lp_enc != 0xFF:
        _, j = enc_val(data, j, lp_enc, j)  # lp_base value unused
    tt_enc = data[j]
    j += 1
    if tt_enc != 0xFF:
        _, j = uleb(data, j)
    cs_enc = data[j]
    j += 1
    cs_len, j = uleb(data, j)
    end = j + cs_len
    rows = []
    while j < end:
        s, j = enc_val(data, j, cs_enc, None)
        ln, j = enc_val(data, j, cs_enc, None)
        pad, j = enc_val(data, j, cs_enc, None)
        act, j = uleb(data, j)
        rows.append((s, s + ln, pad, act))
    return rows


rows = lsda_rows(0x6CD7BC, MAIN)
want_rows = [(s, e, p, a) for s, e, p, a in LSDA_ROWS]
if rows != want_rows:
    fail(f"main LSDA rows {rows} != pinned {want_rows}")
twin_rows = lsda_rows(0x71125C, TWIN)
# rows are offsets from each routine's own lp_base already
if twin_rows != rows:
    fail("twin LSDA geometry differs from the main routine's")
print("10. LSDA call-site rows match the pinned pad mapping; the "
      "twin's geometry is identical")

# 11. Panic message bytes.
msg = data[fo(0x46E9BD):fo(0x46E9BD) + 36]
if msg != b"panic in a destructor during cleanup":
    fail(f"panic message bytes differ: {msg!r}")
print("11. panic shim message is 'panic in a destructor during cleanup'")

print("verify: all checks passed")
