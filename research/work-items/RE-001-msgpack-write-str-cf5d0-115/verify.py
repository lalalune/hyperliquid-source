#!/usr/bin/env python3
"""Verify the RE-001 MessagePack string writer 0x57cf5d0 packet.

Checks, in order:
 1. Target binary digest matches provenance/artifacts.json.
 2. MANIFEST.sha256 entries match the packet files.
 3. main.txt regenerates byte-for-byte from a fresh objdump run.
 4. Every excerpt instruction's bytes match the raw binary at
    the file offset (virtual address minus 0x1000).
 5. The routine and growth-routine FDE ranges are present in
    readelf output.
 6. The census is reproduced: exactly 903 direct calls and 0
    tail jumps with the exact site list from callers.tsv.
 7. No stored qword / relocation for the routine address.
 8. records.json holds semantic records only.
 9. The routine's FDE carries no LSDA (augmentation length 0,
    CIE augmentation "zR" with no personality), and the memcpy
    slot 0x64df508 resolves to memcpy@GLIBC_2.14.
10. The two recorded copies at 0x159f9c0 and 0x25e8bf0 have
    instruction streams identical to the routine's after
    normalizing embedded addresses.
11. Model spot checks (header table, append protocol, growth
    requests, constant return pair).
"""
import importlib.util
import json
import re
import struct
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parents[2]
BIN = ROOT / "work/hl-node-115.bin"
MAIN_START, MAIN_END = 0x57CF5D0, 0x57CF85A


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


# 1. Target digest.
artifacts = json.loads((ROOT / "provenance/artifacts.json").read_text())
want = next(f["sha256"] for f in artifacts["files"]
            if f["path"] == "artifacts/node/115/hl-node")
if sha256(BIN.read_bytes()).hexdigest() != want:
    fail("binary digest mismatch")

# 2. Manifest.
for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
    digest, name = line.split("  ", 1)
    if sha256((HERE / name).read_bytes()).hexdigest() != digest:
        fail(f"manifest mismatch for {name}")

# 3. Excerpt regeneration (header normalized to the bare binary name,
# matching export_excerpts.py, so the check is not machine-specific).
fresh = subprocess.run(
    ["objdump", "-d", f"--start-address={hex(MAIN_START)}",
     f"--stop-address={hex(MAIN_END)}", str(BIN)],
    capture_output=True, text=True, check=True).stdout
fresh = fresh.replace(str(BIN), BIN.name)
if fresh != (HERE / "main.txt").read_text():
    fail("main.txt does not regenerate byte-for-byte")

# 4. Instruction bytes vs raw binary.
data = BIN.read_bytes()
checked = 0
for line in (HERE / "main.txt").read_text().splitlines():
    m = re.match(r"\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t|$)", line)
    if not m:
        continue
    va = int(m.group(1), 16)
    raw = bytes(int(b, 16) for b in m.group(2).split())
    if data[va - 0x1000:va - 0x1000 + len(raw)] != raw:
        fail(f"byte mismatch at {hex(va)} in main.txt")
    checked += 1
if checked < 150:
    fail(f"too few instructions checked in main.txt: {checked}")
print(f"instruction bytes checked in main.txt: {checked}")

# 5. FDE ranges.
frames = subprocess.run(
    ["readelf", "--debug-dump=frames-interp", str(BIN)],
    capture_output=True, text=True, check=True).stdout
for rng in ("pc=00000000057cf5d0..00000000057cf85a",
            "pc=0000000005963a10..0000000005963a9e"):
    if rng not in frames:
        fail(f"FDE not found: {rng}")

# 6. Census reproduction.
census = subprocess.run(
    [sys.executable, str(HERE / "census.py"), "--sites"],
    capture_output=True, text=True, check=True).stdout
counts = json.loads(census)["main"]
if (counts["direct_calls"], counts["tail_jumps"]) != (903, 0):
    fail(f"census counts changed: {counts}")
sites = set()
for line in (HERE / "callers.tsv").read_text().splitlines()[1:]:
    site, kind, _, _ = line.split("\t")
    sites.add((int(site, 16), kind))
fresh_sites = {(int(va, 16), kind) for va, kind in counts["sites"]}
if sites != fresh_sites:
    fail("callers.tsv site list changed")

# 7. No stored pointers / relocations naming the routine.
if struct.pack("<Q", MAIN_START) in data:
    fail("stored qword for 0x57cf5d0 found")
relocs = subprocess.run(
    ["readelf", "-rW", str(BIN)], capture_output=True, text=True).stdout
for line in relocs.splitlines():
    if line.rstrip().endswith("57cf5d0"):
        fail("relocation names the routine address")

# 8. Semantic records only.
records = json.loads((HERE / "records.json").read_text())
if "mnemonics" in records or "instructions" in records:
    fail("records.json carries a per-instruction list")
for key in ("task", "target", "routines", "object_layout",
            "algorithm", "consumers", "internal_transfers",
            "census", "unknowns"):
    if key not in records:
        fail(f"records.json missing {key}")

# 9. No LSDA on the routine's FDE, and the memcpy slot resolves
# as pinned. The .eh_frame CIE 0 has augmentation "zR" (no 'L',
# no personality); an FDE under it carries one augmentation-length
# byte after its initial location and range, and 0 means no LSDA.
e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
secs = [struct.unpack_from("<IIQQQQ", data, e_shoff + i * e_shentsize)
        for i in range(e_shnum)]
str_off = secs[e_shstrndx][4]


def sec_name(sec):
    end = data.index(b"\x00", str_off + sec[0])
    return data[str_off + sec[0]:end].decode()


eh = next(s for s in secs if sec_name(s) == ".eh_frame")
eh_off, eh_va, eh_size = eh[4], eh[3], eh[5]
aug_end = data.index(b"\x00", eh_off + 9)
if data[eh_off + 9:aug_end] != b"zR":
    fail("CIE 0 augmentation is not 'zR'")
aug_len = None
off = eh_off
while off < eh_off + eh_size:
    ln = struct.unpack_from("<I", data, off)[0]
    if ln == 0:
        break
    if struct.unpack_from("<I", data, off + 4)[0] != 0:
        field_va = eh_va + (off - eh_off) + 8
        init = field_va + struct.unpack_from("<i", data, off + 8)[0]
        if init == MAIN_START:
            aug_len = data[off + 16]
            break
    off += 4 + ln
if aug_len != 0:
    fail(f"routine FDE augmentation length is {aug_len}, not 0")
slot_lines = [ln for ln in relocs.splitlines()
              if ln.startswith("00000000064df508")]
if len(slot_lines) != 1 or "memcpy@GLIBC_2.14" not in slot_lines[0]:
    fail("slot 0x64df508 does not resolve to memcpy@GLIBC_2.14")

# 10. The two recorded copies: normalized instruction streams
# identical to the routine's.
def mnemonics(start, end):
    out = subprocess.run(
        ["objdump", "-d", f"--start-address={hex(start)}",
         f"--stop-address={hex(end)}", str(BIN)],
        capture_output=True, text=True, check=True).stdout
    stream = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and re.match(r"\s*[0-9a-f]+:", parts[0]):
            m = re.sub(r"0x[0-9a-f]+", "N", parts[2].strip())
            m = re.sub(r"[0-9a-f]+(?= <)", "A", m)
            stream.append(m)
    return stream


base_stream = mnemonics(MAIN_START, MAIN_END)
for copy_start in (0x159F9C0, 0x25E8BF0):
    if mnemonics(copy_start, copy_start + 650) != base_stream:
        fail(f"copy at {hex(copy_start)} is not instruction-identical")

# 11. Model spot checks.
spec = importlib.util.spec_from_file_location(
    "msgpack_write_str_cf5d0_115",
    ROOT / "tools/msgpack_write_str_cf5d0_115.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

assert mod.header_bytes(0) == b"\xa0"
assert mod.header_bytes(0x1F) == b"\xbf"
assert mod.header_bytes(0x20) == b"\xd9\x20"
assert mod.header_bytes(0xFF) == b"\xd9\xff"
assert mod.header_bytes(0x100) == b"\xda\x01\x00"
assert mod.header_bytes(0xFFFF) == b"\xda\xff\xff"
assert mod.header_bytes(0x10000) == b"\xdb\x00\x01\x00\x00"
assert mod.header_bytes((1 << 32) + 5) == b"\xa5"

buf = mod.Buffer()
assert mod.write_str(buf, b"", mod.pinned_growth(buf)) == (2, 0)
assert buf.bytes() == b"\xa0"
assert buf.grow_requests == [(0, 1)]

buf = mod.Buffer(capacity=10, contents=b"0123456789")
mod.write_str(buf, b"hello", mod.pinned_growth(buf))
assert buf.bytes() == b"0123456789\xa5hello"
assert buf.grow_requests == [(10, 1)]

buf = mod.Buffer(capacity=4, contents=b"xyz")
mod.write_str(buf, b"a" * 0x100, mod.pinned_growth(buf))
assert buf.bytes()[:6] == b"xyz\xda\x01\x00"
assert (4, 2) in buf.grow_requests

buf = mod.Buffer(capacity=8)
payload = bytes(range(256)) * 2
mod.write_str(buf, payload, mod.pinned_growth(buf))
assert buf.bytes() == b"\xda\x02\x00" + payload
assert [r for r in buf.grow_requests if r[1] == len(payload)]

print("ALL CHECKS PASSED")
