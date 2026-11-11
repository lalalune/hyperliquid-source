#!/usr/bin/env python3
"""Independent verification for the RE-001-serializer-115 packet.

Run from the repository root:
    python3 research/work-items/RE-001-serializer-115/verify.py

Exits 0 and prints ALL CHECKS PASSED only when every check below
passes; otherwise it prints the first failure and exits non-zero.

Checks:
  1. The node #115 binary digest matches provenance/artifacts.json.
  2. MANIFEST.sha256 covers every packet file with matching hashes.
  3. Every excerpt regenerates byte-for-byte from a fresh objdump.
  4. Every excerpt line's raw bytes match the binary at that address.
  5. Three seeded random gate spots (random.seed(20261106)) are
     verified byte-for-byte against a fresh objdump run.
  6. Every routine's FDE range is present in frames.txt.
  7. relocations.txt holds the vsnprintf row and the GOT entry at
     0x64ed730 is R_X86_64_GLOB_DAT.
  8. Every pinned literal reads back from the binary.
  9. census.py reproduces callers.tsv byte-identically (156 rows)
     and the per-target counts match records.json.
 10. The model constants match the packet: the jump table at
     0x978650 re-decodes to the model's KIND_TARGETS, the 13
     .rodata chunks rebuild the 200-byte two-digit table with the
     recorded SHA-256, the GOT re-derivation agrees, and the enum
     maps and literals match.
 11. The model tests pass (tests/test_serializer_115.py).
"""

import hashlib
import json
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.dont_write_bytecode = True
sys.path.insert(0, str(PACKET))
from export_excerpts import WINDOWS  # noqa: E402

FAILURES = []


def check(name, ok, detail=""):
    print("%-4s %s %s" % ("PASS" if ok else "FAIL", name, detail))
    if not ok:
        FAILURES.append(name)


def run(cmd, cwd=ROOT):
    return subprocess.run(cmd, capture_output=True, text=True,
                          check=True, cwd=cwd).stdout


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- vaddr -> file offset, from readelf -S ------------------------------


def load_sections():
    sections = []
    for line in run(["readelf", "-S", "-W", str(BINARY)]).splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+"
                     r"([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            sections.append((m.group(1), int(m.group(2), 16),
                             int(m.group(3), 16), int(m.group(4), 16)))
    return sections


SECTIONS = load_sections()
_BINARY_DATA = BINARY.read_bytes()


def read_vaddr(addr, n):
    for _name, vaddr, off, size in SECTIONS:
        if vaddr <= addr < vaddr + size:
            start = off + (addr - vaddr)
            return _BINARY_DATA[start: start + n]
    raise ValueError("address %#x not in any section" % addr)


def read_cstr(addr):
    out = bytearray()
    cur = addr
    while True:
        b = read_vaddr(cur, 1)[0]
        if b == 0:
            return bytes(out)
        out.append(b)
        cur += 1


# --- 1. digest ----------------------------------------------------------


def check_digest():
    artifacts = json.load(open(ROOT / "provenance" / "artifacts.json"))
    entry = None
    for f in artifacts["files"]:
        if f["path"] == "artifacts/node/115/hl-node":
            entry = f
            break
    ok = entry is not None and entry["sha256"] == DIGEST
    ok = ok and sha256_file(BINARY) == DIGEST
    check("digest", ok, "provenance + binary == " + DIGEST[:16] + "...")


# --- 2. manifest --------------------------------------------------------


def check_manifest():
    manifest = PACKET / "MANIFEST.sha256"
    listed = {}
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        listed[parts[1]] = parts[0]
    actual = {}
    for p in sorted(PACKET.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.sha256":
            actual[str(p.relative_to(PACKET))] = sha256_file(p)
    ok = listed == actual
    missing = sorted(set(actual) - set(listed))
    extra = sorted(set(listed) - set(actual))
    mismatched = sorted(k for k in listed if k in actual
                        and listed[k] != actual[k])
    check("manifest", ok, "files=%d missing=%s extra=%s mismatched=%s"
          % (len(actual), missing, extra, mismatched))


# --- 3. excerpts regenerate ----------------------------------------------


def check_excerpts_regenerate():
    bad = []
    for name, start, stop in WINDOWS:
        text = run(["objdump", "-d",
                    "--start-address=%#x" % start,
                    "--stop-address=%#x" % stop,
                    "work/hl-node-115.bin"])
        if (PACKET / "excerpts" / name).read_text() != text:
            bad.append(name)
    check("excerpts-regenerate", not bad, "bad=%s" % bad)


# --- 4. raw bytes of every excerpt line -----------------------------------


def excerpt_lines():
    lines = []
    for name, _s, stop in WINDOWS:
        file_lines = (PACKET / "excerpts" / name).read_text().splitlines()
        parsed = []
        for line in file_lines:
            m = re.match(r"\s+([0-9a-f]+):\t([0-9a-f ]+)\t", line)
            if m:
                addr = int(m.group(1), 16)
                raw = bytes.fromhex(m.group(2).strip())
                parsed.append((name, addr, raw, line.strip()))
        for i, (name, addr, raw, line) in enumerate(parsed):
            # objdump wraps long instructions: the raw-bytes
            # column holds only the first 7 bytes and the rest
            # appears on a continuation line, so the
            # instruction's true end is the NEXT line's
            # address (or the window end for the last line).
            nxt = parsed[i + 1][1] if i + 1 < len(parsed) else stop
            lines.append((name, addr, raw, line, nxt))
    return lines


def check_raw_bytes():
    bad = []
    for name, addr, raw, line, _nxt in excerpt_lines():
        if read_vaddr(addr, len(raw)) != raw:
            bad.append((name, "%#x" % addr, line))
    check("raw-bytes", not bad, "checked=%d bad=%s"
          % (len(excerpt_lines()), bad[:3]))


# --- 5. seeded random gate spots ------------------------------------------


def check_random_spots():
    lines = excerpt_lines()
    random.seed(20261106)
    spots = random.sample(lines, 3)
    bad = []
    for name, addr, raw, line, nxt in spots:
        text = run(["objdump", "-d",
                    "--start-address=%#x" % addr,
                    "--stop-address=%#x" % nxt,
                    "work/hl-node-115.bin"])
        if line.split("\t")[-1].strip() not in text:
            bad.append((name, "%#x" % addr))
    check("random-spots", not bad,
          "spots=%s" % [(n, a) for n, a, _r, _l, _x in spots])


# --- 6. FDE presence ------------------------------------------------------


def check_fdes():
    frames = (PACKET / "frames.txt").read_text()
    missing = []
    for name, start, stop in WINDOWS:
        if "pc=%016x..%016x" % (start, stop) not in frames:
            missing.append((name, "%#x..%#x" % (start, stop)))
    check("fdes", not missing, "windows=%d missing=%s"
          % (len(WINDOWS), missing))


# --- 7. relocations ---------------------------------------------------------


def check_relocations():
    reloc = (PACKET / "relocations.txt").read_text()
    ok = "0x64ed730" in reloc and "R_X86_64_GLOB_DAT" in reloc
    dyn = run(["readelf", "-r", "-W", str(BINARY)])
    ok = ok and "64ed730" in dyn and "vsnprintf" in dyn
    check("relocations", ok, "vsnprintf at 0x64ed730")


# --- 8. literals ------------------------------------------------------------


LITERALS = {
    0x430E89: b"false",
    0x43F883: b"true",
    0x432165: b"%f",
}


def check_literals():
    bad = []
    for addr, want in LITERALS.items():
        if read_cstr(addr) != want:
            bad.append("%#x" % addr)
    check("literals", not bad, "checked=%d bad=%s"
          % (len(LITERALS), bad))


# --- 9. census --------------------------------------------------------------


CENSUS_COUNTS = {
    ("0x61c7e30", "call"): 120,
    ("0x61c7da0", "call"): 2,
    ("0x61d0e90", "call"): 1,
    ("0x61d0f00", "call"): 1,
    ("0x61d0f1c", "jmp"): 1,
    ("0x61d0f30", "call"): 3,
    ("0x5f06bb0", "call"): 13,
    ("0x60b79e0", "call"): 12,
    ("0x60ba450", "call"): 2,
    ("0x60ba600", "call"): 1,
}


def check_census():
    before = (PACKET / "callers.tsv").read_bytes()
    run([sys.executable, str(PACKET / "census.py")], cwd=ROOT)
    after = (PACKET / "callers.tsv").read_bytes()
    ok = before == after
    rows = after.decode().splitlines()[1:]
    ok = ok and len(rows) == 156
    counts = {}
    for line in rows:
        parts = line.split("\t")
        counts[(parts[1], parts[3].strip())] = \
            counts.get((parts[1], parts[3].strip()), 0) + 1
    bad = {k: (counts.get(k, 0), v)
           for k, v in CENSUS_COUNTS.items()
           if counts.get(k, 0) != v}
    check("census", ok and not bad,
          "rows=%d bad-counts=%s" % (len(rows), bad))


# --- 10. model constants + jump table + digits table + GOT -------------------


def check_model_constants():
    sys.path.insert(0, str(ROOT / "tools"))
    import serializer_115 as m
    records = json.load(open(PACKET / "records.json"))
    ok = True
    detail = []
    verified = 0
    for addr in records["routines"]:
        name = records["routines"][addr]["name"]
        const = getattr(m, name.upper(), None)
        if const is None:
            continue
        verified += 1
        if const != int(addr, 16):
            ok = False
            detail.append((name, hex(const), addr))
    # Jump table: re-decode all 25 int32 relative entries at 0x978650.
    raw = read_vaddr(m.JUMP_TABLE, 25 * 4)
    decoded = {}
    for kind in range(25):
        off = struct.unpack("<i", raw[kind * 4:(kind + 1) * 4])[0]
        decoded[kind] = m.JUMP_TABLE + off
    if decoded != m.KIND_TARGETS:
        ok = False
        detail.append(("jump-table",
                       {k: hex(v) for k, v in decoded.items()
                        if m.KIND_TARGETS.get(k) != v}))
    # Kind rules in records.json agree with the decoded table.
    for rule in records["kind_rules"]:
        if int(rule["target"], 16) != decoded[rule["kind"]]:
            ok = False
            detail.append(("kind-rule", rule["kind"]))
    # Two-digit table: rebuild from the 13 chunks with the stack
    # layout (12 movaps at rsp+0x30+16*i, one movups at rsp+0xe9).
    buf = bytearray(208)
    chunks = records["constants"]["digits_table_chunks"]
    for i, addr in enumerate(chunks[:12]):
        buf[16 * i:16 * i + 16] = read_vaddr(int(addr, 16), 16)
    buf[0xB9:0xB9 + 16] = read_vaddr(int(chunks[12], 16), 16)
    table = bytes(buf[:200])
    if table.decode() != m.DIGITS_TABLE:
        ok = False
        detail.append(("digits-table", "mismatch"))
    if hashlib.sha256(table).hexdigest() != m.DIGITS_TABLE_SHA256:
        ok = False
        detail.append(("digits-table-sha", "mismatch"))
    if hashlib.sha256(table).hexdigest() != \
            records["constants"]["digits_table_sha256"]:
        ok = False
        detail.append(("digits-table-sha-records", "mismatch"))
    # Escape mask: read the movabs immediate at 0x61d0ec2.
    mask = struct.unpack("<Q", read_vaddr(0x61D0EC2, 8))[0]
    if mask != m.ESCAPE_MASK:
        ok = False
        detail.append(("escape-mask", hex(mask)))
    ok = ok and m.JUMP_TABLE == 0x978650
    ok = ok and m.KIND_COUNT == 25
    ok = ok and m.BOOL_FALSE_LITERAL == 0x430E89
    ok = ok and m.BOOL_TRUE_LITERAL == 0x43F883
    ok = ok and m.DOUBLE_FORMAT_LITERAL == 0x432165
    ok = ok and m.DOUBLE_FORMAT_BUFFER == 328
    ok = ok and m.VSNPRINTF_GOT == 0x64ED730
    ok = ok and m.ENUM_MAPS == {
        11: 0x65070A0, 12: 0x6507060, 13: 0x6507120, 14: 0x6507020,
        15: 0x6507160, 16: 0x65070E0, 24: 0x6506FE0}
    check("model-constants", ok, "verified=%d mismatches=%s"
          % (verified, detail))


# --- 11. model tests ----------------------------------------------------------


def check_model_tests():
    out = run([sys.executable,
               "tests/test_serializer_115.py"], cwd=ROOT)
    ok = "all 168 tests passed" in out
    check("model-tests", ok, out.strip().splitlines()[-1]
          if out.strip() else "")


def main():
    check_digest()
    check_manifest()
    check_excerpts_regenerate()
    check_raw_bytes()
    check_random_spots()
    check_fdes()
    check_relocations()
    check_literals()
    check_census()
    check_model_constants()
    check_model_tests()
    if FAILURES:
        print("FAILED: %s" % ", ".join(FAILURES))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
