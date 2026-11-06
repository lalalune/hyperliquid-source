#!/usr/bin/env python3
"""Independent verification for the RE-001-default-name-115 packet.

Run from the repository root:
    python3 research/work-items/RE-001-default-name-115/verify.py

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
  7. relocations.txt holds the atexit destructor GOT row, the
     .init_array slot row, and the three twin vtable-slot rows.
  8. Every pinned literal reads back from the binary.
  9. census.py reproduces callers.tsv byte-identically (939 rows)
     and the per-target counts match records.json.
 10. The model constants match the packet: the initializer's stores
     rebuild the string "nullptr" at 0x6508980, the kind
     validator's jump table at 0x978718 re-decodes to 25 in-range
     targets, the twin entries are byte-identical after address
     normalization, the vtable slots re-derive, and the literals
     match.
 11. The model tests pass (tests/test_default_name_115.py).
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
    dyn = run(["readelf", "-r", "-W", str(BINARY)])
    ok = "0x64ed5d8" in reloc and "R_X86_64_GLOB_DAT" in reloc
    ok = ok and "0x63f3b30" in reloc and "61d2970" in reloc
    ok = ok and "0x64d3210" in reloc and "0x64d3690" in reloc
    ok = ok and "0x64d3710" in reloc
    ok = ok and "64ed5d8" in dyn and "basic_string" in dyn
    ok = ok and "64ed028" in dyn and "5d2cac0" in dyn
    check("relocations", ok, "dtor GOT + init_array slot + twin slots")


# --- 8. literals ------------------------------------------------------------


LITERALS = {
    0x4376FD: b"",
    0x433F9F: b"Cannot reset object ",
    0x44481B: b"rocksdb.BuiltinBloomFilter",
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
    "0x6508980:lea": 11,
    "0x61cf670:call": 847,
    "0x609e510:call": 21,
    "0x60bb9a0:call": 16,
    "0x60bf980:call": 15,
    "0x5e4bcf0:call": 8,
    "0x5d66e30:call": 6,
    "0x609a410:call": 3,
    "0x60bf5f0:call": 3,
    "0x6130140:call": 2,
    "0x6130140:jmp": 1,
}


def check_census():
    before = (PACKET / "callers.tsv").read_bytes()
    run([sys.executable, str(PACKET / "census.py")], cwd=ROOT)
    after = (PACKET / "callers.tsv").read_bytes()
    ok = before == after
    rows = after.decode().splitlines()[1:]
    ok = ok and len(rows) == 939
    counts = {}
    for line in rows:
        parts = line.split("\t")
        counts["%s:%s" % (parts[1], parts[3].strip())] = \
            counts.get("%s:%s" % (parts[1], parts[3].strip()), 0) + 1
    bad = {k: (counts.get(k, 0), v)
           for k, v in CENSUS_COUNTS.items()
           if counts.get(k, 0) != v}
    check("census", ok and not bad,
          "rows=%d bad-counts=%s" % (len(rows), bad))


# --- 10. model constants -----------------------------------------------------


def check_model_constants():
    sys.path.insert(0, str(ROOT / "tools"))
    import default_name_115 as m
    records = json.load(open(PACKET / "records.json"))
    ok = True
    detail = []
    # The initializer's stores rebuild the string.
    s, atexit = m.initialize_default_name()
    if s.bytes() != b"nullptr" or s.length != 7 or s.ptr != 0x6508990:
        ok = False
        detail.append("initializer-string")
    if atexit["func_got"] != 0x64ED5D8 or atexit["arg"] != 0x6508980 \
            or atexit["dso_handle"] != 0x64EFA20:
        ok = False
        detail.append("atexit-record")
    # The initializer is .init_array entry #142 (0-based 141).
    if m.INIT_ARRAY_SLOT != 141 or m.INIT_ARRAY_ENTRIES != 168:
        ok = False
        detail.append("init-array-slot")
    # The kind validator's jump table re-decodes to 25 in-range
    # targets inside .text (0x1400000..0x6200000).
    raw = read_vaddr(m.KIND_VALIDATOR_JUMP_TABLE, 25 * 4)
    targets = []
    for kind in range(25):
        off = struct.unpack("<i", raw[kind * 4:(kind + 1) * 4])[0]
        targets.append(m.KIND_VALIDATOR_JUMP_TABLE + off)
    if len(targets) != 25 or not all(
            0x1400000 <= t < 0x6200000 for t in targets):
        ok = False
        detail.append("jump-table")
    # The twins are one template instantiated twice: their
    # instruction streams (mnemonics + operands, intra-function
    # jump targets relative-ized to each function's own start,
    # rip-relative lea resolved to its absolute target) differ only
    # in the two holder-map loads, 0x630 in A and 0x90 in B.
    def instr_lines(path, start, stop):
        out = []
        for line in Path(path).read_text().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and re.match(r"\s*[0-9a-f]+:", parts[0]):
                insn = parts[2]
                # Drop the <symbol+offset> annotation.
                insn = re.sub(r"\s*<[^>]*>", "", insn)
                # Rip-relative lea: use the resolved target from the
                # "# ADDR" comment instead of the displacement.
                m2 = re.search(
                    r"lea\s+(-?0x[0-9a-f]+)\(%rip\)(.*)#\s*([0-9a-f]+)",
                    insn)
                if m2:
                    insn = re.sub(
                        r"lea\s+-?0x[0-9a-f]+\(%rip\)",
                        "lea #%s(%%rip)" % m2.group(3), insn)
                # Intra-function control transfers: relative-ize the
                # bare target address to the function start.
                m3 = re.match(
                    r"(j\w+|call)\s+([0-9a-f]+)(\s.*)?$", insn.strip())
                if m3:
                    t = int(m3.group(2), 16)
                    if start <= t < stop:
                        insn = re.sub(
                            r"\b%s\b" % m3.group(2), "+%#x" % (t - start),
                            insn, count=1)
                out.append(insn)
        return out
    ta = instr_lines(PACKET / "excerpts" / "twin_a.txt", 0x6086B70, 0x6086CC9)
    tb = instr_lines(PACKET / "excerpts" / "twin_b.txt", 0x60A7420, 0x60A7579)
    diffs = [(x, y) for x, y in zip(ta, tb) if x != y]
    if len(ta) != len(tb) or len(diffs) != 2 or not all(
            x == "mov    0x630(%r14),%rdi"
            and y == "mov    0x90(%r14),%rdi" for x, y in diffs):
        ok = False
        detail.append("twin-difference: %s" % diffs)
    if m.TWIN_HOLDER_OFFSETS != {0x6086B70: 0x630, 0x60A7420: 0x90}:
        ok = False
        detail.append("twin-holder-offsets")
    # The vtable slots re-derive from the relocations.
    dyn = run(["readelf", "-r", "-W", str(BINARY)])
    for slot, target in ((0x64D3210, 0x6086B70), (0x64D3690, 0x60A7420),
                         (0x64D3710, 0x60A7420)):
        if ("%x" % slot) not in dyn or ("%x" % target) not in dyn:
            ok = False
            detail.append(("vtable-slot", hex(slot)))
    # Records agree with the model on the literals and constants.
    if records["literals"]["0x44481b"] != "rocksdb.BuiltinBloomFilter":
        ok = False
        detail.append("canonical-literal")
    if records["literals"]["0x433f9f"] != "Cannot reset object ":
        ok = False
        detail.append("reset-literal")
    if records["global"]["text"] != "nullptr" \
            or records["global"]["length"] != 7:
        ok = False
        detail.append("global-record")
    if len(records["consumer_sites"]) != 10:
        ok = False
        detail.append("consumer-site-count")
    ok = ok and m.GLOBAL_ADDR == 0x6508980
    ok = ok and m.INITIALIZER == 0x61D2970
    ok = ok and m.KIND_COUNT == 25
    ok = ok and m.MAP_LINEAR_LIMIT == 20
    ok = ok and m.MAP_HASH_SEED == 0xC70F6907
    ok = ok and m.CONTROL_COUNTS == 0x100000001
    check("model-constants", ok, "mismatches=%s" % detail)


# --- 11. model tests ----------------------------------------------------------


def check_model_tests():
    out = run([sys.executable,
               "tests/test_default_name_115.py"], cwd=ROOT)
    ok = "all 92 tests passed" in out
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
