#!/usr/bin/env python3
"""Verification for the RE-001 need-score predicate packet.

Run from the clone root:
  python3 research/work-items/RE-001-need-score-predicate-115/verify.py

Checks, all against the real binary work/hl-node-115.bin:
  1. SHA-256 digest and its provenance/artifacts.json binding.
  2. MANIFEST.sha256 over every other packet file.
  3. Excerpt regeneration byte-for-byte from a fresh objdump run.
  4. Gate and extra instructions byte-for-byte vs fresh objdump and vs
     the raw binary bytes at file offset (displayed address - 0x1000).
  5. FDE ranges for the two windows, re-parsed from .eh_frame.
  6. Census site lists, recomputed by census.py, against records.json.
  7. The model tests (tests/test_need_score_predicate_115.py) exit 0.

Prints ALL CHECKS PASSED on success, else raises.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOWS = {
    "predicate": (0x5DBD6D0, 0x5DBD7B6, "predicate.txt"),
    "gate": (0x5F6B720, 0x5F6B736, "helper.txt"),
}
GATE = [0x5DBD6D4, 0x5DBD715, 0x5DBD78D, 0x5DBD770, 0x5F6B726]
EXTRA = [0x5DBD744, 0x5DBD77C, 0x5F6B72F]
EH_OFF, EH_SIZE = 0xCA6ED8, 0x77137C
ADDR_RE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")


def fail(msg):
    raise SystemExit("CHECK FAILED: " + msg)


def objdump(start, stop):
    proc = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT)
    return proc.stdout


def parse_bytes(text):
    """Displayed address -> instruction byte string from objdump text."""
    out, cur = {}, None
    for line in text.splitlines():
        m = ADDR_RE.match(line)
        if m:
            cur = int(m.group(1), 16)
            rest = m.group(2)
            parts = rest.split("\t")
            toks = [t for t in parts[0].split()
                    if len(t) == 2 and all(c in "0123456789abcdef" for c in t)]
            out[cur] = bytes.fromhex("".join(toks))
        elif cur is not None and "\t" in line:
            toks = [t for t in line.split("\t")[0].split()
                    if len(t) == 2 and all(c in "0123456789abcdef" for c in t)]
            if toks:
                out[cur] += bytes.fromhex("".join(toks))
    return out


def check_digest():
    h = hashlib.sha256(open(BIN, "rb").read()).hexdigest()
    if h != DIGEST:
        fail("binary digest mismatch: " + h)
    prov = json.load(open(os.path.join(ROOT, "provenance", "artifacts.json")))
    digests = [f.get("sha256") for f in prov.get("files", [])]
    if DIGEST not in digests:
        fail("digest not bound in provenance/artifacts.json")
    print("ok: digest + provenance")


def check_manifest():
    man = os.path.join(HERE, "MANIFEST.sha256")
    for line in open(man):
        want, _, rel = line.strip().partition("  ")
        if not rel:
            want, _, rel = line.strip().partition(" ")
        got = hashlib.sha256(open(os.path.join(HERE, rel), "rb").read()).hexdigest()
        if got != want:
            fail("manifest mismatch: " + rel)
    print("ok: manifest")


def check_excerpts():
    for name, (start, stop, fname) in WINDOWS.items():
        fresh = objdump(start, stop)
        kept = open(os.path.join(HERE, "excerpts", fname)).read()
        if fresh != kept:
            fail("excerpt regeneration mismatch: " + fname)
    print("ok: excerpts regenerate byte-for-byte")


def check_instructions():
    data = open(BIN, "rb").read()
    by_window = {}
    for name, (start, stop, _) in WINDOWS.items():
        by_window[name] = parse_bytes(objdump(start, stop))
    for addr in GATE + EXTRA:
        win = "predicate" if 0x5DBD6D0 <= addr < 0x5DBD7B6 else "gate"
        got = by_window[win].get(addr)
        if not got:
            fail("gate instruction not parsed: %#x" % addr)
        raw = data[addr - 0x1000:addr - 0x1000 + len(got)]
        if raw != got:
            fail("instruction bytes mismatch vs raw binary: %#x" % addr)
    print("ok: %d gate + %d extra instructions byte-for-byte"
          % (len(GATE), len(EXTRA)))


def check_frames():
    data = open(BIN, "rb").read()
    found = {}
    off, end = EH_OFF, EH_OFF + EH_SIZE
    while off + 4 <= end:
        ln = struct.unpack_from("<I", data, off)[0]
        if ln == 0:
            break
        total = 4 + ln
        cid = struct.unpack_from("<I", data, off + 4)[0]
        if cid != 0:
            init4, rng4 = struct.unpack_from("<ii", data, off + 8)
            found[(off + 8 + init4) & 0xFFFFFFFFFFFFFFFF] = rng4
        off += total
    records = json.load(open(os.path.join(HERE, "records.json")))
    for name, (start, stop, _) in WINDOWS.items():
        want_start = records["windows"]["gate" if name == "gate" else "predicate"]["start"]
        if int(want_start, 16) != start:
            fail("records start mismatch: " + name)
        if found.get(start) != stop - start:
            fail("FDE range mismatch: " + name)
    print("ok: FDE ranges")


def check_census():
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "census.py"), BIN],
        capture_output=True, text=True, check=True, cwd=ROOT)
    records = json.load(open(os.path.join(HERE, "records.json")))
    got = {}
    for line in proc.stdout.splitlines():
        m = re.match(r"(\w+) 0x[0-9a-f]+: (\w+)=(\[.*\])", line)
        if m:
            got[(m.group(1), m.group(2))] = json.loads(m.group(3).replace("'", '"'))
    for win, key in (("predicate", "predicate"), ("gate", "gate")):
        rec = records["census"][key]
        for field in ("direct_calls", "tail_jumps", "qword_file_offsets",
                      "relative_reloc_offsets"):
            want = sorted(int(x, 16) for x in rec[field]) if field in (
                "direct_calls", "tail_jumps") else rec[field]
            have = sorted(got.get((win, field), [])) if field in (
                "direct_calls", "tail_jumps") else got.get((win, field), [])
            if field in ("direct_calls", "tail_jumps"):
                have = sorted(int(x, 16) if isinstance(x, str) else x for x in have)
            if want != have:
                fail("census mismatch: %s %s: %r != %r" % (win, field, want, have))
    print("ok: census")


def check_tests():
    proc = subprocess.run(
        [sys.executable, "tests/test_need_score_predicate_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        fail("model tests failed:\n" + proc.stdout + proc.stderr)
    print("ok: model tests")


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_instructions()
    check_frames()
    check_census()
    check_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
