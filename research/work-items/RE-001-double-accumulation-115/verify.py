#!/usr/bin/env python3
"""Verification for the RE-001 double-accumulation packet.

Run from the clone root:
  python3 research/work-items/RE-001-double-accumulation-115/verify.py

Checks, all against the real binary work/hl-node-115.bin:
  1. SHA-256 digest and its provenance/artifacts.json binding.
  2. MANIFEST.sha256 over every other packet file.
  3. Excerpt regeneration byte-for-byte from a fresh objdump run.
  4. Gate and extra instructions byte-for-byte vs fresh objdump and vs
     the raw binary bytes at file offset (displayed address - 0x1000).
  5. FDE ranges for the three windows, re-parsed from .eh_frame.
  6. Census site lists, recomputed by census.py, against records.json.
  7. The model tests (tests/test_double_accumulation_115.py) exit 0.

Prints ALL CHECKS PASSED on success, else raises.
"""
import hashlib
import importlib.util
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
    "main": (0x5F6C750, 0x5F6CB28, "main.txt"),
    "helper": (0x5F6B720, 0x5F6B736, "helper.txt"),
    "leaf": (0x5F6C740, 0x5F6C750, "leaf.txt"),
}
GATE = [0x5F6C765, 0x5F6C859, 0x5F6CA3D, 0x5F6B726, 0x5F6C744]
EXTRA = [0x5F6C7D4, 0x5F6C88E, 0x5F6C958]
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
            # Continuation of a wrapped instruction display.
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
        win = "main" if 0x5F6C750 <= addr < 0x5F6CB28 else (
            "helper" if 0x5F6B720 <= addr < 0x5F6B736 else "leaf")
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
        if found.get(start) != stop - start:
            fail("FDE range mismatch: " + name)
        rec = records["windows"][name]
        if int(rec["address"], 16) != start or int(rec["end"], 16) != stop:
            fail("records window mismatch: " + name)
    print("ok: frames")


def check_census():
    spec = importlib.util.spec_from_file_location(
        "packet_census", os.path.join(HERE, "census.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    data = open(BIN, "rb").read()
    records = json.load(open(os.path.join(HERE, "records.json")))
    for name, target in (("main", 0x5F6C750), ("helper", 0x5F6B720),
                         ("leaf", 0x5F6C740)):
        calls, tails = mod.scan_calls(data, target)
        rec = records["census"][name]
        if [hex(c) for c in calls] != rec["direct_calls"]:
            fail("census direct calls mismatch: " + name)
        if [hex(t) for t in tails] != rec["tail_jumps"]:
            fail("census tail jumps mismatch: " + name)
        if mod.scan_qwords(data, target) != []:
            fail("census qword hits for " + name)
        rel = mod.scan_rela(data, mod.RELA_OFF, mod.RELA_SIZE, target)
        rel += mod.scan_rela(data, mod.RELAPLT_OFF, mod.RELAPLT_SIZE, target)
        if rel != []:
            fail("census RELATIVE addends for " + name)
    print("ok: census")


def check_model_tests():
    proc = subprocess.run(
        [sys.executable, "tests/test_double_accumulation_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        fail("model tests failed")
    print("ok: model tests")


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_instructions()
    check_frames()
    check_census()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
