#!/usr/bin/env python3
"""Verification for the RE-001 bisect leaf packet.

Run from the clone root:
  python3 research/work-items/RE-001-bisect-leaf-115/verify.py

Checks, all against the real binary work/hl-node-115.bin:
  1. SHA-256 digest and its provenance/artifacts.json binding.
  2. MANIFEST.sha256 over every other packet file.
  3. Excerpt regeneration byte-for-byte from a fresh objdump run.
  4. Gate and extra instructions byte-for-byte vs fresh objdump and vs
     the raw binary bytes at file offset (displayed address - 0x1000).
  5. FDE range for the window, re-parsed from .eh_frame.
  6. Census site lists, recomputed by census.py, against records.json.
  7. The model tests (tests/test_bisect_leaf_115.py) exit 0.

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
    "bisect": (0x5F6BBA0, 0x5F6BC0A, "bisect.txt"),
}
GATE = [0x5F6BBA4, 0x5F6BBB8, 0x5F6BBC8, 0x5F6BBDE, 0x5F6BC00]
EXTRA = [0x5F6BBBF, 0x5F6BBE6, 0x5F6BBF3]
EH_OFF, EH_SIZE = 0xCA6ED8, 0x77137C
ADDR_RE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")


def fail(msg):
    raise SystemExit("CHECK FAILED: " + msg)


def check_digest():
    data = open(BIN, "rb").read()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")
    prov = json.load(open(os.path.join(ROOT, "provenance", "artifacts.json")))
    bound = any(f.get("sha256") == DIGEST for f in prov["files"])
    if not bound:
        fail("digest not bound in provenance/artifacts.json")
    print("ok: digest + provenance")


def check_manifest():
    manifest = os.path.join(HERE, "MANIFEST.sha256")
    for line in open(manifest):
        want, name = line.split(None, 1)
        name = name.strip()
        path = os.path.join(HERE, name)
        got = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if got != want:
            fail("manifest mismatch: " + name)
    print("ok: manifest")


def objdump(start, stop):
    proc = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT)
    return proc.stdout


def check_excerpts():
    for name, (start, stop, fname) in WINDOWS.items():
        kept = open(os.path.join(HERE, "excerpts", fname)).read()
        fresh = objdump(start, stop)
        if fresh != kept:
            fail("excerpt regeneration mismatch: " + fname)
    print("ok: excerpts regenerate byte-for-byte")


def parse_bytes(text):
    """Displayed address -> instruction byte string from objdump text."""
    out, cur = {}, None
    for line in text.splitlines():
        m = ADDR_RE.match(line)
        if m:
            cur = int(m.group(1), 16)
            rest = m.group(2)
            parts = rest.split("\t")
            hexpart = parts[0].strip()
            if re.fullmatch(r"[0-9a-f ]+", hexpart):
                out[cur] = bytes.fromhex(hexpart.replace(" ", ""))
            else:
                out[cur] = b""
        elif cur is not None and line.strip():
            mm = re.match(r"^\s*[0-9a-f]+:\t([0-9a-f ]+)$", line)
            if mm:
                out[cur] += bytes.fromhex(mm.group(1).replace(" ", ""))
    return out


def check_instructions():
    data = open(BIN, "rb").read()
    by_window = {}
    for name, (start, stop, _) in WINDOWS.items():
        by_window[name] = parse_bytes(objdump(start, stop))
    for addr in GATE + EXTRA:
        got = by_window["bisect"].get(addr)
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
        want_start = records["windows"][name]["start"]
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
        m = re.match(r"(\w+) 0x[0-9a-f]+: (.*)$", line)
        if not m:
            continue
        for field, val in re.findall(r"(\w+)=(\[[^\]]*\])", m.group(2)):
            got[(m.group(1), field)] = json.loads(val.replace("'", '"'))
    rec = records["census"]["bisect"]
    for field in ("direct_calls", "tail_jumps", "qword_file_offsets",
                  "relative_reloc_offsets"):
        want = rec[field]
        have = got.get(("bisect", field), [])
        if field in ("direct_calls", "tail_jumps"):
            want = sorted(int(x, 16) for x in want)
            have = sorted(int(x, 16) if isinstance(x, str) else x
                          for x in have)
        if want != have:
            fail("census mismatch: pass %s: %r != %r" % (field, want, have))
    print("ok: census")


def check_tests():
    proc = subprocess.run(
        [sys.executable, "tests/test_bisect_leaf_115.py"],
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
