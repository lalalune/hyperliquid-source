#!/usr/bin/env python3
"""Verification for the RE-001 selector dispatch packet.

Run from the clone root:
  python3 research/work-items/RE-001-selector-dispatch-6a820-115/verify.py

Checks, all against the real binary work/hl-node-115.bin:
  1. SHA-256 digest and its provenance/artifacts.json binding.
  2. MANIFEST.sha256 over every other packet file.
  3. Excerpt regeneration byte-for-byte from a fresh objdump run.
  4. Gate and extra instructions byte-for-byte vs fresh objdump and vs
     the raw binary bytes at file offset (displayed address - 0x1000).
  5. FDE ranges for the windows, re-parsed from .eh_frame.
  6. Census site lists, recomputed by census.py, against records.json.
  7. The model tests (tests/test_selector_dispatch_6a820_115.py) exit 0.
  8. The Unicorn differential (differential.py), when the unicorn
     package is available; otherwise the step reports itself not run.

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
    "dispatch": (0x5F6A820, 0x5F6ABAC, "dispatch.txt"),
    "builder": (0x5EAA060, 0x5EAA10B, "builder.txt"),
    "find": (0x5F69D00, 0x5F69D31, "find.txt"),
    "thunk": (0x5D48410, 0x5D48428, "thunk.txt"),
}
GATE = {
    "dispatch": [0x5F6A84F, 0x5F6A858, 0x5F6A8B6, 0x5F6A8D4, 0x5F6A982,
                 0x5F6A9A4, 0x5F6A9B1, 0x5F6A9B9, 0x5F6A9FB, 0x5F6AA1A,
                 0x5F6AA1D, 0x5F6AA7C, 0x5F6AAFA, 0x5F6AB29, 0x5F6AB54,
                 0x5F6AB76, 0x5F6AB94],
    "builder": [0x5EAA066, 0x5EAA09F, 0x5EAA0CC, 0x5EAA101],
    "find": [0x5F69D1C, 0x5F69D26, 0x5F69D2A],
    "thunk": [0x5D48414, 0x5D48426],
}
EXTRA = {
    "dispatch": [0x5F6A83B, 0x5F6A83F, 0x5F6A8F8, 0x5F6A920, 0x5F6AA30,
                 0x5F6AA8C, 0x5F6ABA0],
    "builder": [0x5EAA079, 0x5EAA0A4],
    "find": [0x5F69D05, 0x5F69D21],
    "thunk": [0x5D48418, 0x5D4841B],
}
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
    total = 0
    for name in WINDOWS:
        for addr in GATE[name] + EXTRA[name]:
            got = by_window[name].get(addr)
            if not got:
                fail("gate instruction not parsed: %#x" % addr)
            raw = data[addr - 0x1000:addr - 0x1000 + len(got)]
            if raw != got:
                fail("instruction bytes mismatch vs raw binary: %#x" % addr)
            total += 1
    print("ok: %d gate + extra instructions byte-for-byte" % total)


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
    for name in WINDOWS:
        rec = records["census"][name]
        for field in ("direct_calls", "tail_jumps", "qword_file_offsets",
                      "relative_reloc_offsets"):
            want = sorted(int(x, 16) for x in rec[field])
            have = sorted(int(x, 16) for x in got.get((name, field), []))
            if want != have:
                fail("census mismatch: %s %s: %r != %r"
                     % (name, field, want, have))
    print("ok: census")


def check_tests():
    proc = subprocess.run(
        [sys.executable, "tests/test_selector_dispatch_6a820_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        fail("model tests failed:\n" + proc.stdout + proc.stderr)
    print("ok: model tests")


def check_differential():
    try:
        import unicorn  # noqa: F401
    except Exception:
        print("note: unicorn package unavailable; differential not run")
        return
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "differential.py")],
        capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        fail("differential failed:\n" + proc.stdout + proc.stderr)
    line = proc.stdout.strip().splitlines()[-1]
    print("ok: differential (%s)" % line)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_instructions()
    check_frames()
    check_census()
    check_tests()
    check_differential()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
