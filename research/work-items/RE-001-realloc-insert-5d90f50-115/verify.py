#!/usr/bin/env python3
"""Self-verifying provenance for the realloc-insert packet.

Re-derives, from the digest-verified work binary alone: the FDE
ranges for both windows, the byte-exact instruction matches at the
recorded gate / extra sites, the whole-.text direct-call census,
the twin-copy body difference count, the model unit tests, and the
Unicorn differential (that step reports itself skipped when unicorn
is not importable, so this script stays portable; rerun it with a
unicorn-capable interpreter to include the differential). Exit
status 0 only when every check passes.
"""

import hashlib
import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, HERE)

BIN = os.path.join(ROOT, "work", "hl-node-115.bin")
EXPECT = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

GROW = (0x5D90F50, 0x5D910D5)
CALLER = (0x5F13E00, 0x5F13E93)
TWIN = (0x5D9EE20, 0x5D9EFA5)
TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
TEXT_END_VA = 0x63F1BA0

GATE = {
    "grow": {
        0x5D90F50: "f30f1efa",          # endbr64
        0x5D90F83: "0f8440010000",      # je length-error arm
        0x5D91021: "e8aafd6500",        # call operator new
        0x5D910D0: "e80bfd6500",        # call __throw_length_error
    },
    "caller": {
        0x5F13E00: "f30f1efa",          # endbr64
        0x5F13E64: "483b4660",          # cmp 0x60(%rsi),%rax (caller capacity test)
        0x5F13E8C: "e8bfd0e7ff",        # call grow (helper invocation)
    },
}
EXTRA = {
    "grow": {
        0x5D90F9E: "488d0c00",          # lea (%rax,%rax,1),%rcx (doubling)
        0x5D91042: "e829fa6500",        # call memmove
        0x5D9105D: "e81efd6500",        # call operator delete(sized)
        0x5D9109F: "e8bcf96500",        # call memcpy (suffix arm)
    },
    "caller": {
        0x5F13E42: "48891cc2",          # mov %rbx,(%rdx,%rax,8) inline append
        0x5F13E80: "488d7e50",          # lea 0x50(%rsi),%rdi (vector address)
    },
}


def ok(cond, msg):
    if not cond:
        raise SystemExit("FAIL: " + msg)
    print("ok:", msg)


def at(data, va, n=16):
    return data[TEXT_OFF + (va - TEXT_VA):TEXT_OFF + (va - TEXT_VA) + n]


def main():
    data = open(BIN, "rb").read()
    ok(hashlib.sha256(data).hexdigest() == EXPECT, "binary sha256")

    for line in open(os.path.join(HERE, "MANIFEST.sha256")):
        digest, _, name = line.strip().partition("  ")
        got = hashlib.sha256(open(os.path.join(HERE, name), "rb").read()).hexdigest()
        ok(got == digest, "manifest " + name)

    before = {n: open(os.path.join(HERE, "excerpts", n), "rb").read()
              for n in ("grow.txt", "caller.txt")}
    regen = subprocess.run([sys.executable, os.path.join(HERE, "export_excerpts.py")],
                           capture_output=True, text=True, cwd=ROOT)
    ok(regen.returncode == 0, "excerpt regeneration ran")
    for name, blob in before.items():
        ok(open(os.path.join(HERE, "excerpts", name), "rb").read() == blob,
           "excerpt regeneration byte-identical " + name)

    frames = open(os.path.join(HERE, "frames.txt")).read()
    ok("0x5d90f50..0x5d910d5 (389 bytes)" in frames
       and "0x5f13e00..0x5f13e93 (147 bytes)" in frames,
       "frames.txt records both window ranges")
    reloc = open(os.path.join(HERE, "relocations.txt")).read()
    ok("no R_X86_64_RELATIVE record carries it as addend" in reloc,
       "relocations.txt records the census result")

    for section in (GATE, EXTRA):
        for window, sites in section.items():
            for va, hexbytes in sites.items():
                want = bytes.fromhex(hexbytes)
                ok(at(data, va, len(want)) == want,
                   "%s bytes at %#x" % (window, va))

    # FDE re-parse for both windows (.eh_frame file offset == VA in
    # the first PT_LOAD, so the pcrel key is off + 8 + initial_location)
    rec = json.load(open(os.path.join(HERE, "records.json")))
    EH_OFF, EH_SIZE = 0xCA6ED8, 0x77137C
    found = {}
    off, end = EH_OFF, EH_OFF + EH_SIZE
    while off + 4 <= end:
        (ln,) = struct.unpack_from("<I", data, off)
        if ln == 0:
            break
        (cid,) = struct.unpack_from("<I", data, off + 4)
        if cid != 0:
            init4, rng4 = struct.unpack_from("<iI", data, off + 8)
            key = (off + 8 + init4) & 0xFFFFFFFFFFFFFFFF
            # augmentation length byte 0 -> no LSDA pointer stored
            found[key] = (rng4, "0x%x" % off, "0x%x" % ln, data[off + 16])
        off += 4 + ln
    for name, win in (("grow", GROW), ("caller", CALLER)):
        r, o, l, auglen = found[win[0]]
        w = rec["windows"][name]
        ok(r == win[1] - win[0] and o == w["fde_file_offset"]
           and l == w["fde_length_field"] and auglen == 0
           and w["lsda"] is None,
           "FDE re-parse " + name)

    # census re-derivation
    from census import (RELA_OFF, RELA_SIZE, RELAPLT_OFF, RELAPLT_SIZE,
                        scan_calls, scan_qwords, scan_rela)
    for name, win in (("grow", GROW), ("caller", CALLER)):
        calls, tails = scan_calls(data, win[0])
        qwords = scan_qwords(data, win[0])
        rela = (scan_rela(data, RELA_OFF, RELA_SIZE, win[0])
                + scan_rela(data, RELAPLT_OFF, RELAPLT_SIZE, win[0]))
        want = rec["census"][name]
        ok([hex(x) for x in calls] == want["direct_calls"]
           and [hex(x) for x in tails] == want["tail_jumps"]
           and qwords == [] and rela == [],
           "census re-derivation " + name)

    # twin body difference: 15 bytes, all inside call rel32 fields
    a = at(data, GROW[0], GROW[1] - GROW[0])
    b = at(data, TWIN[0], TWIN[1] - TWIN[0])
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    ok(len(diffs) == 15, "twin body differs in exactly 15 bytes")
    spans = [(0x8F, 0x92), (0xD2, 0xD5), (0xF3, 0xF6), (0x10E, 0x111),
             (0x150, 0x153), (0x17C, 0x180), (0x181, 0x184)]
    ok(all(any(lo <= i < hi for lo, hi in spans) for i in diffs),
       "all twin differences lie inside call rel32 fields")

    out = subprocess.run([sys.executable, os.path.join(
        ROOT, "tests", "test_realloc_insert_5d90f50_115.py")],
        capture_output=True, text=True)
    ok(out.returncode == 0 and "checks passed" in out.stdout,
       "model unit tests pass")

    try:
        import unicorn  # noqa: F401
    except ImportError:
        print("note: differential step skipped (rerun verify.py with "
              "a unicorn-capable python)")
    else:
        out = subprocess.run(
            [sys.executable, os.path.join(HERE, "differential.py")],
            capture_output=True, text=True)
        ok(out.returncode == 0 and "0 mismatches" in out.stdout,
           "unicorn differential passes (%s)"
           % out.stdout.strip().splitlines()[-1])

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
