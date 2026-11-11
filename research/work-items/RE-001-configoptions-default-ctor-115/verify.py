"""Checker for RE-001-configoptions-default-ctor-115.

Run from the repository root:
    python3 research/work-items/RE-001-configoptions-default-ctor-115/verify.py

Checks, in order:
  1. artifact digest against provenance/artifacts.json
  2. MANIFEST.sha256 entries (hash + exactly two spaces + name)
  3. excerpt regeneration against a fresh objdump run (relative binary path)
  4. fixed samples + 3 seeded random gate spots byte-for-byte against fresh
     objdump AND the raw binary (vaddr -> file offset via PT_LOAD segments)
  5. FDE ranges in frames.txt against a fresh objdump --dwarf=frames run
  6. census reproduction (9 ctor calls, 44 dtor calls, 1 NewInstance call)
  7. model constants (defaults, nine sites, site call sites == census)
  8. relocation records against a fresh readelf -r run
  9. data literals against the raw binary
 10. the model test suite passes
"""

import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
BIN_ABS = os.path.join(ROOT, BIN)

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("ctor-60bb890.objdump.txt", 0x60BB890, 0x60BB932),
    ("dtor-5e33fb0.objdump.txt", 0x5E33FB0, 0x5E33FEA),
    ("landing-60bb856.objdump.txt", 0x60BB856, 0x60BB88A),
    ("newinstance-61f9400.objdump.txt", 0x61F9400, 0x61F963E),
    ("setoptions-5d8ea70.objdump.txt", 0x5D8EA70, 0x5D8F4B5),
    ("write-5e34010.objdump.txt", 0x5E34010, 0x5E34108),
    ("read-5e34160.objdump.txt", 0x5E34160, 0x5E347C1),
    ("addcipher-5ffabd0.objdump.txt", 0x5FFABD0, 0x5FFAE04),
    ("getmutable-60a1d60.objdump.txt", 0x60A1D60, 0x60A1F03),
    ("mutableeq-60a2080.objdump.txt", 0x60A2080, 0x60A2357),
    ("persist-60d4a00.objdump.txt", 0x60D4A00, 0x60D4B7E),
    ("bbtopen-611fb10.objdump.txt", 0x611FB10, 0x61213DB),
    ("asstring-61c8370.objdump.txt", 0x61C8370, 0x61C84FA),
    ("setoptions-helper-60c4550.objdump.txt", 0x60C4550, 0x60C46B8),
    ("persist-copy-60d2820.objdump.txt", 0x60D2820, 0x60D290F),
]

# (vaddr, instruction bytes) pinned by direct reads of the excerpts.
FIXED_SAMPLES = [
    (0x60BB890, bytes.fromhex("f30f1efa")),          # ctor endbr64
    (0x60BB8B1, bytes.fromhex("c70700010101")),       # movl $0x1010100,(%rdi)
    (0x60BB8DB, bytes.fromhex("48c7473000000800")),   # movq $0x80000,0x30(%rdi)
    (0x5E33FB0, bytes.fromhex("f30f1efa")),          # dtor endbr64
    (0x61F9463, bytes.fromhex("488d1586fa2d00")),     # lea 0x64d8ef0,%rdx
    (0x5E34467, bytes.fromhex("c644245001")),        # Read: movb $0x1,0x50(%rsp)
]

FAILS = []


def fail(msg):
    FAILS.append(msg)
    print("FAIL:", msg)


def segments(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr = struct.unpack_from("<IIQQ", data, off)
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        if p_type == 1:
            segs.append((p_offset, p_vaddr, p_filesz))
    return segs


def v2o(segs, vaddr):
    for p_offset, p_vaddr, p_filesz in segs:
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


def objdump(args):
    return subprocess.run(["objdump"] + args + [BIN], cwd=ROOT,
                          capture_output=True, text=True, check=True).stdout


def parse_excerpt(path):
    """(vaddr, bytes) pairs from one objdump excerpt file.

    Long instructions wrap: the continuation line carries an address but
    no mnemonic, so its bytes are appended to the previous instruction.
    """
    out = []
    line_re = re.compile(r"^\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)(.*)$")
    for line in open(path):
        m = line_re.match(line)
        if not m:
            continue
        b = bytes.fromhex(m.group(2).replace(" ", ""))
        if m.group(3).strip() == "":
            if out:
                prev_addr, prev_bytes = out[-1]
                out[-1] = (prev_addr, prev_bytes + b)
            continue
        out.append((int(m.group(1), 16), b))
    return out


def main():
    data = open(BIN_ABS, "rb").read()
    segs = segments(data)

    # 1. artifact digest
    art = json.load(open(os.path.join(ROOT, "provenance", "artifacts.json")))
    want = None
    for a in art.get("files", []):
        if a.get("path") == "artifacts/node/115/hl-node":
            want = a.get("sha256")
    if want != DIGEST:
        fail("provenance digest mismatch: %r" % want)
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("binary digest mismatch")

    # 2. manifest
    manifest = open(os.path.join(HERE, "MANIFEST.sha256")).read().splitlines()
    for line in manifest:
        if not line.strip():
            continue
        m = re.match(r"^([0-9a-f]{64})  (.+)$", line)
        if not m:
            fail("manifest line malformed: %r" % line)
            continue
        path = os.path.join(HERE, m.group(2))
        if not os.path.exists(path):
            fail("manifest file missing: " + m.group(2))
            continue
        actual = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if actual != m.group(1):
            fail("manifest hash mismatch: " + m.group(2))

    # 3. excerpt regeneration
    for name, start, stop in WINDOWS:
        fresh = objdump(["-d", "--start-address=" + hex(start),
                         "--stop-address=" + hex(stop)])
        saved = open(os.path.join(HERE, name)).read()
        if fresh != saved:
            fail("excerpt mismatch on regeneration: " + name)

    # 4. fixed samples + seeded random gate spots vs objdump AND raw binary
    excerpts = []
    for name, _s, _e in WINDOWS:
        excerpts += parse_excerpt(os.path.join(HERE, name))
    by_addr = dict(excerpts)
    samples = list(FIXED_SAMPLES)
    rng = random.Random(115)
    picks = rng.sample(excerpts, 3)
    samples += [(a, b) for a, b in picks]
    for vaddr, expect in samples:
        off = v2o(segs, vaddr)
        if off is None:
            fail("no file offset for %#x" % vaddr)
            continue
        if data[off:off + len(expect)] != expect:
            fail("raw binary mismatch at %#x" % vaddr)
        if by_addr.get(vaddr) != expect:
            fail("excerpt mismatch at %#x" % vaddr)
    print("gate spots: " + ", ".join(hex(a) for a, _b in picks))

    # 5. FDE ranges
    frames = objdump(["--dwarf=frames"])
    fdes = {}
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", frames):
        fdes[int(m.group(1), 16)] = int(m.group(2), 16)
    for name, start, stop in WINDOWS:
        if fdes.get(start) != stop:
            # persist-copy is a bounded prologue, not a whole function.
            if name == "persist-copy-60d2820.objdump.txt":
                if not (start in fdes and stop <= fdes[start]):
                    fail("persist-copy prologue outside its FDE")
            else:
                fail("FDE mismatch for %s: %#x..%#x" % (name, start, stop))
    if fdes.get(0x60BB856) != 0x60BB88A:
        fail("landing-pad FDE mismatch")

    # 6. census reproduction
    sys.path.insert(0, HERE)
    import census as C
    calls, tails, hits, _slots = C.scan()
    if len(calls[C.CTOR]) != 9:
        fail("ctor calls != 9: %d" % len(calls[C.CTOR]))
    if len(calls[C.DTOR]) != 44:
        fail("dtor calls != 44: %d" % len(calls[C.DTOR]))
    if len(calls[C.NEWINSTANCE]) != 1:
        fail("NewInstance calls != 1: %d" % len(calls[C.NEWINSTANCE]))
    if any(tails.values()) or any(hits.values()):
        fail("unexpected tail jumps or qword hits")

    # 7. model constants
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import configoptions_default_ctor_115 as model
    if model.FLAG_DEFAULTS != (0, 1, 1, 1, 0):
        fail("model flag defaults wrong")
    if model.DELIMITER_DEFAULT != ";":
        fail("model delimiter default wrong")
    if model.SCALAR30_DEFAULT != 0x80000:
        fail("model scalar30 default wrong")
    if len(model.SITES) != 9:
        fail("model sites != 9")
    if sorted(s for s, *_r in model.SITES) != sorted(hex(c) for c in calls[C.CTOR]):
        fail("model site call sites != census ctor calls")

    # 8. relocation records
    relocs = subprocess.run(["readelf", "-r", BIN_ABS], capture_output=True,
                            text=True, check=True).stdout
    for want_line in (
            "0000064d8f00  000000000008 R_X86_64_RELATIVE                    61f8130",
            "0000064ed290  00f800000006 R_X86_64_GLOB_DAT 0000000000000000 "
            "__libc_single_threaded@GLIBC_2.32 + 0",
            "0000064ed818  016600000012 R_X86_64_TPOFF64  0000000000000000 "
            "_ZSt15__once_callable@GLIBCXX_3.4.11 + 0",
            "0000064ed820  016700000012 R_X86_64_TPOFF64  0000000000000000 "
            "_ZSt11__once_call@GLIBCXX_3.4.11 + 0",
            "0000064ed828  016800000006 R_X86_64_GLOB_DAT 0000000000000000 "
            "__once_proxy@GLIBCXX_3.4.11 + 0"):
        if want_line not in relocs:
            fail("relocation record missing: " + want_line[:40])

    # 9. data literals
    off = v2o(segs, 0x459B20)
    if off is None or data[off:off + 8] != struct.pack("<Q", 0x100000001):
        fail("packed counts literal at 0x459b20 wrong")
    off = v2o(segs, 0x43D5C7)
    if off is None or data[off:off + 1] != b";":
        fail("delimiter literal at 0x43d5c7 wrong")
    off = v2o(segs, 0x446696)
    if off is None or data[off:off + 3] != b"\n  ":
        fail("persist delimiter literal at 0x446696 wrong")
    off = v2o(segs, 0x4541E0)
    if off is None or data[off:off + 16] != b"MutableDBOptions":
        fail("MutableDBOptions literal at 0x4541e0 wrong")

    # 10. model tests
    out = subprocess.run([sys.executable,
                          os.path.join(ROOT, "tests",
                                       "test_configoptions_default_ctor_115.py")],
                         capture_output=True, text=True)
    if out.returncode != 0 or "tests passed" not in out.stdout:
        fail("model tests failed: " + out.stdout + out.stderr)

    if FAILS:
        print("%d CHECK(S) FAILED" % len(FAILS))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
