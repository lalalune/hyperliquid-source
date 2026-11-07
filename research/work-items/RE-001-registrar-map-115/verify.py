"""Checker for RE-001-registrar-map-115.

Run from the repository root:
    python3 research/work-items/RE-001-registrar-map-115/verify.py

Checks, in order:
  1. artifact digest against provenance/artifacts.json
  2. MANIFEST.sha256 entries (hash + exactly two spaces + name)
  3. excerpt regeneration against a fresh objdump run (relative binary path)
  4. fixed samples + 3 seeded random gate spots byte-for-byte against fresh
     objdump AND the raw binary (vaddr -> file offset via PT_LOAD segments)
  5. FDE ranges in frames.txt against a fresh objdump --dwarf=frames run
  6. census reproduction (12 string-helper calls, 1 ctor call, 3 getter
     calls, 0 static-init/map-dtor calls, 2 map lea sites, 0 qwords for
     the map, 1 qword for the static init)
  7. model constants (map/node sizes, SSO limit, literals, FDE ranges,
     census constants)
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
    ("static-init-620b470.objdump.txt", 0x620B470, 0x620B57D),
    ("string-assign-5f204e0.objdump.txt", 0x5F204E0, 0x5F205C3),
    ("map-dtor-620a500.objdump.txt", 0x620A500, 0x620A5BD),
    ("ctor-61f91b0.objdump.txt", 0x61F91B0, 0x61F9277),
]

# (vaddr, instruction bytes) pinned by direct reads of the excerpts.
FIXED_SAMPLES = [
    (0x620B470, bytes.fromhex("f30f1efa")),          # static init endbr64
    (0x620B516, bytes.fromhex("488d3523e02f00")),    # lea map 0x6509540,%rsi
    (0x620B540, bytes.fromhex("c746200000803f")),    # movl $0x3f800000,0x20(%rsi)
    (0x620A557, bytes.fromhex("be50000000")),        # mov $0x50,%esi (node size)
    (0x61F9234, bytes.fromhex("488d0505033100")),    # lea map 0x6509540,%rax
    (0x5F204E0, bytes.fromhex("f30f1efa")),          # string helper endbr64
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
            fail("FDE mismatch for %s: %#x..%#x" % (name, start, stop))
    if fdes.get(0x61F92B0) != 0x61F93C5:
        fail("getter FDE mismatch")

    # 6. census reproduction
    sys.path.insert(0, HERE)
    import census as C
    calls, tails, lea_cands, imm_hits, qwords = C.scan(data)
    if len([c for c in calls[C.STRING_ASSIGN] if C.confirm_call(c, C.STRING_ASSIGN)]) != 12:
        fail("string-helper calls != 12")
    if calls[C.CTOR] != [0x61F9380] or not C.confirm_call(0x61F9380, C.CTOR):
        fail("ctor calls != [0x61f9380]")
    if sorted(calls[C.GETTER]) != [0x5FF88FC, 0x61F9420, 0x6206A3D]:
        fail("getter calls mismatch: %s" % [hex(c) for c in calls[C.GETTER]])
    if calls[C.STATIC_INIT] or calls[C.MAP_DTOR]:
        fail("unexpected static-init or map-dtor calls")
    if any(tails.values()):
        fail("unexpected tail jumps")
    good_leas = [a for a in lea_cands if C.confirm_lea(a, C.MAP_ADDR)]
    if good_leas != [0x61F9234, 0x620B516]:
        fail("map lea sites mismatch: %s" % [hex(a) for a in good_leas])
    if imm_hits:
        fail("unexpected absolute-immediate references to the map")
    if qwords[C.MAP_ADDR]:
        fail("unexpected stored pointers to the map")
    if qwords[C.STATIC_INIT] != [0x7BA0]:
        fail("static-init qword hits mismatch: %s" % qwords[C.STATIC_INIT])
    if qwords[C.MAP_DTOR] or qwords[C.STRING_ASSIGN]:
        fail("unexpected qword hits for map dtor or string helper")

    # 7. model constants
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import registrar_map_115 as model
    if model.MAP_ADDR != 0x6509540:
        fail("model map address wrong")
    if model.MAP_SIZE != 0x38:
        fail("model map size wrong")
    if model.NODE_SIZE != 0x50:
        fail("model node size wrong")
    if model.SSO_LIMIT != 15:
        fail("model SSO limit wrong")
    if model.BUILD_SHA != "6a436150417120a3f9732d65a2a5c2b8d19b60fc":
        fail("model SHA literal wrong")
    if model.BUILD_TAG != "rocksdb_build_git_tag:v8.1.1":
        fail("model tag literal wrong")
    if model.BUILD_DATE != "rocksdb_build_date:2023-04-06 16:38:52":
        fail("model date literal wrong")
    if model.MAP_LEA_SITES != (0x61F9234, 0x620B516):
        fail("model lea sites wrong")
    if model.STRING_HELPER_CALLS != 12:
        fail("model string-helper call count wrong")
    if model.STATIC_INIT_FDE != (0x620B470, 0x620B57D):
        fail("model static-init FDE wrong")
    if model.MAP_DTOR_FDE != (0x620A500, 0x620A5BD):
        fail("model map-dtor FDE wrong")

    # 8. relocation records
    relocs = subprocess.run(["readelf", "-r", BIN_ABS], capture_output=True,
                            text=True, check=True).stdout
    for want_line in (
            "0000063f3bf8  000000000008 R_X86_64_RELATIVE                    620b470",
            "0000064efa20  000000000008 R_X86_64_RELATIVE                    64efa20",
            "0000064fe448  000000000008 R_X86_64_RELATIVE                    64efa20",
            "0000064ed5d8  013a00000006 R_X86_64_GLOB_DAT 0000000000000000 "
            "_ZNSt7__cxx1112ba[...]@GLIBCXX_3.4.21 + 0"):
        if want_line not in relocs:
            fail("relocation record missing: " + want_line[:60])

    # 9. data literals
    for vaddr, want in (
            (0x965C68, b"6a436150417120a3f9732d65a2a5c2b8d19b60fc"),
            (0x44EED4, b"rocksdb_build_git_tag:v8.1.1"),
            (0x95B628, b"rocksdb_build_date:2023-04-06 16:38:52"),
            (0x963298, b"basic_string: construction from null is not valid")):
        off = v2o(segs, vaddr)
        if off is None or data[off:off + len(want)] != want:
            fail("literal mismatch at %#x" % vaddr)

    # 10. model tests
    out = subprocess.run([sys.executable,
                          os.path.join(ROOT, "tests",
                                       "test_registrar_map_115.py")],
                         capture_output=True, text=True)
    # unittest writes its progress and the OK verdict to stderr.
    if out.returncode != 0 or ("OK" not in out.stdout and "OK" not in out.stderr):
        fail("model tests failed: " + out.stdout + out.stderr)

    if FAILS:
        print("%d CHECK(S) FAILED" % len(FAILS))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
