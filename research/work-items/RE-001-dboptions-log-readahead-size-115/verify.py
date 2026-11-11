"""Checker for RE-001-dboptions-log-readahead-size-115.

Run from the repository root:
    python3 research/work-items/RE-001-dboptions-log-readahead-size-115/verify.py

Checks, in order:
  1. artifact digest against provenance/artifacts.json
  2. MANIFEST.sha256 entries (hash + exactly two spaces + name)
  3. excerpt regeneration against a fresh objdump run (relative binary path)
  4. fixed samples + 3 seeded random gate spots byte-for-byte against fresh
     objdump AND the raw binary (vaddr -> file offset via PT_LOAD segments)
  5. FDE ranges in frames.txt against a fresh objdump --dwarf=frames run
  6. census reproduction (call counts and displacement totals)
  7. model constants (offsets, defaults, OptionTypeInfo map, embeds)
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
    ("dboptions-ctor-60b2db0.objdump.txt", 0x60B2DB0, 0x60B3154),
    ("dboptions-copy-ctor-5d38750.objdump.txt", 0x5D38750, 0x5D38DA5),
    ("dboptions-options-ctor-60b3280.objdump.txt", 0x60B3280, 0x60B3B87),
    ("dboptions-assign-60c3480.objdump.txt", 0x60C3480, 0x60C3AF4),
    ("immutabledboptions-ctor-60a3b60.objdump.txt", 0x60A3B60, 0x60A4363),
    ("immutabledboptions-copy-5da6bc0.objdump.txt", 0x5DA6BC0, 0x5DA7600),
    ("builddboptions-60c2e20.objdump.txt", 0x60C2E20, 0x60C3477),
    ("static-init-60aa2b0.objdump.txt", 0x60AA2B0, 0x60B1D78),
    ("dboptions-configurable-ctor-60a47f0.objdump.txt", 0x60A47F0, 0x60A636B),
    ("configoptions-ctor-60bb890.objdump.txt", 0x60BB890, 0x60BB932),
    ("persist-60d4a00.objdump.txt", 0x60D4A00, 0x60D4B7E),
    ("persist-inner-60d2820.objdump.txt", 0x60D2820, 0x60D49D3),
    ("verify-options-60d13a0.objdump.txt", 0x60D13A0, 0x60D24EA),
    ("parse-60cfb60.objdump.txt", 0x60CFB60, 0x60D1354),
]

# (vaddr, instruction bytes) pinned by direct reads of the excerpts.
FIXED_SAMPLES = [
    (0x60B2FE9, bytes.fromhex("48c7832002000000000000")),  # ctor movq $0,0x220(%rbx)
    (0x60D4A6C, bytes.fromhex("488b8320020000")),  # outer Persist mov 0x220(%rbx),%rax
    (0x60A40C9, bytes.fromhex("488b8520020000")),  # immutable ctor mov 0x220(%rbp),%rax
    (0x60A40D0, bytes.fromhex("488983a0010000")),  # immutable ctor mov %rax,0x1a0(%rbx)
    (0x60C332F, bytes.fromhex("488b85a0010000")),  # BuildDBOptions mov 0x1a0(%rbp),%rax
    (0x60C3336, bytes.fromhex("48898320020000")),  # BuildDBOptions mov %rax,0x220(%rbx)
    (0x60AFA9C, bytes.fromhex("48c785f0b3ffffa0010000")),  # map movq $0x1a0 (log_readahead)
    (0x60BB8DB, bytes.fromhex("48c7473000000800")),  # ConfigOptions movq $0x80000,0x30(%rdi)
    (0x5D38B52, bytes.fromhex("488b8520020000")),  # copy ctor mov 0x220(%rbp),%rax
    (0x5D38B60, bytes.fromhex("48898320020000")),  # copy ctor mov %rax,0x220(%rbx)
    (0x60AF8C4, bytes.fromhex("48c78570b2ffff98010000")),  # map movq $0x198 (avoid)
    (0x60AF9B0, bytes.fromhex("48c78530b3ffff9a010000")),  # map movq $0x19a (write_dbid)
    (0x60AFB79, bytes.fromhex("48c785b0b4ffffb8010000")),  # map movq $0x1b8 (best_efforts)
    (0x60AFC6C, bytes.fromhex("48c78570b5ffffbc010000")),  # map movq $0x1bc (max_bgerror)
]

EXPECTED_CALLS = {
    0x60B2DB0: 11, 0x5D38750: 3, 0x60B3280: 6, 0x60C3480: 3,
    0x60A3B60: 6, 0x5DA6BC0: 4, 0x60C2E20: 12, 0x60D4A00: 1,
    0x60D2820: 1, 0x60D13A0: 1, 0x60CFB60: 1,
}

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
    # frames.txt lines must all appear in the fresh frames output.
    for line in open(os.path.join(HERE, "frames.txt")):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line not in frames:
            fail("frames.txt line missing from fresh frames: " + line[:60])

    # 6. census reproduction
    sys.path.insert(0, HERE)
    import census as C
    calls, tails, hits, _slots = C.scan()
    for t, want_n in EXPECTED_CALLS.items():
        if len(calls[t]) != want_n:
            fail("calls for %#x != %d: %d" % (t, want_n, len(calls[t])))
    if any(tails.values()) or any(hits.values()):
        fail("unexpected tail jumps or qword hits")
    totals, by_func = C.disp_census()
    if totals[0x220] != 633 or len(by_func[0x220]) != 232:
        fail("disp 0x220 census != 633/232: %d/%d"
             % (totals[0x220], len(by_func[0x220])))
    if totals[0x1A0] != 681 or len(by_func[0x1A0]) != 288:
        fail("disp 0x1a0 census != 681/288: %d/%d"
             % (totals[0x1A0], len(by_func[0x1A0])))

    # 7. model constants
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import dboptions_log_readahead_size_115 as model
    if model.LOG_READAHEAD_SIZE_OFFSET != 0x220:
        fail("model DBOptions offset wrong")
    if model.LOG_READAHEAD_SIZE_IMMUTABLE_OFFSET != 0x1A0:
        fail("model ImmutableDBOptions offset wrong")
    if model.LOG_READAHEAD_SIZE_DEFAULT != 0:
        fail("model default wrong")
    if model.CONFIGOPTIONS_FILE_READAHEAD_SIZE_DEFAULT != 0x80000:
        fail("model ConfigOptions +0x30 default wrong")
    if model.CONFIGOPTIONS_SANITY_LEVEL_DEFAULT != 0xFF:
        fail("model ConfigOptions +0x2c default wrong")
    if model.OPTION_TYPE_INFO.get("log_readahead_size") != 0x1A0:
        fail("model map log_readahead_size wrong")
    if model.OPTION_TYPE_INFO.get("best_efforts_recovery") != 0x1B8:
        fail("model map best_efforts_recovery wrong")
    if model.OPTION_TYPE_INFO.get("max_bgerror_resume_count") != 0x1BC:
        fail("model map max_bgerror_resume_count wrong")
    if model.CONFIGURABLE_DBOFFSET != 0x2D8:
        fail("model Configurable DBOptions embed wrong")
    if model.CONFIGURABLE_IMMUTABLE_OFFSET != 0x98:
        fail("model Configurable ImmutableDBOptions embed wrong")
    if len(model.OPEN_UNKNOWNS) != 4:
        fail("model open unknowns != 4")
    if model.DBOptions().write_dbid_to_manifest is not None:
        fail("model +0x21b should be unwritten (None)")

    # 8. relocation records
    relocs = subprocess.run(["readelf", "-r", BIN_ABS], capture_output=True,
                            text=True, check=True).stdout
    if ("0000064fee88  000000000008 R_X86_64_RELATIVE                    "
            "4342d1") not in relocs:
        fail("relocation record missing: db_host_id GOT slot 0x64fee88")

    # 9. data literals
    def lit(vaddr, want_bytes, what):
        off = v2o(segs, vaddr)
        if off is None or data[off:off + len(want_bytes)] != want_bytes:
            fail("literal wrong: " + what)
    lit(0x458E70, struct.pack("<Q", 0x00000010FFFFFFFF),
        "max_open_files/max_file_opening_threads at 0x458e70")
    lit(0x4594F0, struct.pack("<Q", 0xFFFFFFFF00000002),
        "max_background_jobs/compactions at 0x4594f0")
    lit(0x459148, struct.pack("<Q", 0x0000025800000258),
        "stats periods at 0x459148")
    lit(0x451490, struct.pack("<QQ", 0, 1048576),
        "compaction_readahead/random_access at 0x451490")
    lit(0x4517A0, struct.pack("<QQ", 1048576, 100),
        "write batch group/yield at 0x4517a0")
    lit(0x446696, b"\n  ", "persist delimiter at 0x446696")
    lit(0x43D7DC, b"log_readahead_size\x00", "name string at 0x43d7dc")
    lit(0x4342D1, b"__hostname__\x00", "db_host_id default at 0x4342d1")
    lit(0x44B4DA, b"avoid_unnecessary_blocking_io\x00", "avoid name string")
    lit(0x44A4EA, b"write_dbid_to_manifest\x00", "write_dbid name string")
    lit(0x4310FA, b"best_efforts_recovery\x00", "best_efforts name string")
    lit(0x43D7EF, b"max_bgerror_resume_count\x00", "max_bgerror name string")
    lit(0x433299, b"max_open_files\x00", "max_open_files name string")

    # 10. model tests
    out = subprocess.run([sys.executable,
                          os.path.join(ROOT, "tests",
                                       "test_dboptions_log_readahead_size_115.py")],
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
