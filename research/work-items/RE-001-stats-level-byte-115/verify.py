"""Checker for RE-001-stats-level-byte-115.

Run from the repository root:
    python3 research/work-items/RE-001-stats-level-byte-115/verify.py

Checks, in order:
  1. artifact digest against provenance/artifacts.json
  2. MANIFEST.sha256 entries (hash + exactly two spaces + name)
  3. excerpt regeneration against a fresh objdump run (relative binary path)
  4. fixed samples + 3 seeded random gate spots byte-for-byte against fresh
     objdump AND the raw binary (vaddr -> file offset via PT_LOAD segments)
  5. FDE ranges in frames.txt against a fresh objdump --dwarf=frames run
  6. census reproduction (135,313 FDEs; 62 stats-marked FDEs; 16,889
     movb +0x20 stores and 11,335 movzbl +0x20 loads binary-wide; the
     single writer 0x6071a32 and the 9 reader sites; 779 timer/forwarder
     calls with the pinned per-kind split)
  7. model constants (enum, gates, layouts, census constants)
  8. relocation records against a fresh readelf -rW run (916 rows)
  9. the "BasicStatistics" string at its pinned file offset, and the
     excerpt content pins (ctor store, forwarder compare, code-52
     compare, compaction-run reads)
 10. the model test suite passes (21 checks)
"""

import hashlib
import json
import os
import random
import re
import struct
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"
BIN_ABS = os.path.join(ROOT, BIN)

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("ctor-6071a00.objdump.txt", 0x6071A00, 0x6071B60),
    ("record-tick-606fba0.objdump.txt", 0x606FBA0, 0x606FC59),
    ("record-hist-606fef0.objdump.txt", 0x606FEF0, 0x606FFCE),
    ("record-hist-devirt-606ffd0.objdump.txt", 0x606FFD0, 0x60700C4),
    ("forwarder-5d48960.objdump.txt", 0x5D48960, 0x5D48979),
    ("mutex-lock-606ca40.objdump.txt", 0x606CA40, 0x606CC6A),
    ("condvar-wait-606ccb0.objdump.txt", 0x606CCB0, 0x606CEDA),
    ("condvar-timedwait-606cf20.objdump.txt", 0x606CF20, 0x606D14B),
    ("tls-init-606dd10.objdump.txt", 0x606DD10, 0x606DD7B),
    ("lock-wrapper-60d5230.objdump.txt", 0x60D5230, 0x60D52C5),
    ("condwait-wrapper-60d5530.objdump.txt", 0x60D5530, 0x60D55C9),
    ("time-math-60d55f0.objdump.txt", 0x60D55F0, 0x60D56CD),
    ("clock-accessor-5fe2680.objdump.txt", 0x5FE2680, 0x5FE2756),
    ("factory-lambda-6071ba0.objdump.txt", 0x6071BA0, 0x6071CCB),
    ("factory-create-6077820.objdump.txt", 0x6077820, 0x60780A0),
    ("compaction-run-5e080f0.objdump.txt", 0x5E080F0, 0x5E095ED),
    ("thunk-606ca00.objdump.txt", 0x606CA00, 0x606CA09),
    ("thunk-606cc70.objdump.txt", 0x606CC70, 0x606CC79),
    ("thunk-606cee0.objdump.txt", 0x606CEE0, 0x606CEE9),
]

# (vaddr, instruction bytes) pinned by direct reads of the excerpts.
FIXED_SAMPLES = [
    (0x6071A00, bytes.fromhex("f30f1efa")),          # ctor endbr64
    (0x6071A32, bytes.fromhex("c6472003")),          # ctor movb $0x3,0x20(%rdi)
    (0x606FBA4, bytes.fromhex("0fb64720")),          # recordTick gate read
    (0x606FEF4, bytes.fromhex("0fb64720")),          # recordHist gate read
    (0x5D48964, bytes.fromhex("0fb64720")),          # forwarder gate read
    (0x5D48968, bytes.fromhex("3c02")),              # forwarder cmp $0x2
    (0x606CA85, bytes.fromhex("410fb6442420")),      # mutex-lock gate read
    (0x606CAFD, bytes.fromhex("837b3834")),          # code == 52 compare
    (0x6077B74, bytes.fromhex("e8879effff")),        # factory ctor call
    (0x5E084AC, bytes.fromhex("0fb64f20")),          # compaction-run read 1
    (0x60D524A, bytes.fromhex("e811b93100")),        # lock wrapper PLT call
    (0x60D554E, bytes.fromhex("e88dc23100")),        # condwait wrapper PLT call
    (0x606DD38, bytes.fromhex("c680a8fcffff01")),    # TLS-init set byte
]

# The exact reader sites (level-reads.tsv content, minus header).
READER_SITES = [0x5D48964, 0x5E084AC, 0x5E084E3, 0x606CA85, 0x606CCF5,
                0x606CF67, 0x606FBA4, 0x606FEF4, 0x606FFFB]
WRITER_SITE = (0x6071A32, 3, "di")

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

    # 6. census reproduction
    sys.path.insert(0, HERE)
    import census as C
    fdes_all, marked, writes, reads, calls = C.scan()
    if len(fdes_all) != 135313:
        fail("FDE count != 135313: %d" % len(fdes_all))
    if len(marked) != 62:
        fail("marked FDEs != 62: %d" % len(marked))
    if len(writes) != 16889:
        fail("movb stores != 16889: %d" % len(writes))
    if len(reads) != 11335:
        fail("movzbl loads != 11335: %d" % len(reads))
    REGION = (0x606B000, 0x6072000)

    def in_scope(addr, fde):
        return fde in marked or REGION[0] <= addr < REGION[1]

    scoped_writes = [(a, f, i, r) for a, f, i, r in writes
                     if r != "sp" and in_scope(a, f)]
    scoped_reads = [(a, f, r, d) for a, f, r, d in reads
                    if r != "sp" and in_scope(a, f)]
    if len(scoped_writes) != 1:
        fail("scoped writers != 1: %s" % [hex(a) for a, _f, _i, _r in scoped_writes])
    elif scoped_writes[0][:1] + (scoped_writes[0][2], scoped_writes[0][3]) != \
            (WRITER_SITE[0], WRITER_SITE[1], WRITER_SITE[2]):
        fail("writer mismatch: %r" % (scoped_writes[0],))
    if sorted(a for a, _f, _r, _d in scoped_reads) != sorted(READER_SITES):
        fail("reader sites mismatch: %s"
             % [hex(a) for a, _f, _r, _d in scoped_reads])
    by_kind = Counter(c[3] for c in calls)
    if len(calls) != 779:
        fail("timer calls != 779: %d" % len(calls))
    if by_kind != {"mutex-lock": 244, "condvar-wait": 27,
                   "condvar-timedwait": 3, "tls-init": 500,
                   "thunk-lock": 2, "thunk-condwait": 2,
                   "thunk-time-math": 1}:
        fail("timer call split mismatch: %s" % dict(by_kind))
    # records.json cross-check.
    rec = json.load(open(os.path.join(HERE, "records.json")))
    if rec["writer_census"]["stats_marked_fdes"] != len(marked):
        fail("records.json marked FDEs mismatch")
    if rec["writer_census"]["writes_in_marked_fdes_or_stats_region"] != \
            len(scoped_writes):
        fail("records.json writer count mismatch")
    if rec["reader_census"]["reads_in_marked_fdes_or_stats_region"] != \
            len(scoped_reads):
        fail("records.json reader count mismatch")
    if rec["caller_census"]["timer_calls_total"] != len(calls):
        fail("records.json timer calls mismatch")
    if len(rec["windows"]) != len(WINDOWS):
        fail("records.json window count mismatch")

    # 7. model constants
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import stats_level_byte_115 as model
    if model.LEVEL_DEFAULT != 3 or model.LEVEL_MAX != 5:
        fail("model level default/max wrong")
    if model.DB_MUTEX_WAIT_MICROS != 52:
        fail("model DB_MUTEX_WAIT_MICROS wrong")
    if model.CTOR_WRITE_SITE != 0x6071A32:
        fail("model ctor write site wrong")
    if model.MARKED_FDES != 62 or model.LEVEL_WRITES != 1:
        fail("model writer census wrong")
    if model.LEVEL_READS != 9:
        fail("model reader census wrong")
    if model.TIMER_CALLS != {"mutex-lock": 244, "condvar-wait": 27,
                             "condvar-timedwait": 3, "tls-init": 500,
                             "thunk-lock": 2, "thunk-condwait": 2,
                             "thunk-time-math": 1}:
        fail("model timer calls wrong")
    if model.STATISTICS_VTABLE != 0x64D2D88:
        fail("model vtable wrong")

    # 8. relocation records
    relocs = C.relocations()
    saved = open(os.path.join(HERE, "relocations.txt")).read().splitlines()[1:]
    want_rows = []
    for line in saved:
        if not line.strip():
            continue
        parts = line.split("\t")
        want_rows.append((int(parts[0], 16), parts[1], parts[2], parts[3]))
    if relocs != want_rows:
        fail("relocations.txt mismatch against fresh readelf -rW")
    if len(relocs) != 916:
        fail("relocation rows != 916: %d" % len(relocs))

    # 9. the "BasicStatistics" string and excerpt content pins
    off = v2o(segs, 0x432248)
    if off is None or data[off:off + 16] != b"BasicStatistics\x00":
        fail("BasicStatistics string mismatch at 0x432248")
    ctor = open(os.path.join(HERE, "ctor-6071a00.objdump.txt")).read()
    if "movb   $0x3,0x20(%rdi)" not in ctor:
        fail("ctor excerpt lacks the level store")
    fwd = open(os.path.join(HERE, "forwarder-5d48960.objdump.txt")).read()
    if "cmp    $0x2,%al" not in fwd or "jmp    *0xd8(%rax)" not in fwd:
        fail("forwarder excerpt lacks the gate/forward")
    mlock = open(os.path.join(HERE, "mutex-lock-606ca40.objdump.txt")).read()
    if "cmpl   $0x34,0x38(%rbx)" not in mlock:
        fail("mutex-lock excerpt lacks the code-52 compare")
    crun = open(os.path.join(HERE, "compaction-run-5e080f0.objdump.txt")).read()
    if crun.count("movzbl 0x20(%rdi),%ecx") != 2:
        fail("compaction-run excerpt lacks the two level reads")
    if "cmp    %rbx,%rcx" not in crun:
        fail("compaction-run excerpt lacks the slot-0xc8 devirt check")

    # 10. model tests
    out = subprocess.run([sys.executable,
                          os.path.join(ROOT, "tests",
                                       "test_stats_level_byte_115.py")],
                         capture_output=True, text=True)
    # unittest writes its progress and the OK verdict to stderr.
    if out.returncode != 0 or ("OK" not in out.stdout and "OK" not in out.stderr):
        fail("model tests failed: " + out.stdout + out.stderr)
    if "Ran 21 tests" not in out.stderr:
        fail("model test count != 21: " + out.stderr)

    if FAILS:
        print("%d CHECK(S) FAILED" % len(FAILS))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
