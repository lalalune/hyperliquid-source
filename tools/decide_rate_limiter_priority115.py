#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::WritableFileWriter::DecideRateLimiterPriority.

Target: rocksdb::WritableFileWriter::DecideRateLimiterPriority(
Env::IOPriority, Env::IOPriority) at 0x604c800..0x604c827 (39 B,
single FDE) in node #115 (work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The smallest function in the small-item queue (Chi, 2026-11-11):
a pure 39-byte leaf that picks which rate-limiter priority a
WritableFileWriter write uses. Six WritableFileWriter methods call
it once each (Append, Flush, WriteBuffered,
WriteBufferedWithChecksum, WriteDirect, WriteDirectWithChecksum);
upstream RocksDB v8.1.1 calls it at exactly the same six sites
(file/writable_file_writer.cc:64, 364, 557, 652, 789, 899).

Whole-FDE facts (verified live, see --live):
- Signature: Env::IOPriority (int, in eax), first arg in edi
  (writable_file_io_priority), second arg in esi
  (op_rate_limiter_priority). No stack frame, no canary, no calls,
  no LSDA, no .cold FDE. The .eh_frame record at section offset
  0x367198 has length 0x10, range 0x27, aug_len 0.
- Body hash matches the vendor census target_body_sha256 exactly
  (raw_equal, zero relocations): member
  a895f7517936a0f7-writable_file_writer.o, librocksdb-sys
  0.11.0+8.1.1, symbol
  _ZN7rocksdb18WritableFileWriter25DecideRateLimiterPriorityENS_3Env10IOPriorityES2_.
- Decision (16 instructions, 4 conditional jumps, 2 rets, 0 calls):
  result = op unless op == IO_TOTAL (4), in which case file.
  Both TOTAL -> TOTAL; file TOTAL -> op; op TOTAL -> file;
  neither TOTAL -> op. This is exactly upstream v8.1.1
  file/writable_file_writer.cc:974-987, only compiled into a
  different branch shape (the binary tests esi == 4 once into dl,
  then branches on edi == 4).
- IOPriority enum (include/rocksdb/env.h:431-437): IO_LOW 0,
  IO_MID 1, IO_HIGH 2, IO_USER 3, IO_TOTAL 4. The binary compares
  full 32-bit values against 4 only, so any out-of-range value
  passes through unchanged (op != 4 -> op; op == 4 -> file).
  The model follows the binary, not the enum range.

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM. The
target binary is never executed. The tool models the helper in
Python from its whole-FDE disassembly.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

ARTIFACT_SHA256 = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f"
                   "249e98c3867b5301")
START = 0x604C800
END = 0x604C827
BODY_SHA256 = ("1e2d437d644b8055475bfacacec90c80e5ae626ff53224925c2"
               "df1be0cd8947e")
SOURCE_SHA256 = BODY_SHA256  # raw_equal: zero relocations
RELOCATIONS = ""
MEMBER = "a895f7517936a0f7-writable_file_writer.o"
SYMBOL = ("_ZN7rocksdb18WritableFileWriter25DecideRateLimiterPriority"
          "ENS_3Env10IOPriorityES2_")
# FDE record in .eh_frame (section offset 0x367198): length 0x10,
# range 0x27, aug_len 0 -- no LSDA pointer, no landing pad.
FDE_SECTION_OFFSET = 0x367198
FDE_LENGTH = 0x10
FDE_RANGE = 0x27
# The 16 instructions of the FDE, (address, mnemonic, op_str),
# in Capstone's Intel syntax (the .objdump.txt excerpt is the
# verbatim objdump rendering of the same bytes).
INSTRUCTIONS = [
    (0x604C800, "endbr64", ""),
    (0x604C804, "cmp", "esi, 4"),
    (0x604C807, "sete", "dl"),
    (0x604C80A, "cmp", "edi, 4"),
    (0x604C80D, "jne", "0x604c820"),
    (0x604C80F, "mov", "eax, 4"),
    (0x604C814, "test", "dl, dl"),
    (0x604C816, "jne", "0x604c81f"),
    (0x604C818, "cmp", "edi, 4"),
    (0x604C81B, "jne", "0x604c820"),
    (0x604C81D, "mov", "eax, esi"),
    (0x604C81F, "ret", ""),
    (0x604C820, "test", "dl, dl"),
    (0x604C822, "je", "0x604c81d"),
    (0x604C824, "mov", "eax, edi"),
    (0x604C826, "ret", ""),
]

IO_TOTAL = 4
PRIORITY_NAMES = {0: "IO_LOW", 1: "IO_MID", 2: "IO_HIGH",
                  3: "IO_USER", 4: "IO_TOTAL"}

# Callers: (site, caller start, caller name, member). All six are
# WritableFileWriter methods reconstructed in earlier open PRs.
CALLERS = [
    (0x604E1D6, 0x604E140, "rocksdb::WritableFileWriter::WriteBuffered",
     MEMBER),
    (0x604F10C, 0x604F080,
     "rocksdb::WritableFileWriter::WriteBufferedWithChecksum", MEMBER),
    (0x604FFF1, 0x604FE80, "rocksdb::WritableFileWriter::WriteDirect",
     MEMBER),
    (0x6050DF9, 0x6050C80,
     "rocksdb::WritableFileWriter::WriteDirectWithChecksum", MEMBER),
    (0x6051B69, 0x6051A20, "rocksdb::WritableFileWriter::Flush", MEMBER),
    (0x6054829, 0x6054680, "rocksdb::WritableFileWriter::Append", MEMBER),
]
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-decide-rate-limiter-priority-115"
CASES = PACKET / "cases.tsv"


def _u32(v):
    return v & 0xFFFFFFFF


def decide(file_priority, op_priority):
    """The binary's rule, on full 32-bit values.

    return op unless op == IO_TOTAL (4), in which case file.
    """
    file_priority = _u32(file_priority)
    op_priority = _u32(op_priority)
    return op_priority if op_priority != IO_TOTAL else file_priority


def name_of(value):
    return PRIORITY_NAMES.get(_u32(value), f"UNKNOWN({_u32(value)})")


def run_case(inputs):
    """Run one case: inputs has file_priority, op_priority (ints),
    and optionally invariant (one of body_sha256, source_sha256,
    fde_record, caller_census)."""
    file_p = inputs["file_priority"]
    op_p = inputs["op_priority"]
    result = decide(file_p, op_p)
    out = {"file_priority": _u32(file_p),
           "file_priority_name": name_of(file_p),
           "op_priority": _u32(op_p),
           "op_priority_name": name_of(op_p),
           "result": result,
           "result_name": name_of(result)}
    if "invariant" in inputs:
        out["invariant"] = inputs["invariant"]
        out["invariant_expected"] = invariant_value(inputs["invariant"])
    return out


def invariant_value(name):
    """The recorded expected value of a binding invariant."""
    if name == "body_sha256":
        return BODY_SHA256
    if name == "source_sha256":
        return SOURCE_SHA256
    if name == "fde_record":
        return {"section_offset": hex(FDE_SECTION_OFFSET),
                "length": FDE_LENGTH, "range": FDE_RANGE, "aug_len": 0}
    if name == "caller_census":
        return {"calls": len(CALLERS), "jumps": 0, "lea_refs": 0}
    raise ValueError(name)


VALID_PAIRS = [(f, o) for f in range(5) for o in range(5)]
OUT_OF_RANGE = [5, 6, 255, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
CALLER_CONTEXTS = ["Append", "WriteBuffered", "WriteDirect", "Flush"]


def gen_cases():
    """300 deterministic cases: 100 checks + 100 edge + 100 bindings."""
    rows = []
    # checks: every valid (file, op) pair in 4 caller contexts.
    for i, (f, o) in enumerate(VALID_PAIRS):
        for ctx in CALLER_CONTEXTS:
            rows.append(("checks", f"checks-{len(rows):04d}",
                         {"case_id": f"checks-{len(rows):04d}",
                          "group": "checks", "context": ctx,
                          "file_priority": f, "op_priority": o},
                         run_case({"file_priority": f, "op_priority": o})))
    # edge: out-of-range values on either side (binary compares
    # full 32-bit values against 4 only).
    edge_pairs = []
    for v in OUT_OF_RANGE:
        for o in range(5):
            edge_pairs.append((v, o))
            edge_pairs.append((o, v))
    for v1 in OUT_OF_RANGE:
        for v2 in OUT_OF_RANGE:
            edge_pairs.append((v1, v2))
    edge_pairs.append((5, 5))
    edge_pairs.append((0xFFFFFFFF, 0xFFFFFFFF))
    edge_pairs.append((0x80000000, 4))
    edge_pairs.append((4, 0x80000000))
    assert len(edge_pairs) == 100, len(edge_pairs)
    for i, (f, o) in enumerate(edge_pairs):
        rows.append(("edge", f"edge-{len(rows) - 100:04d}",
                     {"case_id": f"edge-{len(rows) - 100:04d}",
                      "group": "edge",
                      "file_priority": f, "op_priority": o},
                     run_case({"file_priority": f, "op_priority": o})))
    # bindings: the 25 valid pairs, each bound to one recorded
    # invariant (body hash, source hash, FDE record, caller census).
    invariants = ["body_sha256", "source_sha256", "fde_record",
                  "caller_census"]
    for i, (f, o) in enumerate(VALID_PAIRS):
        for inv in invariants:
            inputs = {"case_id": f"bindings-{len(rows) - 200:04d}",
                      "group": "bindings", "invariant": inv,
                      "file_priority": f, "op_priority": o}
            rows.append(("bindings", inputs["case_id"], inputs,
                         run_case(inputs)))
    assert len(rows) == 300, len(rows)
    return rows


def write_cases(path=CASES):
    rows = gen_cases()
    with open(path, "w") as fh:
        fh.write("group\tcase_id\tinputs_json\texpected_json\n")
        for group, case_id, inputs, expected in rows:
            fh.write(f"{group}\t{case_id}\t"
                     f"{json.dumps(inputs, separators=(',', ':'))}\t"
                     f"{json.dumps(expected, separators=(',', ':'))}\n")
    print(f"wrote {len(rows)} cases to {path}")
    return rows


def verify_cases(path=CASES):
    rows = gen_cases()
    by_id = {r[1]: r for r in rows}
    mismatches = []
    with open(path) as fh:
        header = fh.readline()
        assert header.startswith("group\tcase_id\t"), header
        for line in fh:
            group, case_id, inputs_json, expected_json = \
                line.rstrip("\n").split("\t")
            inputs = json.loads(inputs_json)
            expected = json.loads(expected_json)
            if case_id not in by_id:
                mismatches.append((case_id, "unknown case id"))
                continue
            got = run_case(inputs)
            if got != expected:
                mismatches.append((case_id, f"got {got} want {expected}"))
    if mismatches:
        for m in mismatches[:10]:
            print("MISMATCH", m, file=sys.stderr)
        print(f"{len(mismatches)} mismatches / {len(rows)} cases",
              file=sys.stderr)
        return 1
    print(f"{len(rows)} cases, 0 mismatches")
    return 0


def _bin_path():
    for candidate in (Path(__file__).resolve().parents[1] / 'artifacts' / 'node' / '115' / 'hl-node',):
        data = open(candidate, "rb").read()
        if hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256:
            return candidate
    raise RuntimeError("node #115 artifact not materialized")


def _load_text():
    BIN = _bin_path()
    out = subprocess.check_output(["readelf", "-SW", str(BIN)]).decode()
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
                  r"([0-9a-f]+)", out)
    va, off, size = (int(m.group(i), 16) for i in (1, 2, 3))
    data = open(BIN, "rb").read()
    return va, off, data[off:off + size]


def live_check():
    """Decisive legs only: hashes, FDE record, instruction facts,
    caller census, model end-to-end. Returns exit code."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    legs = []

    def leg(ok, label):
        legs.append((bool(ok), label))
        print(("PASS " if ok else "FAIL ") + label)
        return ok

    BIN = _bin_path()
    data = open(BIN, "rb").read()
    leg(hashlib.sha256(data).hexdigest() == ARTIFACT_SHA256,
        "artifact digest")
    text_va, text_off, text = _load_text()
    body = data[text_off + (START - text_va):
                text_off + (END - text_va)]
    leg(len(body) == 39, "body length 39")
    leg(hashlib.sha256(body).hexdigest() == BODY_SHA256, "body hash")
    leg(SOURCE_SHA256 == BODY_SHA256 and RELOCATIONS == "",
        "source hash == body hash (raw_equal, 0 relocations)")
    # FDE record: parse .eh_frame for the record at FDE_SECTION_OFFSET.
    out = subprocess.check_output(["readelf", "-SW", str(BIN)]).decode()
    m = re.search(r"\.eh_frame\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
                  r"([0-9a-f]+)", out)
    eh_va, eh_off, _eh_size = (int(m.group(i), 16) for i in (1, 2, 3))
    sec = data[eh_off:]
    pos = FDE_SECTION_OFFSET
    (length,) = struct.unpack_from("<I", sec, pos)
    (init4,) = struct.unpack_from("<I", sec, pos + 8)
    (rng,) = struct.unpack_from("<I", sec, pos + 12)
    import ctypes
    pc = eh_va + pos + 8 + ctypes.c_int32(init4).value
    leg(length == FDE_LENGTH, f"FDE length 0x{length:x}")
    leg(pc == START, f"FDE initial_location 0x{pc:x}")
    leg(rng == FDE_RANGE, f"FDE range 0x{rng:x}")
    leg(sec[pos + 16] == 0, "FDE aug_len 0 (no LSDA)")
    # Instruction facts via Capstone over the FDE bytes.
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    insns = list(md.disasm(body, START))
    got = [(i.address, i.mnemonic, i.op_str) for i in insns]
    leg(got == INSTRUCTIONS, f"16 instructions verbatim "
        f"({len(insns)} decoded)")
    leg(all(i.mnemonic != "call" for i in insns), "0 call instructions")
    leg(sum(1 for i in insns if i.mnemonic == "ret") == 2, "2 ret")
    leg(all(START <= int(i.op_str, 16) < END
            for i in insns if i.mnemonic in ("jne", "je")),
        "all 4 conditional jumps internal to the FDE")
    # Caller census: raw whole-.text scan for E8/E9/LEA landing on
    # START, validated by decoding from the enclosing FDE start.
    out2 = subprocess.check_output(
        ["readelf", "--debug-dump=frames-interp", str(BIN)]).decode()
    fdes = {}
    for line in out2.splitlines():
        mm = re.search(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if mm:
            fdes[int(mm.group(1), 16)] = int(mm.group(2), 16)
    import bisect
    starts = sorted(fdes)

    def fde_containing(v):
        i = bisect.bisect_right(starts, v) - 1
        if i < 0:
            return None
        s = starts[i]
        return (s, fdes[s]) if s <= v < fdes[s] else None

    def validate(site, kind, target):
        fde = fde_containing(site)
        if fde is None:
            return None
        start, end = fde
        o = start - text_va
        for insn in md.disasm(text[o:o + (end - start)], start):
            if insn.address == site:
                if kind == "call" and insn.mnemonic == "call":
                    return insn
                if kind == "jmp" and insn.mnemonic == "jmp":
                    return insn
                if kind == "lea" and insn.mnemonic == "lea":
                    return insn
                return None
            if insn.address > site:
                return None
        return None

    sites = []
    n = len(text)
    for opcode, kind, width in ((0xE8, "call", 5), (0xE9, "jmp", 5)):
        i = 0
        while True:
            i = text.find(bytes([opcode]), i)
            if i < 0 or i + 5 > n:
                break
            disp = struct.unpack_from("<i", text, i + 1)[0]
            site = text_va + i
            if site + width + disp == START:
                if validate(site, kind, START) is not None:
                    sites.append((site, kind))
            i += 1
    i = 0
    while True:
        i = text.find(b"\x48\x8d", i)
        if i < 0 or i + 7 > n:
            break
        modrm = text[i + 2]
        if modrm & 0xC7 == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            site = text_va + i
            if site + 7 + disp == START:
                if validate(site, "lea", START) is not None:
                    sites.append((site, "lea"))
        i += 1
    leg(sorted(sites) == sorted((s, "call") for s, _, _, _ in CALLERS),
        f"caller census: 6 direct calls, 0 jumps, 0 LEA refs "
        f"({len(sites)} validated)")
    # Model end-to-end: all 25 valid pairs + out-of-range pins.
    ok = True
    for f, o in VALID_PAIRS:
        want_r = o if o != 4 else f
        ok = ok and decide(f, o) == want_r
    ok = ok and decide(5, 4) == 5 and decide(4, 255) == 255
    ok = ok and decide(0xFFFFFFFF, 4) == 0xFFFFFFFF
    ok = ok and decide(4, 4) == 4
    leg(ok, "model end-to-end (25 valid pairs + out-of-range pins)")
    failed = [label for passed, label in legs if not passed]
    print(f"{len(legs) - len(failed)}/{len(legs)} live legs pass")
    return 0 if not failed else 1


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--live":
        return live_check()
    if len(sys.argv) > 1 and sys.argv[1] == "--write-cases":
        write_cases()
        return verify_cases()
    if len(sys.argv) > 1 and sys.argv[1] == "--verify-cases":
        return verify_cases()
    print("usage: decide_rate_limiter_priority115.py "
          "[--live | --write-cases | --verify-cases]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
