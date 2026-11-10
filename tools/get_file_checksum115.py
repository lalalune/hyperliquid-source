#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::WritableFileWriter::GetFileChecksum.

Target: rocksdb::WritableFileWriter::GetFileChecksum()
at 0x604c710..0x604c77a (106 B, single FDE) in node #115
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The third function in the small-item queue (Chi, 2026-11-11): a
106-byte leaf that returns the writer's file checksum -- the
generator's GetChecksum() result when a generator is set, else
kUnknownFileChecksum (""). The direct follow-up to open PR #6566
(UpdateFileChecksum, the generator's Update dispatch) and open PR
#6565 (DecideRateLimiterPriority); the same writer, the same
checksum_generator_ at this+0xc8. Six callers: BuildTable
(db/builder.cc:335, meta->file_checksum), CompactionOutputs::
WriterSyncClose, BlobLogWriter::AppendFooter, and the three table
builders' own GetFileChecksum wrappers (BlockBased, Cuckoo,
Plain), which delegate to this function when the writer has a
generator. Upstream RocksDB v8.1.1 calls it at the same sites
(file/writable_file_writer.cc:415-422; db/builder.cc:335).

Whole-FDE facts (verified live, see --live):
- Signature: std::string GetFileChecksum() (hidden sret out in
  rdi, this in rsi). Stack frame: push rbx, sub rsp, 0x10; stack
  canary stored at rsp+0x8, checked before every return; a bad
  canary calls __stack_chk_fail. No LSDA, no .cold FDE. The
  .eh_frame record at section offset 0x367130 has length 0x20,
  range 0x6a, aug_len 0.
- Body hash matches the vendor census target_body_sha256 exactly;
  source hash reproduced exactly by zeroing the single kind-4
  relocation at offset 102 (the __stack_chk_fail PLT call disp32):
  member a895f7517936a0f7-writable_file_writer.o, librocksdb-sys
  0.11.0+8.1.1, symbol
  _ZN7rocksdb18WritableFileWriter15GetFileChecksumB5cxx11Ev.
- Decision (26 instructions, 2 conditional jumps, 1 indirect
  call, 1 direct call, 1 jmp, 1 ret): load this+0xc8
  (checksum_generator_, a std::unique_ptr<FileChecksumGenerator>
  per file/writable_file_writer.h:163); if null, build the empty
  SSO string in the sret out (ptr = out+0x10, size 0, first byte
  NUL) -- that is kUnknownFileChecksum, constexpr char [] = ""
  (include/rocksdb/file_checksum.h:27) -- then fall into the
  canary check and return; else call vtable slot 4 of the
  generator (*0x20(%rax)) with (out, generator). Slot 4 is
  GetChecksum: FileChecksumGenerator's virtuals occupy six vtable
  entries in declaration order -- the two Itanium ABI destructor
  slots (complete-object dtor, deleting dtor), then Update,
  Finalize, GetChecksum, Name (include/rocksdb/file_checksum.h:
  52-67) -- so the fifth entry (0x20 past the vptr) is
  GetChecksum() const, returning std::string by value into the
  same sret out. The concrete checksum bytes are the generator's
  own behavior (already reconstructed for the CRC32C/XXH
  generators in earlier RE-002 packets) -- not this function's;
  this model pins the dispatch, the null branch and the returned
  value only.
- The canary is checked on BOTH paths, after the virtual call on
  the present path and after the empty-string build on the null
  path, so a bad canary fails even when no generator is set. A
  throw from the generator's GetChecksum propagates with no
  cleanup (no LSDA, no landing pad) and the canary check never
  runs on that path. The assert(checksum_finalized_) in the
  upstream source is compiled out: no reference to the flag in
  the FDE. The 7-byte nop at 0x604c757 is alignment padding
  inside the FDE (the ret at 0x604c756 is the fall-through of the
  present path; the null path jumps back to the canary check at
  0x604c73e).

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM. The
target binary is never executed. The tool models the helper in
Python from its whole-FDE disassembly. Checksum strings are
deterministic values (the generator's GetChecksum may return
arbitrary bytes, including non-printable ones, per the header
comment), not real file bytes.
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
START = 0x604C710
END = 0x604C77A
BODY_SHA256 = ("2c4cb495674d79320e55e2b6908d84b6ac2e82fb4f2b5da2780"
               "17d2975ed174f")
SOURCE_SHA256 = ("faec8b67ec0ac85231bb3db839ec724802e11175ee9d29d4c"
                 "dff5ea6aff8941f")
# One kind-4 relocation at offset 102 (the __stack_chk_fail PLT
# call disp32); zeroing it reproduces source_body_sha256 exactly.
RELOCATIONS = "1 kind-4 relocation at offset 102"
MEMBER = "a895f7517936a0f7-writable_file_writer.o"
SYMBOL = ("_ZN7rocksdb18WritableFileWriter15GetFileChecksumB5cxx11Ev")
# FDE record in .eh_frame (section offset 0x367130): length 0x20,
# range 0x6a, aug_len 0 -- no LSDA pointer, no landing pad.
FDE_SECTION_OFFSET = 0x367130
FDE_LENGTH = 0x20
FDE_RANGE = 0x6A
# The 26 instructions of the FDE, (address, mnemonic, op_str),
# in Capstone's Intel syntax (the .objdump.txt excerpt is the
# verbatim objdump rendering of the same bytes).
INSTRUCTIONS = [
    (0x604C710, "endbr64", ""),
    (0x604C714, "push", "rbx"),
    (0x604C715, "mov", "rbx, rdi"),
    (0x604C718, "sub", "rsp, 0x10"),
    (0x604C71C, "mov", "rsi, qword ptr [rsi + 0xc8]"),
    (0x604C723, "mov", "rax, qword ptr fs:[0x28]"),
    (0x604C72C, "mov", "qword ptr [rsp + 8], rax"),
    (0x604C731, "xor", "eax, eax"),
    (0x604C733, "test", "rsi, rsi"),
    (0x604C736, "je", "0x604c760"),
    (0x604C738, "mov", "rax, qword ptr [rsi]"),
    (0x604C73B, "call", "qword ptr [rax + 0x20]"),
    (0x604C73E, "mov", "rax, qword ptr [rsp + 8]"),
    (0x604C743, "sub", "rax, qword ptr fs:[0x28]"),
    (0x604C74C, "jne", "0x604c775"),
    (0x604C74E, "add", "rsp, 0x10"),
    (0x604C752, "mov", "rax, rbx"),
    (0x604C755, "pop", "rbx"),
    (0x604C756, "ret", ""),
    (0x604C757, "nop", "word ptr [rax + rax]"),
    (0x604C760, "lea", "rax, [rdi + 0x10]"),
    (0x604C764, "mov", "qword ptr [rdi + 8], 0"),
    (0x604C76C, "mov", "qword ptr [rdi], rax"),
    (0x604C76F, "mov", "byte ptr [rdi + 0x10], 0"),
    (0x604C773, "jmp", "0x604c73e"),
    (0x604C775, "call", "0x63f0d70"),
]

# Callers: (site, caller start, caller end, caller name, member).
CALLERS = [
    (0x5E1892E, 0x5E183F0, 0x5E18B3B,
     "rocksdb::CompactionOutputs::WriterSyncClose",
     "e7c8f0e01ce23ae2-compaction_outputs.o"),
    (0x5E1F4DF, 0x5E1B9C0, 0x5E20481,
     "rocksdb::BuildTable",
     "25dac13516458d4d-builder.o"),
    (0x5E2734F, 0x5E26E90, 0x5E278EB,
     "rocksdb::BlobLogWriter::AppendFooter",
     "ae4e8abb3e2e5bbe-blob_log_writer.o"),
    (0x60E3F6A, 0x60E3F40, 0x60E3FAA,
     "rocksdb::BlockBasedTableBuilder::GetFileChecksum",
     "76f427614eeda70f-block_based_table_builder.o"),
    (0x615CEF5, 0x615CED0, 0x615CF32,
     "rocksdb::CuckooTableBuilder::GetFileChecksum",
     "d82ba100ade79948-cuckoo_table_builder.o"),
    (0x618B378, 0x618B350, 0x618B3BA,
     "rocksdb::PlainTableBuilder::GetFileChecksum",
     "85d8dc4d32f101fc-plain_table_builder.o"),
]
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-get-file-checksum-115"
CASES = PACKET / "cases.tsv"


class StackCheckFailed(Exception):
    """The canary check failed: __stack_chk_fail."""


class GeneratorThrew(Exception):
    """The generator's GetChecksum threw (propagates, no LSDA)."""


def get_file_checksum(writer, gen_checksum=None, canary_ok=True,
                      gen_throws=False):
    """The binary's dispatch, on the writer state.

    writer: {"checksum_generator": None | {"name": str}}.
    gen_checksum: the string the generator's GetChecksum returns
        (None when no generator is set).
    Returns {"checksum": str}. Raises StackCheckFailed on a bad
    canary (either path) and GeneratorThrew when the generator's
    GetChecksum throws (before any canary check).
    """
    gen = writer["checksum_generator"]
    if gen is None:
        checksum = ""
    else:
        if gen_throws:
            raise GeneratorThrew(gen["name"])
        checksum = gen_checksum
    if not canary_ok:
        raise StackCheckFailed()
    return {"checksum": checksum}


def run_case(inputs):
    """Run one case. Inputs: generator (None or name string),
    gen_checksum (str or None), canary_ok (bool), gen_throws
    (bool), and optionally invariant."""
    writer = {"checksum_generator":
              None if inputs["generator"] is None
              else {"name": inputs["generator"]}}
    try:
        out = get_file_checksum(
            writer, gen_checksum=inputs.get("gen_checksum"),
            canary_ok=inputs.get("canary_ok", True),
            gen_throws=inputs.get("gen_throws", False))
        out = {"generator": inputs["generator"],
               "gen_checksum": inputs.get("gen_checksum"),
               "canary_ok": inputs.get("canary_ok", True),
               "gen_throws": inputs.get("gen_throws", False),
               "outcome": "ok", "checksum": out["checksum"]}
    except StackCheckFailed:
        out = {"generator": inputs["generator"],
               "gen_checksum": inputs.get("gen_checksum"),
               "canary_ok": inputs.get("canary_ok", True),
               "gen_throws": inputs.get("gen_throws", False),
               "outcome": "stack_check_failed", "checksum": None}
    except GeneratorThrew:
        out = {"generator": inputs["generator"],
               "gen_checksum": inputs.get("gen_checksum"),
               "canary_ok": inputs.get("canary_ok", True),
               "gen_throws": inputs.get("gen_throws", False),
               "outcome": "generator_throw", "checksum": None}
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


# Checksum payloads: 10 lengths x 5 patterns = 50 variants.
# Patterns cover empty, short ASCII, hex, binary (NUL/0xff) and
# long values; GetChecksum may return arbitrary bytes.
_CHECKSUM_LENS = [0, 1, 2, 3, 4, 8, 16, 32, 64, 128]


def _pattern(kind, n):
    if kind == 0:
        return "a" * n
    if kind == 1:
        return ("0123456789abcdef" * ((n + 15) // 16))[:n]
    if kind == 2:
        return "".join(chr(b) for b in
                       bytes((i * 37 + 11) % 256 for i in range(n)))
    if kind == 3:
        return ("crc32c:" * ((n + 6) // 7))[:n]
    return "\x00\xff" * (n // 2) + ("\x00" if n % 2 else "")


CHECKSUM_VALUES = [_pattern(k, n) for n in _CHECKSUM_LENS
                   for k in range(5)]
GENERATORS = [None, "FileChecksumGenCrc32c"]
# Edge conditions: (canary_ok, gen_throws, force_empty).
EDGE_CONDITIONS = [
    (True, False, False),
    (False, False, False),
    (True, True, False),
    (False, True, False),
    (True, False, True),
]


def gen_cases():
    """300 deterministic cases: 100 checks + 100 edge + 100 bindings."""
    rows = []
    # checks: 50 checksum variants x 2 generator states.
    for gen in GENERATORS:
        for value in CHECKSUM_VALUES:
            rows.append(("checks", f"checks-{len(rows):04d}",
                         {"case_id": f"checks-{len(rows):04d}",
                          "group": "checks", "generator": gen,
                          "gen_checksum": value if gen else None,
                          "canary_ok": True, "gen_throws": False},
                         run_case({"generator": gen,
                                   "gen_checksum": value if gen else None,
                                   "canary_ok": True,
                                   "gen_throws": False})))
    # edge: 10 checksum values x 2 generator states x 5 conditions.
    # A null generator never calls, so gen_throws is vacuous there;
    # the canary check still applies on the null path.
    edge_values = CHECKSUM_VALUES[::5]
    assert len(edge_values) == 10, len(edge_values)
    for gen in GENERATORS:
        for value in edge_values:
            for canary_ok, gen_throws, force_empty in EDGE_CONDITIONS:
                v = "" if force_empty else value
                inputs = {"case_id": f"edge-{len(rows) - 100:04d}",
                          "group": "edge", "generator": gen,
                          "gen_checksum": v if gen else None,
                          "canary_ok": canary_ok,
                          "gen_throws": gen_throws}
                rows.append(("edge", inputs["case_id"], inputs,
                             run_case(inputs)))
    assert len(rows) == 200, len(rows)
    # bindings: 25 (generator, checksum) pairs x 4 invariants.
    bind_pairs = []
    for gen in GENERATORS:
        for value in CHECKSUM_VALUES[:13]:
            bind_pairs.append((gen, value))
    bind_pairs = bind_pairs[:25]
    invariants = ["body_sha256", "source_sha256", "fde_record",
                  "caller_census"]
    for gen, value in bind_pairs:
        for inv in invariants:
            inputs = {"case_id": f"bindings-{len(rows) - 200:04d}",
                      "group": "bindings", "invariant": inv,
                      "generator": gen,
                      "gen_checksum": value if gen else None,
                      "canary_ok": True, "gen_throws": False}
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
    for candidate in (Path(__file__).resolve().parents[1] / "work" /
                      "hl-node-115.bin",
                      Path(__file__).resolve().parents[1] / "artifacts" /
                      "node" / "115" / "hl-node"):
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
    leg(len(body) == 106, "body length 106")
    leg(hashlib.sha256(body).hexdigest() == BODY_SHA256, "body hash")
    src = bytearray(body)
    src[102:106] = b"\x00\x00\x00\x00"
    leg(hashlib.sha256(bytes(src)).hexdigest() == SOURCE_SHA256,
        "source hash (zero 1 kind-4 reloc @102)")
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
    leg(got == INSTRUCTIONS, f"26 instructions verbatim "
        f"({len(insns)} decoded)")
    leg(sum(1 for i in insns if i.mnemonic == "call") == 2,
        "2 calls (1 indirect vtable, 1 __stack_chk_fail)")
    leg([i for i in insns if i.mnemonic == "call"
         and i.op_str == "qword ptr [rax + 0x20]"] != [],
        "indirect call to vtable slot 4 (GetChecksum)")
    leg(sum(1 for i in insns if i.mnemonic == "ret") == 1, "1 ret")
    leg(sum(1 for i in insns if i.mnemonic == "jmp") == 1, "1 jmp")
    leg(all(START <= int(i.op_str, 16) < END
            for i in insns if i.mnemonic in ("je", "jne")),
        "both conditional jumps stay inside the FDE")
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
    leg(sorted(sites) == sorted((s, "call") for s, _, _, _, _ in CALLERS),
        f"caller census: 6 direct calls, 0 jumps, 0 LEA refs "
        f"({len(sites)} validated)")
    # Model end-to-end legs.
    ok = True
    null_writer = {"checksum_generator": None}
    gen_writer = {"checksum_generator": {"name": "FileChecksumGenCrc32c"}}
    ok = ok and get_file_checksum(null_writer) == {"checksum": ""}
    try:
        get_file_checksum(null_writer, canary_ok=False)
        ok = False
    except StackCheckFailed:
        pass
    ok = ok and get_file_checksum(
        gen_writer, gen_checksum="deadbeef") == {"checksum": "deadbeef"}
    ok = ok and get_file_checksum(
        gen_writer, gen_checksum="") == {"checksum": ""}
    ok = ok and get_file_checksum(
        gen_writer, gen_checksum="\x00\xff\x01") == \
        {"checksum": "\x00\xff\x01"}
    try:
        get_file_checksum(gen_writer, gen_checksum="x", gen_throws=True)
        ok = False
    except GeneratorThrew:
        pass
    try:
        get_file_checksum(gen_writer, gen_checksum="x", gen_throws=True,
                          canary_ok=False)
        ok = False
    except GeneratorThrew:
        pass  # throw beats the canary check: it happens first
    try:
        get_file_checksum(gen_writer, gen_checksum="x", canary_ok=False)
        ok = False
    except StackCheckFailed:
        pass
    leg(ok, "model end-to-end (null/present x empty/binary, "
            "canary, throw order)")
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
    print("usage: get_file_checksum115.py "
          "[--live | --write-cases | --verify-cases]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
