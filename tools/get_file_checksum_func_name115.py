#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::WritableFileWriter::
GetFileChecksumFuncName.

Target: rocksdb::WritableFileWriter::GetFileChecksumFuncName()
at 0x604c780..0x604c7a8 (40 B, single FDE) in node #115
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The direct sibling of open PR #6568 (GetFileChecksum, the
generator's GetChecksum reader): a 40-byte leaf that returns the
name of the checksum function -- the generator's Name() result
when a generator is set, else kUnknownFileChecksumFuncName
("Unknown"). Unlike its sibling it returns `const char*` (not
std::string): `this` in rdi, the pointer result in rax, no sret
out, no stack frame, no canary. Upstream RocksDB v8.1.1 calls
it at the same three sites (file/writable_file_writer.cc:424-430;
db/builder.cc:336 stores the name in meta->file_checksum_func_name).

Whole-FDE facts (verified live, see --live):
- Signature: const char* GetFileChecksumFuncName() const (this
  in rdi, result pointer in rax). No stack frame, no canary, no
  LSDA, no .cold FDE. The .eh_frame record at section offset
  0x367154 has length 0x10, range 0x28, aug_len 0.
- Body hash matches the vendor census target_body_sha256 exactly;
  source hash reproduced exactly by zeroing the single kind-2
  relocation at offset 35 (the "Unknown" lea disp32):
  member a895f7517936a0f7-writable_file_writer.o, librocksdb-sys
  0.11.0+8.1.1, symbol
  _ZNK7rocksdb18WritableFileWriter23GetFileChecksumFuncNameEv.
- Decision (9 instructions, 1 conditional jump, 1 indirect tail
  jump, 1 ret, 0 calls): load this+0xc8 (checksum_generator_, a
  std::unique_ptr<FileChecksumGenerator> per
  file/writable_file_writer.h:163); if null, lea rax to the
  "Unknown" literal at 0x974e00 and return; else tail-jump to
  vtable slot 5 of the generator (*0x28(%rax)) with (generator).
  Slot 5 is Name: FileChecksumGenerator's virtuals occupy six
  vtable entries in declaration order -- the two Itanium ABI
  destructor slots (complete-object dtor, deleting dtor), then
  Update, Finalize, GetChecksum, Name (include/rocksdb/
  file_checksum.h:52-67) -- so the sixth entry (0x28 past the
  vptr) is Name() const, returning const char* (:67). The
  concrete name string is the generator's own behavior (already
  reconstructed for the CRC32C/XXH generators in earlier RE-002
  packets) -- not this function's; this model pins the dispatch,
  the null branch and the returned pointer only.
- The tail jump leaves no frame of this function on the stack, so
  Name() returns directly to this function's caller, and a throw
  from Name() propagates with no cleanup of ours. The 10-byte nop
  at 0x604c796 is alignment padding inside the FDE.
- Callers: exactly 3 direct calls and 3 tail jumps, 0 LEA refs
  (whole-.text E8/E9/LEA scan, Capstone-validated). The three
  direct callers strlen() the result and assign it into a
  std::string (BuildTable: meta->file_checksum_func_name). The
  three tail jumps are the table builders' own
  GetFileChecksumFuncName wrappers, each of which loads its
  writer, null-checks it, and either tail-jumps here or returns
  its own TU-local copy of the "Unknown" literal (BlockBased
  0x97a0b0, Cuckoo 0x97ba18, Plain 0x97be00 -- the literal is
  `constexpr char[]` in a header, so each TU has its own copy).

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM. The
target binary is never executed. The tool models the helper in
Python from its whole-FDE disassembly. Name strings are
deterministic values, not real generator names.
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
START = 0x604C780
END = 0x604C7A8
BODY_SHA256 = ("33f3e26f2e3d0ad3022a823027bf36ef26327f2e5cca29eef"
               "02e1f3730226241")
SOURCE_SHA256 = ("eeb70928b90e9ec6e9f0988bc85a28f8adf8f64c3d6f35a"
                 "7ea4756377672533c")
# One kind-2 relocation at offset 35 (the "Unknown" lea disp32);
# zeroing it reproduces source_body_sha256 exactly.
RELOCATIONS = "1 kind-2 relocation at offset 35"
MEMBER = "a895f7517936a0f7-writable_file_writer.o"
SYMBOL = ("_ZNK7rocksdb18WritableFileWriter23GetFileChecksumFuncNameEv")
# FDE record in .eh_frame (section offset 0x367154): length 0x10,
# range 0x28, aug_len 0 -- no LSDA pointer, no landing pad.
FDE_SECTION_OFFSET = 0x367154
FDE_LENGTH = 0x10
FDE_RANGE = 0x28
# The 9 instructions of the FDE, (address, mnemonic, op_str),
# in Capstone's Intel syntax (the .objdump.txt excerpt is the
# verbatim objdump rendering of the same bytes).
INSTRUCTIONS = [
    (0x604C780, "endbr64", ""),
    (0x604C784, "mov", "rdi, qword ptr [rdi + 0xc8]"),
    (0x604C78B, "test", "rdi, rdi"),
    (0x604C78E, "je", "0x604c7a0"),
    (0x604C790, "mov", "rax, qword ptr [rdi]"),
    (0x604C793, "jmp", "qword ptr [rax + 0x28]"),
    (0x604C796, "nop", "word ptr cs:[rax + rax]"),
    (0x604C7A0, "lea", "rax, [rip - 0x56d79a7]"),
    (0x604C7A7, "ret", ""),
]
# The null-branch literal: "Unknown" at 0x974e00 in .rodata.
UNKNOWN_LITERAL_VA = 0x974E00
UNKNOWN_LITERAL = "Unknown"

# Callers: (site, caller start, caller end, caller name, member, kind).
CALLERS = [
    (0x5E189BE, 0x5E183F0, 0x5E18B3B,
     "rocksdb::CompactionOutputs::WriterSyncClose",
     "e7c8f0e01ce23ae2-compaction_outputs.o", "call"),
    (0x5E1F508, 0x5E1B9C0, 0x5E20481,
     "rocksdb::BuildTable",
     "25dac13516458d4d-builder.o", "call"),
    (0x5E27213, 0x5E26E90, 0x5E278EB,
     "rocksdb::BlobLogWriter::AppendFooter",
     "ae4e8abb3e2e5bbe-blob_log_writer.o", "call"),
    (0x60E2194, 0x60E2180, 0x60E21A8,
     "rocksdb::BlockBasedTableBuilder::GetFileChecksumFuncName",
     "76f427614eeda70f-block_based_table_builder.o", "jmp"),
    (0x615CB1D, 0x615CB10, 0x615CB30,
     "rocksdb::CuckooTableBuilder::GetFileChecksumFuncName",
     "d82ba100ade79948-cuckoo_table_builder.o", "jmp"),
    (0x618B340, 0x618B330, 0x618B350,
     "rocksdb::PlainTableBuilder::GetFileChecksumFuncName",
     "85d8dc4d32f101fc-plain_table_builder.o", "jmp"),
]
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-get-file-checksum-func-name-115"
CASES = PACKET / "cases.tsv"


class GeneratorThrew(Exception):
    """The generator's Name threw (propagates, no LSDA)."""


def get_file_checksum_func_name(writer, gen_name=None,
                                gen_throws=False):
    """The binary's dispatch, on the writer state.

    writer: {"checksum_generator": None | {"name": str}}.
    gen_name: the string the generator's Name returns (None when
        no generator is set).
    Returns {"func_name": str}. Raises GeneratorThrew when the
    generator's Name throws (before any return: the tail jump
    leaves no frame of this function, so the throw reaches this
    function's caller directly).
    """
    gen = writer["checksum_generator"]
    if gen is None:
        return {"func_name": UNKNOWN_LITERAL}
    if gen_throws:
        raise GeneratorThrew(gen["name"])
    return {"func_name": gen_name}


def run_case(inputs):
    """Run one case. Inputs: generator (None or name string),
    gen_name (str or None), gen_throws (bool), and optionally
    invariant."""
    writer = {"checksum_generator":
              None if inputs["generator"] is None
              else {"name": inputs["generator"]}}
    try:
        out = get_file_checksum_func_name(
            writer, gen_name=inputs.get("gen_name"),
            gen_throws=inputs.get("gen_throws", False))
        out = {"generator": inputs["generator"],
               "gen_name": inputs.get("gen_name"),
               "gen_throws": inputs.get("gen_throws", False),
               "outcome": "ok", "func_name": out["func_name"]}
    except GeneratorThrew:
        out = {"generator": inputs["generator"],
               "gen_name": inputs.get("gen_name"),
               "gen_throws": inputs.get("gen_throws", False),
               "outcome": "generator_throw", "func_name": None}
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
        return {"calls": 3, "jumps": 3, "lea_refs": 0}
    raise ValueError(name)


# Name payloads: 10 lengths x 5 patterns = 50 variants.
# Patterns cover empty, short ASCII, hex, printable arithmetic
# bytes and FileChecksum-prefixed values; Name() returns a
# pointer, so the model pins the pointed-to string verbatim.
_NAME_LENS = [0, 1, 2, 3, 4, 8, 16, 32, 64, 128]


def _pattern(kind, n):
    if kind == 0:
        return "a" * n
    if kind == 1:
        return ("0123456789abcdef" * ((n + 15) // 16))[:n]
    if kind == 2:
        return "".join(chr(33 + (i * 37 + 11) % 94)
                       for i in range(n))
    if kind == 3:
        return ("FileChecksum" * ((n + 11) // 12))[:n]
    return ("Ab9_" * ((n + 3) // 4))[:n]


NAME_VALUES = [_pattern(k, n) for n in _NAME_LENS for k in range(5)]
GENERATORS = [None, "FileChecksumGenCrc32c"]
# Edge conditions: (gen_throws, name_mode). name_mode "value"
# uses the case value, "empty" forces "", "unknown" forces the
# literal "Unknown" (same value as the null branch, different
# path -- the pointer differs).
EDGE_CONDITIONS = [
    (False, "value"),
    (True, "value"),
    (False, "empty"),
    (True, "empty"),
    (False, "unknown"),
]


def _edge_name(mode, value):
    if mode == "value":
        return value
    if mode == "empty":
        return ""
    return UNKNOWN_LITERAL


def gen_cases():
    """300 deterministic cases: 100 checks + 100 edge + 100 bindings."""
    rows = []
    # checks: 50 name variants x 2 generator states.
    for gen in GENERATORS:
        for value in NAME_VALUES:
            rows.append(("checks", f"checks-{len(rows):04d}",
                         {"case_id": f"checks-{len(rows):04d}",
                          "group": "checks", "generator": gen,
                          "gen_name": value if gen else None,
                          "gen_throws": False},
                         run_case({"generator": gen,
                                   "gen_name": value if gen else None,
                                   "gen_throws": False})))
    # edge: 10 name values x 2 generator states x 5 conditions.
    # A null generator never calls, so gen_throws and the name
    # mode are vacuous there; the null branch still returns
    # "Unknown".
    edge_values = NAME_VALUES[::5]
    assert len(edge_values) == 10, len(edge_values)
    for gen in GENERATORS:
        for value in edge_values:
            for gen_throws, mode in EDGE_CONDITIONS:
                inputs = {"case_id": f"edge-{len(rows) - 100:04d}",
                          "group": "edge", "generator": gen,
                          "gen_name": _edge_name(mode, value)
                          if gen else None,
                          "gen_throws": gen_throws}
                rows.append(("edge", inputs["case_id"], inputs,
                             run_case(inputs)))
    assert len(rows) == 200, len(rows)
    # bindings: 25 (generator, name) pairs x 4 invariants.
    bind_pairs = []
    for gen in GENERATORS:
        for value in NAME_VALUES[:13]:
            bind_pairs.append((gen, value))
    bind_pairs = bind_pairs[:25]
    invariants = ["body_sha256", "source_sha256", "fde_record",
                  "caller_census"]
    for gen, value in bind_pairs:
        for inv in invariants:
            inputs = {"case_id": f"bindings-{len(rows) - 200:04d}",
                      "group": "bindings", "invariant": inv,
                      "generator": gen,
                      "gen_name": value if gen else None,
                      "gen_throws": False}
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
    literal, caller census, model end-to-end. Returns exit code."""
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
    leg(len(body) == 40, "body length 40")
    leg(hashlib.sha256(body).hexdigest() == BODY_SHA256, "body hash")
    src = bytearray(body)
    src[35:39] = b"\x00\x00\x00\x00"
    leg(hashlib.sha256(bytes(src)).hexdigest() == SOURCE_SHA256,
        "source hash (zero 1 kind-2 reloc @35)")
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
    leg(got == INSTRUCTIONS, f"9 instructions verbatim "
        f"({len(insns)} decoded)")
    leg(sum(1 for i in insns if i.mnemonic == "call") == 0, "0 calls")
    leg([i for i in insns if i.mnemonic == "jmp"
         and i.op_str == "qword ptr [rax + 0x28]"] != [],
        "indirect tail jump to vtable slot 5 (Name)")
    leg(sum(1 for i in insns if i.mnemonic == "ret") == 1, "1 ret")
    leg(all(START <= int(i.op_str, 16) < END
            for i in insns if i.mnemonic in ("je", "jne")),
        "the conditional jump stays inside the FDE")
    # The null-branch literal: the lea targets 0x974e00, which
    # holds "Unknown" in .rodata.
    lea = [i for i in insns if i.mnemonic == "lea"][0]
    disp = int(lea.op_str.split("rip - ")[1].rstrip("]"), 16)
    target = lea.address + lea.size - disp
    m2 = re.search(r"\.rodata\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
                   r"([0-9a-f]+)", out)
    rva, roff, _rsize = (int(m2.group(i), 16) for i in (1, 2, 3))
    lit = data[roff + (target - rva):
               roff + (target - rva) + len(UNKNOWN_LITERAL) + 1]
    leg(target == UNKNOWN_LITERAL_VA,
        f"lea targets 0x{target:x} (Unknown literal)")
    leg(lit == UNKNOWN_LITERAL.encode() + b"\x00",
        "literal bytes are 'Unknown' + NUL")
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
    leg(sorted(sites) == sorted(
        (s, kind) for s, _, _, _, _, kind in CALLERS),
        f"caller census: 3 direct calls + 3 tail jumps, 0 LEA refs "
        f"({len(sites)} validated)")
    # Model end-to-end legs.
    ok = True
    null_writer = {"checksum_generator": None}
    gen_writer = {"checksum_generator": {"name": "FileChecksumGenCrc32c"}}
    ok = ok and get_file_checksum_func_name(null_writer) == \
        {"func_name": "Unknown"}
    ok = ok and get_file_checksum_func_name(
        null_writer, gen_name="ignored") == {"func_name": "Unknown"}
    ok = ok and get_file_checksum_func_name(
        gen_writer, gen_name="FileChecksumCrc32c") == \
        {"func_name": "FileChecksumCrc32c"}
    ok = ok and get_file_checksum_func_name(
        gen_writer, gen_name="") == {"func_name": ""}
    ok = ok and get_file_checksum_func_name(
        gen_writer, gen_name="Unknown") == {"func_name": "Unknown"}
    try:
        get_file_checksum_func_name(gen_writer, gen_name="x",
                                    gen_throws=True)
        ok = False
    except GeneratorThrew:
        pass
    # A null generator never calls, so gen_throws is vacuous there.
    ok = ok and get_file_checksum_func_name(
        null_writer, gen_throws=True) == {"func_name": "Unknown"}
    leg(ok, "model end-to-end (null/present x empty/Unknown, "
            "throw, vacuous throw)")
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
    print("usage: get_file_checksum_func_name115.py "
          "[--live | --write-cases | --verify-cases]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
