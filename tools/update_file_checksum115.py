#!/usr/bin/env python3
"""Reconstruction of node #115 rocksdb::WritableFileWriter::UpdateFileChecksum.

Target: rocksdb::WritableFileWriter::UpdateFileChecksum(const Slice&)
at 0x604c7b0..0x604c7d1 (33 B, single FDE) in node #115
(work/hl-node-115.bin, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The second function in the small-item queue (Chi, 2026-11-11): a
33-byte leaf that forwards appended data to the writer's file
checksum generator, if one is set. Exactly one caller:
WritableFileWriter::Append (site 0x6054764), which calls it once
per Append before PrepareWrite; upstream RocksDB v8.1.1 calls it
at the same single site (file/writable_file_writer.cc:59).

Whole-FDE facts (verified live, see --live):
- Signature: void (this in rdi, data Slice* in rsi: data.data()
  at (%rsi), data.size() at 0x8(%rsi)). No stack frame, no canary,
  no calls, no LSDA, no .cold FDE. The .eh_frame record at section
  offset 0x367168 has length 0x10, range 0x21, aug_len 0.
- Body hash matches the vendor census target_body_sha256 exactly
  (raw_equal, zero relocations): member
  a895f7517936a0f7-writable_file_writer.o, librocksdb-sys
  0.11.0+8.1.1, symbol
  _ZN7rocksdb18WritableFileWriter18UpdateFileChecksumERKNS_5SliceE.
- Decision (10 instructions, 1 conditional jump, 1 tail jump,
  1 ret): load this+0xc8 (checksum_generator_, a
  std::unique_ptr<FileChecksumGenerator> per
  file/writable_file_writer.h:163); if null, return; else tail-jump
  to vtable slot 2 of the generator with (data.data(),
  data.size()). Slot 2 is Update: FileChecksumGenerator's virtuals
  occupy six vtable entries in declaration order -- the two
  Itanium ABI destructor slots (complete-object dtor, deleting
  dtor), then Update, Finalize, GetChecksum, Name
  (include/rocksdb/file_checksum.h:52-67) -- so the third entry
  (0x10 past the vptr) is Update(const char*, size_t). The
  concrete checksum algorithm is the generator's own behavior --
  already reconstructed for the CRC32C/XXH generators in earlier
  RE-002 packets -- not this function's; this model pins the
  dispatch and the forwarded arguments only.
- The 3-byte nop at 0x604c7cd is alignment padding inside the FDE
  (the ret at 0x604c7d0 is the fall-through of the je). The tail
  jump transfers control to Update with Append's return address
  still on the stack, so Update returns to Append, at the
  instruction after the call site -- not to Append's caller.

Environment limits: no cargo/rustc/git-lfs/Ghidra on this VM. The
target binary is never executed. The tool models the helper in
Python from its whole-FDE disassembly. Data pointers are
deterministic ids, not real addresses.
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
START = 0x604C7B0
END = 0x604C7D1
BODY_SHA256 = ("1f2a30cf85914602784dea75923fb645ef27bc3bfc508a05a578"
               "72ab6d25dd63")
SOURCE_SHA256 = BODY_SHA256  # raw_equal: zero relocations
RELOCATIONS = ""
MEMBER = "a895f7517936a0f7-writable_file_writer.o"
SYMBOL = ("_ZN7rocksdb18WritableFileWriter18UpdateFileChecksumERK"
          "NS_5SliceE")
# FDE record in .eh_frame (section offset 0x367168): length 0x10,
# range 0x21, aug_len 0 -- no LSDA pointer, no landing pad.
FDE_SECTION_OFFSET = 0x367168
FDE_LENGTH = 0x10
FDE_RANGE = 0x21
# The 10 instructions of the FDE, (address, mnemonic, op_str),
# in Capstone's Intel syntax (the .objdump.txt excerpt is the
# verbatim objdump rendering of the same bytes).
INSTRUCTIONS = [
    (0x604C7B0, "endbr64", ""),
    (0x604C7B4, "mov", "rdi, qword ptr [rdi + 0xc8]"),
    (0x604C7BB, "test", "rdi, rdi"),
    (0x604C7BE, "je", "0x604c7d0"),
    (0x604C7C0, "mov", "rax, qword ptr [rdi]"),
    (0x604C7C3, "mov", "rdx, qword ptr [rsi + 8]"),
    (0x604C7C7, "mov", "rsi, qword ptr [rsi]"),
    (0x604C7CA, "jmp", "qword ptr [rax + 0x10]"),
    (0x604C7CD, "nop", "dword ptr [rax]"),
    (0x604C7D0, "ret", ""),
]

# Callers: (site, caller start, caller name, member).
CALLERS = [
    (0x6054764, 0x6054680, "rocksdb::WritableFileWriter::Append",
     MEMBER),
]
PACKET = Path(__file__).resolve().parents[1] / "research" / \
    "work-items" / \
    "re-002-node115-rocksdb-writable-file-writer-update-file-checksum-115"
CASES = PACKET / "cases.tsv"


def _u64(v):
    return v & 0xFFFFFFFFFFFFFFFF


def update(writer, data):
    """The binary's dispatch, on the writer state and the Slice.

    writer: {"checksum_generator": None | {"name": str}}.
    data: {"ptr": str (deterministic id), "len": int (size_t)}.
    Returns {"called": bool, "update_call": None | {...}}.
    """
    gen = writer["checksum_generator"]
    n = _u64(data["len"])
    if gen is None:
        return {"called": False, "update_call": None}
    return {"called": True, "update_call": {
        "target": "FileChecksumGenerator::Update "
                  "(vtable slot 2, *0x10(%rax))",
        "this": gen["name"],
        "data_ptr": data["ptr"],
        "n": n}}


def run_case(inputs):
    """Run one case: inputs has generator (None or name string),
    data_ptr (str) and data_len (int), and optionally invariant."""
    writer = {"checksum_generator":
              None if inputs["generator"] is None
              else {"name": inputs["generator"]}}
    data = {"ptr": inputs["data_ptr"], "len": inputs["data_len"]}
    out = update(writer, data)
    out = {"generator": inputs["generator"],
           "data_ptr": inputs["data_ptr"],
           "data_len": _u64(inputs["data_len"]),
           "called": out["called"],
           "update_call": out["update_call"]}
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


# Data shapes: (ptr id, len). 10 lens x 5 ptr ids = 50 variants.
DATA_LENS = [0, 1, 2, 7, 8, 15, 16, 31, 32, 4096]
DATA_PTRS = ["buf", "direct", "heap", "stack", "mapped"]
DATA_VARIANTS = [(p, n) for n in DATA_LENS for p in DATA_PTRS]
EDGE_LENS = [0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
             0x100000000, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000,
             0xFFFFFFFFFFFFFFFF]
GENERATORS = [None, "FileChecksumGenCrc32c"]


def gen_cases():
    """300 deterministic cases: 100 checks + 100 edge + 100 bindings."""
    rows = []
    # checks: 50 data variants x 2 generator states.
    for gen in GENERATORS:
        for ptr, n in DATA_VARIANTS:
            rows.append(("checks", f"checks-{len(rows):04d}",
                         {"case_id": f"checks-{len(rows):04d}",
                          "group": "checks", "generator": gen,
                          "data_ptr": ptr, "data_len": n},
                         run_case({"generator": gen, "data_ptr": ptr,
                                   "data_len": n})))
    # edge: size_t extremes on either side; a null generator never
    # calls even for a huge len, a present generator is called even
    # for len 0 (the binary calls unconditionally when non-null).
    edge_pairs = []
    for n in EDGE_LENS:
        for gen in GENERATORS:
            for ptr in DATA_PTRS:
                edge_pairs.append((gen, ptr, n))
    assert len(edge_pairs) == 100, len(edge_pairs)
    for gen, ptr, n in edge_pairs:
        rows.append(("edge", f"edge-{len(rows) - 100:04d}",
                     {"case_id": f"edge-{len(rows) - 100:04d}",
                      "group": "edge", "generator": gen,
                      "data_ptr": ptr, "data_len": n},
                     run_case({"generator": gen, "data_ptr": ptr,
                               "data_len": n})))
    # bindings: 25 (generator, data) pairs x 4 recorded invariants.
    bind_pairs = []
    for gen in GENERATORS:
        for ptr, n in DATA_VARIANTS[:13]:
            bind_pairs.append((gen, ptr, n))
    bind_pairs = bind_pairs[:25]
    invariants = ["body_sha256", "source_sha256", "fde_record",
                  "caller_census"]
    for gen, ptr, n in bind_pairs:
        for inv in invariants:
            inputs = {"case_id": f"bindings-{len(rows) - 200:04d}",
                      "group": "bindings", "invariant": inv,
                      "generator": gen, "data_ptr": ptr, "data_len": n}
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
    leg(len(body) == 33, "body length 33")
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
    leg(got == INSTRUCTIONS, f"10 instructions verbatim "
        f"({len(insns)} decoded)")
    leg(all(i.mnemonic != "call" for i in insns), "0 call instructions")
    leg(sum(1 for i in insns if i.mnemonic == "ret") == 1, "1 ret")
    jmps = [i for i in insns if i.mnemonic == "jmp"]
    leg(len(jmps) == 1 and jmps[0].op_str == "qword ptr [rax + 0x10]",
        "1 tail jump to vtable slot 2")
    leg(all(START <= int(i.op_str, 16) < END
            for i in insns if i.mnemonic == "je"),
        "the conditional jump stays inside the FDE")
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
        f"caller census: 1 direct call, 0 jumps, 0 LEA refs "
        f"({len(sites)} validated)")
    # Model end-to-end legs.
    ok = True
    null_writer = {"checksum_generator": None}
    gen_writer = {"checksum_generator": {"name": "FileChecksumGenCrc32c"}}
    ok = ok and update(null_writer, {"ptr": "buf", "len": 4096}) == \
        {"called": False, "update_call": None}
    ok = ok and update(null_writer, {"ptr": "buf", "len": 0xFFFFFFFFFFFFFFFF}) == \
        {"called": False, "update_call": None}
    r = update(gen_writer, {"ptr": "buf", "len": 0})
    ok = ok and r["called"] and r["update_call"]["n"] == 0
    r = update(gen_writer, {"ptr": "heap", "len": 0x100000000})
    ok = ok and r["called"] and r["update_call"]["n"] == 0x100000000
    ok = ok and r["update_call"]["data_ptr"] == "heap"
    leg(ok, "model end-to-end (null/present x empty/huge/64-bit lens)")
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
    print("usage: update_file_checksum115.py "
          "[--live | --write-cases | --verify-cases]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
