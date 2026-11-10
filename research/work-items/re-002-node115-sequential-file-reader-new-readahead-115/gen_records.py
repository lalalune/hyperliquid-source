#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
ranges. Both FDEs are vendor-census-bound (member
a895f7517936a0f7-sequence_file_reader.o, librocksdb-sys
0.11.0+8.1.1); the source hashes are reproduced exactly by zeroing
the census relocations. The LSDA call-site table was decoded from
.gcc_except_table by hand (see records.json) and is recorded as
data, not re-derived here.
"""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BIN = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# (start, end, name, slug, census-bound?)
FUNCS = [
    ("0x6048c30", "0x6048d67",
     "rocksdb::SequentialFileReader::NewReadaheadSequentialFile",
     "sequential-file-reader-new-readahead-6048c30", True),
    ("0x6048bfe", "0x6048c30",
     "rocksdb::SequentialFileReader::NewReadaheadSequentialFile.cold",
     "sequential-file-reader-new-readahead-6048bfe-cold", True),
]


def va2off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BIN)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def _caller_sites():
    sites = []
    with open(PACKET / "callers.tsv") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            row = dict(zip(header, line.rstrip("\n").split("\t")))
            sites.append({
                "instruction": row["instruction"],
                "kind": row["kind"], "site": row["site"],
                "site_fde_end": row["site_fde_end"],
                "site_fde_start": row["site_fde_start"],
                "target": row["target"],
                "target_name": row["target_name"]})
    return sites


def main():
    data = open(BIN, "rb").read()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    census = json.load(open(
        ROOT / "research" / "work-items" / "RE-002-node115-vendor-census"
        / "census.json"))["records"]
    by_start = {r["start"]: r for r in census}
    rows = []
    functions = {}
    for start_s, end_s, name, slug, census_bound in FUNCS:
        start, end = int(start_s, 16), int(end_s, 16)
        body = data[va2off(start):va2off(end)]
        body_hash = hashlib.sha256(body).hexdigest()
        assert census_bound
        rec = by_start[start]
        assert body_hash == rec["target_body_sha256"], name
        zeroed = bytearray(body)
        for rel in rec["relocations"]:
            o, w = rel["offset"], rel["width"]
            zeroed[o:o + w] = b"\x00" * w
            if rel.get("relaxation") == "gotpcrelx-mov-lea":
                assert zeroed[o - 2] == 0x8D
                zeroed[o - 2] = 0x8B
        source_hash = hashlib.sha256(bytes(zeroed)).hexdigest()
        assert source_hash == rec["source_body_sha256"], name
        relocs = ";".join(
            "%d:kind%d%s" % (r["offset"], r["kind"],
                             "(mov-lea)" if r.get("relaxation")
                             == "gotpcrelx-mov-lea" else "")
            for r in rec["relocations"])
        row = {
            "name": name, "start": start_s, "end": end_s,
            "size": str(end - start), "body_sha256": body_hash,
            "source_sha256": source_hash,
            "raw_equal": str(rec["raw_equal"]),
            "relocations": relocs,
            "census_id": "node115-vendor-%s" % start_s[2:],
            "symbol": rec["symbol"],
            "excerpt": slug + ".objdump.txt", "hex": slug + ".hex",
        }
        functions[start_s] = {
            "body_sha256": body_hash,
            "source_sha256": source_hash,
            "relocations": relocs,
            "census_id": row["census_id"],
            "mangled": rec["symbol"],
            "callers": [],
            "lea_refs": [],
        }
        rows.append(row)
    with open(PACKET / "functions.tsv", "w") as fh:
        cols = ["name", "start", "end", "size", "body_sha256",
                "source_sha256", "raw_equal", "relocations", "census_id",
                "symbol", "excerpt", "hex"]
        fh.write("\t".join(cols) + "\n")
        for r in rows:
            fh.write("\t".join(r[c] for c in cols) + "\n")
    print("wrote functions.tsv (%d functions, all hashes verified)"
          % len(rows))

    # Caller census sites, read back from callers.tsv (no hand copy).
    sites = _caller_sites()
    main_calls = [s for s in sites if s["target"] == "0x6048c30"]
    functions["0x6048c30"]["callers"] = [s["site"] for s in main_calls]
    functions["0x6048c30"]["model"] = (
        "311-byte static factory std::unique_ptr<FSSequentialFile> "
        "SequentialFileReader::NewReadaheadSequentialFile("
        "std::unique_ptr<FSSequentialFile>&& file, size_t "
        "readahead_size) (hidden sret out unique_ptr in rdi, input "
        "unique_ptr* in rsi, readahead_size in rdx). (1) Gate "
        "(0x6048c47..0x6048c53): alignment = "
        "file->GetRequiredBufferAlignment() -- the virtual call "
        "through vtable slot 5 at 0x6048c4d; if alignment >= "
        "readahead_size (unsigned, jb), go to the move path. "
        "Upstream sequence_file_reader.cc:594, with the "
        "short-circuit comment. (2) Move path "
        "(0x6048c55..0x6048c72): out->ptr = file.ptr; file.ptr = "
        "nullptr; return out. (3) Wrap path (0x6048c78..): "
        "operator new(0x80) for the ReadaheadSequentialFile "
        "(PLT _Znwm 0x63f0dd0). (4) vptr + file_ "
        "(0x6048c82..0x6048c9e): the input file pointer is moved "
        "out (file.ptr = nullptr) and stored at +0x8; the vtable "
        "pointer at +0x0 is the LEA at 0x6048c91 to 0x64d1d80. "
        "(5) Second alignment call (0x6048c9b..0x6048ca2): "
        "alignment = file_->GetRequiredBufferAlignment() AGAIN "
        "(the ctor init list, sequence_file_reader.cc:303); the "
        "binary never reuses the gate result; alignment_ (+0x10) "
        "is set from this second call. (6) Roundup "
        "(0x6048ca5..0x6048ced): readahead_size_ (+0x18) = "
        "Roundup(readahead_size, alignment_) via div "
        "(util/aligned_buffer.h:62); a zero alignment faults "
        "(#DE) here. (7) AlignedBuffer init "
        "(0x6048cb6..0x6048ce9): lock_ (+0x20, 40 B) zeroed; "
        "buffer_.alignment_ (+0x48) = alignment_; buffer_.buf_ "
        "(+0x50) = nullptr; buffer_.capacity_ (+0x58) and "
        "buffer_.cursize_ (+0x60) zeroed; buffer_.bufstart_ "
        "(+0x68) = nullptr; buffer_offset_ (+0x70) and "
        "read_offset_ (+0x78) zeroed. (8) AllocateNewBuffer "
        "(0x6048cf2..0x6048d2f): new_capacity = "
        "Roundup(readahead_size_, alignment_) (= readahead_size_); "
        "buf_ = new char[new_capacity + alignment_] (PLT _Znam "
        "0x63f0e30); capacity_ (+0x58) = new_capacity; cursize_ "
        "(+0x60) = 0; bufstart_ (+0x68) = (buf_ + alignment_ - 1) "
        " & -alignment_; the old buf_ (nullptr) is delete[]'d only "
        "if non-null. (9) Return (0x6048d3d..0x6048d4e): out->ptr "
        "= the new object; return out. The two endbr64 stubs at "
        "the tail (0x6048d4f, 0x6048d5b) are the LSDA landing "
        "pads: they save the exception in rbp and jump into "
        ".cold (0x6048bfe and 0x6048c0c).")
    functions["0x6048bfe"]["model"] = (
        "50-byte landing pad (.cold) for NewReadaheadSequentialFile. "
        "Full entry (0x6048bfe, pad for the operator new[] call at "
        "0x6048d07 via stub 0x6048d4f): delete[] buffer_.buf_ "
        "(+0x50) if non-null (PLT _ZdaPv 0x63f0dc0); delete file_ "
        "(+0x8) via its virtual deleting destructor (vtable slot "
        "1) if non-null; sized operator delete (0x80 bytes, PLT "
        "_ZdlPvm 0x63f0d80); _Unwind_Resume (PLT 0x63f0a50). "
        "Second entry (0x6048c0c, pad for the ctor's "
        "GetRequiredBufferAlignment() call at 0x6048ca2 via stub "
        "0x6048d5b): the same minus the buf_ delete[] -- buf_ is "
        "still null at that call site. The LSDA call-site table "
        "(decoded from .gcc_except_table) has three entries: "
        "FDE+0x1d..+0x52 (gate call + operator new(0x80)) with NO "
        "landing pad; FDE+0x72..+0x75 (ctor alignment call) -> pad "
        "0x6048d5b; FDE+0xd7..+0xdc (operator new[] call) -> pad "
        "0x6048d4f. All actions are 0.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-line-file-reader-readline-115 "
            "(open, PR #6228): reconstructs "
            "LineFileReader::ReadLine 0x60d4cf0, whose reader is "
            "built through this factory -- Parse constructs the "
            "LineFileReader on its stack, forwarding to the "
            "SequentialFileReader readahead constructor, which "
            "calls this factory at the inlined site 0x60cfec4. "
            "This packet supplies the factory that packet took "
            "as an oracle.",
            "SequentialFileReader::Read 0x6048e00 (open, PR #5992) "
            "and log::Reader::ReadMore 0x5f018d0 (merged, PR "
            "#5986): the SequentialFileReader family this factory "
            "feeds -- every SequentialFileReader built with a "
            "readahead size holds the wrapper this factory "
            "builds; the wrapper's own Read/Skip are separate "
            "FDEs (0x60486f0 / 0x6048ac0) and are NOT modelled "
            "here, only the factory + the inlined constructor.",
            "RE-002-node115-vendor-census: BOTH FDEs are "
            "census-bound (member "
            "a895f7517936a0f7-sequence_file_reader.o, "
            "librocksdb-sys 0.11.0+8.1.1). Main FDE body "
            "487104cb... / source 2acc4f4d... (6 relocations, "
            "kinds 2/4); .cold body 204e9c9a... / source "
            "017b892e... (3 relocations, kind 4). The census "
            "mislabels 0x6048640 as ReadaheadRandomAccessFile::D1; "
            "the binary proves it is ReadaheadSequentialFile::D1 "
            "(it resets the vptr to 0x64d1d80, frees +0x50 with "
            "delete[] and virtual-deletes +0x8). The census "
            "0x60485e0 label (PositionedRead) is recorded but its "
            "arg plumbing is left open (see the tool docstring).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "file/sequence_file_reader.cc:588-610 defines "
            "NewReadaheadSequentialFile (the >= gate with the "
            "short-circuit comment at 594-600, then new "
            "ReadaheadSequentialFile at 604-608); :283-583 "
            "defines ReadaheadSequentialFile (ctor init list at "
            "297-317, members at 552-581 in the same order as "
            "the binary layout); file/sequence_file_reader.h:136-"
            "162 declares the readahead ctor overload that calls "
            "it, and :209-215 declares the factory itself; "
            "util/aligned_buffer.h:62 defines Roundup and "
            ":236-290 AllocateNewBuffer; "
            "include/rocksdb/file_system.h:1298-1415 declares "
            "FSSequentialFile's virtuals in vtable order (Read, "
            "Skip, use_direct_io, GetRequiredBufferAlignment "
            "returning kDefaultPageSize, InvalidateCache, "
            "PositionedRead, GetTemperature), matching the "
            "relocated vtable slots exactly.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "target, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "NewReadaheadSequentialFile 0x6048c30: exactly 4 "
                "direct calls, 0 tail jumps, 0 LEA refs. All four "
                "are the SequentialFileReader readahead "
                "constructor's init-list call "
                "(file/sequence_file_reader.h:150-154), inlined at "
                "three sites plus the standalone ctor FDE.",
                "At each inlined site the call is followed by the "
                "shared_ptr copy (0x5d35c00, "
                "std::__shared_count copy) installing the io_tracer "
                "into the SequentialFileReader's file_ wrapper -- "
                "exactly the ctor's file_(..., io_tracer, "
                "_file_name). Parse reaches it through the inlined "
                "LineFileReader forwarding-template ctor.",
                "The LSDA call-site table was decoded from "
                ".gcc_except_table by hand: the first entry covers "
                "both the gate call and the operator new(0x80) "
                "call with no landing pad; the ctor's alignment "
                "call maps to pad 0x6048d5b (skips the buf_ "
                "delete[]); the operator new[] call maps to pad "
                "0x6048d4f (full cleanup).",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 gate (alignment vs readahead_size across "
                     "the move/wrap boundary, incl. equality, zero, "
                     "and the zero-alignment fault) + 600 rounding "
                     "(Roundup(readahead, alignment) and the "
                     "AllocateNewBuffer recomputation across powers "
                     "and non-powers of two) + 600 layout (whole-"
                     "object field layout for wrapped objects, "
                     "aligned and misaligned fake heap bases) + 600 "
                     "bindings (lying files whose second alignment "
                     "call disagrees, the default 4096 alignment, "
                     "huge readaheads, move-path bindings)",
            "tests": "tests/test_sequential_file_reader_new_readahead115.py",
            "tool": "tools/sequential_file_reader_new_readahead115.py",
            "what_is_checked": [
                "gate: alignment >= readahead_size takes the move "
                "path (the same file comes back, the input is "
                "nulled, exactly one alignment call); equality "
                "moves; readahead 0 moves; alignment 0 with "
                "readahead > 0 faults in Roundup (ZeroDivisionError "
                "in the model, #DE in the binary)",
                "rounding: readahead_size_ is Roundup(readahead, "
                "alignment) by the div-based formula; capacity_ "
                "recomputes to the same value; alloc size is "
                "capacity + alignment; bufstart_ is the binary's "
                "mask formula (a true AlignUp only for power-of-"
                "two alignments; for non-powers the mask can round "
                "down, which the model reproduces)",
                "layout: the wrapped object is 0x80 bytes with "
                "vtable 0x64d1d80; file_ moved in at +0x8; "
                "alignment_ at +0x10 from the SECOND call; "
                "readahead_size_ at +0x18; lock_ 40 zero bytes at "
                "+0x20; buffer_ at +0x48 (alignment_, buf_, "
                "capacity_, cursize_ 0, bufstart_); buffer_offset_ "
                "and read_offset_ 0",
                "bindings: the FDE body and source hashes match "
                "the binary and the census; the 4 caller-census "
                "sites are pinned; the vtable slots match the "
                ".rela.dyn entries; the LSDA's 3 call-site entries "
                "and 2 landing pads are pinned; a lying file takes "
                "its gate from call 1 and its layout from call 2",
            ],
        },
        "engine_callees": {
            "0x6048640": "ReadaheadSequentialFile::~ReadaheadSequentialFile "
                         "(complete destructor, D1): resets the vptr to "
                         "0x64d1d80, delete[]s buffer_.buf_ (+0x50) if "
                         "non-null, virtual-deletes file_ (+0x8) via "
                         "vtable slot 1. The vendor census mislabels "
                         "this address as ReadaheadRandomAccessFile::D1; "
                         "the binary proves the sequential identity. "
                         "It is vtable slot 0.",
            "0x6048680": "ReadaheadSequentialFile::~ReadaheadSequentialFile "
                         "(deleting destructor, D0): the D1 body plus "
                         "the sized operator delete of the 0x80-byte "
                         "object. It is vtable slot 1.",
            "0x6025720": "FSSequentialFile::GetRequiredBufferAlignment "
                         "(inherited default, vtable slot 5): mov "
                         "$0x1000, %eax; ret -- returns kDefaultPageSize "
                         "4096. ReadaheadSequentialFile does not override "
                         "it, so a plain file reports 4096 and takes the "
                         "move path for any readahead_size <= 4096.",
            "0x60486f0": "ReadaheadSequentialFile::Read (vtable slot 2): "
                         "the wrapper's cached Read; NOT modelled here "
                         "(its own FDE).",
            "0x6048ac0": "ReadaheadSequentialFile::Skip (vtable slot 3): "
                         "the wrapper's Skip; NOT modelled here.",
            "0x6048630": "ReadaheadSequentialFile::use_direct_io (vtable "
                         "slot 4): a delegating thunk -- jmp to the "
                         "wrapped file's vtable slot 4.",
            "0x60489e0": "ReadaheadSequentialFile::InvalidateCache "
                         "(vtable slot 6): NOT modelled here.",
            "0x60485e0": "ReadaheadSequentialFile::PositionedRead "
                         "(vtable slot 7, census label): forwards to the "
                         "wrapped file's vtable slot 7; the arg plumbing "
                         "is left open (see the tool docstring). NOT "
                         "modelled here.",
            "0x63f0dd0": "PLT operator new _Znwm: the 0x80-byte object "
                         "allocation (0x6048c7d).",
            "0x63f0e30": "PLT operator new[] _Znam: the buffer allocation "
                         "new char[capacity + alignment] (0x6048d07).",
            "0x63f0dc0": "PLT operator delete[] _ZdaPv: frees the old "
                         "buffer_.buf_ in AllocateNewBuffer (skipped, "
                         "null) and in .cold.",
            "0x63f0d80": "PLT operator delete _ZdlPvm: the sized delete "
                         "of the 0x80-byte object in the D0 and in .cold.",
            "0x63f0a50": "PLT _Unwind_Resume: the .cold epilogue.",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this VM. "
            "The target binary is never executed. The tool models the "
            "factory in Python; the wrapped file's Read/Skip/etc. are "
            "scripted as oracles (their record bytes are the "
            "ReadaheadSequentialFile method subjects, not reimplemented "
            "here); heap addresses are deterministic fake bases, not real "
            "pointers; the buffer bytes are uninitialised new char[] and "
            "are modelled as a size, not content. The live engine check "
            "wraps real files in a temp dir and asserts the model fields "
            "against the binary's arithmetic and the wrapped file's bytes "
            "against the real file. make verify/test/catalogue-check in a "
            "tooled environment is still owed upstream.",
        "functions": functions,
        "layouts": {
            "readahead_sequential_file": {
                "+0x00": "vptr (ReadaheadSequentialFile vtable, 0x64d1d80) "
                         "-- stored by the LEA at 0x6048c91; reset to the "
                         "same value by both destructors",
                "+0x08": "file_ (std::unique_ptr<FSSequentialFile>) -- the "
                         "moved-in wrapped file; deleted via its virtual "
                         "deleting destructor (slot 1) in the D1/D0/.cold",
                "+0x10": "alignment_ (const size_t) -- the SECOND "
                         "GetRequiredBufferAlignment() call "
                         "(0x6048c9b..0x6048ca2)",
                "+0x18": "readahead_size_ (const size_t) -- "
                         "Roundup(readahead_size, alignment_)",
                "+0x20": "lock_ (std::mutex, 40 B) -- zeroed by the ctor",
                "+0x48": "buffer_.alignment_ (size_t) -- = alignment_",
                "+0x50": "buffer_.buf_ (std::unique_ptr<char[]>) -- new "
                         "char[capacity + alignment]; delete[]'d in the "
                         "D1/D0/.cold",
                "+0x58": "buffer_.capacity_ (size_t) -- = readahead_size_ "
                         "(Roundup recomputed by AllocateNewBuffer)",
                "+0x60": "buffer_.cursize_ (size_t) -- 0",
                "+0x68": "buffer_.bufstart_ (char*) -- (buf_ + alignment_ "
                         "- 1) & -alignment_",
                "+0x70": "buffer_offset_ (uint64_t) -- 0",
                "+0x78": "read_offset_ (uint64_t) -- 0",
            },
            "vtable_0x64d1d80": {
                "slot 0 (0x64d1d80)": "D1 complete destructor 0x6048640",
                "slot 1 (0x64d1d88)": "D0 deleting destructor 0x6048680",
                "slot 2 (0x64d1d90)": "Read 0x60486f0",
                "slot 3 (0x64d1d98)": "Skip 0x6048ac0",
                "slot 4 (0x64d1da0)": "use_direct_io 0x6048630 "
                                      "(delegating thunk)",
                "slot 5 (0x64d1da8)": "GetRequiredBufferAlignment 0x6025720 "
                                      "(inherited default, returns 4096)",
                "slot 6 (0x64d1db0)": "InvalidateCache 0x60489e0",
                "slot 7 (0x64d1db8)": "PositionedRead 0x60485e0 "
                                      "(arg plumbing left open)",
                "typeinfo (0x64d1d78)": "-> 0x64d1d58 (RELATIVE reloc)",
            },
            "lsda_call_sites": {
                "FDE+0x1d..+0x52": "gate GetRequiredBufferAlignment() call "
                                   "(0x6048c4d) + operator new(0x80) call "
                                   "(0x6048c7d) -- NO landing pad",
                "FDE+0x72..+0x75": "ctor GetRequiredBufferAlignment() call "
                                   "(0x6048ca2) -- landing pad 0x6048d5b "
                                   "(-> 0x6048c0c, skips the buf_ delete[])",
                "FDE+0xd7..+0xdc": "operator new[] call (0x6048d07) -- "
                                   "landing pad 0x6048d4f (-> 0x6048bfe, "
                                   "full cleanup)",
            },
        },
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
