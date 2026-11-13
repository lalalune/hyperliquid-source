#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
range. The FDE is vendor-census-bound (member
4d429ab1cb2d8f8b-db_impl_open.o, librocksdb-sys 0.11.0+8.1.1); its
source hash is reproduced exactly by zeroing the 21 census
relocations (kinds 2/4, no relaxation). The FDE has NO LSDA: its
.eh_frame augmentation length is 0 (record at section offset
0x3533f4, length 0x20, initial_location 0x5e59cd0, range 0x303),
so there is no landing pad, no catch and no cleanup in this FDE.
"""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# (start, end, name, slug, census-bound?)
FUNCS = [
    ("0x5e59cd0", "0x5e59fd3",
     "rocksdb::DBImpl::ValidateOptions",
     "dbimpl-validate-options-1arg-5e59cd0", True),
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
        source_hash = hashlib.sha256(bytes(zeroed)).hexdigest()
        assert source_hash == rec["source_body_sha256"], name
        relocs = ";".join(
            "%d:kind%d" % (r["offset"], r["kind"])
            for r in rec["relocations"])
        symbol = rec["symbol"]
        raw_equal = str(rec["raw_equal"])
        row = {
            "name": name, "start": start_s, "end": end_s,
            "size": str(end - start), "body_sha256": body_hash,
            "source_sha256": source_hash,
            "raw_equal": raw_equal,
            "relocations": relocs,
            "census_id": "node115-vendor-%s" % start_s[2:],
            "symbol": symbol,
            "excerpt": slug + ".objdump.txt", "hex": slug + ".hex",
        }
        functions[start_s] = {
            "body_sha256": body_hash,
            "source_sha256": source_hash,
            "relocations": relocs,
            "census_id": row["census_id"],
            "mangled": symbol,
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
    main_calls = [s for s in sites if s["target"] == "0x5e59cd0"]
    functions["0x5e59cd0"]["callers"] = [s["site"] for s in main_calls]
    functions["0x5e59cd0"]["model"] = (
        "771-byte one-argument validator "
        "DBImpl::ValidateOptions(const DBOptions&) (result by value, "
        "sret out in rdi = rbx; db_options in rsi; stack canary "
        "used). Nine checks in binary order, first failure wins: "
        "db_paths byte size > 0xa0 (4 DbPaths of 0x28 bytes) -> "
        "NotSupported; allow_mmap_reads && use_direct_reads -> "
        "NotSupported; allow_mmap_writes && "
        "use_direct_io_for_flush_and_compaction -> NotSupported; "
        "keep_log_file_num == 0 -> InvalidArgument; unordered_write "
        "&& !allow_concurrent_memtable_write -> InvalidArgument; "
        "unordered_write && enable_pipelined_write -> "
        "InvalidArgument; atomic_flush && enable_pipelined_write -> "
        "InvalidArgument; atomic_flush && best_efforts_recovery -> "
        "InvalidArgument; use_direct_io_for_flush_and_compaction && "
        "writable_file_max_buffer_size == 0 -> InvalidArgument; "
        "else OK. Each error block builds two Slices on the stack "
        "(msg + the empty msg2 at 0x4376fd) and calls the Status "
        "ctor 0x61cf670 with (out, code, subcode 0, &msg, &msg2, "
        "severity 0); the ctor writes code u8 +0x0, subcode u8 "
        "+0x1, severity u8 +0x2, zeroes +0x3..+0x5, and sets state_ "
        "to a new char[len+1] buffer holding msg + NUL (msg2 is "
        "always empty here). The OK path writes out = {0, 0, "
        "nullptr} with movl + movw + movq. Bytes +0x6..+0x7 are "
        "never written by any path. The single epilogue checks the "
        "stack canary and returns out. NO LSDA: the FDE "
        "augmentation length is 0, so a bad_alloc from the Status "
        "ctor propagates straight through with no cleanup in this "
        "frame; the caller's pad handles it.")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-dbimpl-validate-options-115 (open, "
            "PR #6342): reconstructs the two-argument dispatcher "
            "0x5e5a000, which calls this one-argument overload once "
            "(site 0x5e5a0ee) after every column family passed. The "
            "dispatcher packet's reference oracle for this function "
            "is superseded by this full reconstruction.",
            "RE-002-node115-rocksdb-build-db-options-115 (open, PR "
            "#6297): reconstructs BuildDBOptions 0x60c2e20, which "
            "builds the DBOptions this validator checks; the "
            "default-ctor packet (open PR #6337, 0x60b2db0) builds "
            "the 93 defaults and pins the field offsets this FDE "
            "reads (db_paths +0x70/+0x78, allow_mmap_reads +0x128, "
            "allow_mmap_writes +0x129, use_direct_reads +0x12a, "
            "use_direct_io_for_flush_and_compaction +0x12b, "
            "keep_log_file_num +0xf0, writable_file_max_buffer_size "
            "+0x180, enable_pipelined_write +0x1d0, unordered_write "
            "+0x1d1, allow_concurrent_memtable_write +0x1d2, "
            "atomic_flush +0x218, best_efforts_recovery +0x238).",
            "RE-002-node115-vendor-census: this FDE is census-bound "
            "(member 4d429ab1cb2d8f8b-db_impl_open.o, "
            "librocksdb-sys 0.11.0+8.1.1). Body fe207dc0... / source "
            "858395f2... (21 relocations, kinds 2/4, no relaxation).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "db/db_impl/db_impl_open.cc:243-298 defines this "
            "one-argument overload's nine checks in order "
            "(db_paths.size() > 4; allow_mmap_reads && "
            "use_direct_reads; allow_mmap_writes && "
            "use_direct_io_for_flush_and_compaction; "
            "keep_log_file_num == 0; unordered_write && "
            "!allow_concurrent_memtable_write; unordered_write && "
            "enable_pipelined_write; atomic_flush && "
            "enable_pipelined_write; atomic_flush && "
            "best_efforts_recovery; use_direct_io_for_flush_and_"
            "compaction && writable_file_max_buffer_size == 0), "
            "with the messages quoted verbatim (including the "
            "trailing space in the first three) and the first three "
            "as NotSupported, the rest as InvalidArgument. :229-241 "
            "defines the two-argument dispatcher. db/db_impl/"
            "db_impl.cc:1242 (SetDBOptions) confirms the second "
            "caller: after BuildDBOptions it calls ValidateOptions "
            "on the new DBOptions before validating each column "
            "family. NOTE: the #6342 packet cited this function as "
            ":392-484; the file read live this cycle has it at "
            ":243-298 -- the function content matches exactly.",
            "Binary-vs-source observations (recorded, not hidden): "
            "the binary checks the db_paths BYTE size (> 0xa0) "
            "rather than the element count -- the same rule, since "
            "DbPath is 0x28 bytes; the binary passes an empty "
            "second Slice to the Status ctor (the source calls "
            "NotSupported/InvalidArgument with one message, which "
            "delegates to the five-argument ctor with msg2 empty); "
            "the binary's check 7 is reached through two entries "
            "that share one +0x218 read, and check 8 is reached two "
            "ways -- the source's straight-line order is preserved, "
            "only the control flow is folded; the Status layout is "
            "code u8 +0x0, subcode u8 +0x1, severity u8 +0x2 "
            "(proved by the ctor at 0x61cf670), correcting the "
            "#6342 packet's loose wording of code u32 + subcode "
            "u16 -- behaviorally identical for the values pinned, "
            "since all three bytes are zero except the code byte.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "target, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "DBImpl::ValidateOptions 0x5e59cd0: exactly 2 direct "
                "calls, 0 tail jumps, 0 LEA refs -- the two-argument "
                "dispatcher 0x5e5a000 (site 0x5e5a0ee, census-bound, "
                "db_impl_open.o) and DBImpl::SetDBOptions 0x5d71fe0 "
                "(site 0x5d7256d, census-bound, db_impl.o). The "
                "validator runs once per DB open (after the column "
                "families pass) and once per SetDBOptions call (on "
                "the rebuilt DBOptions).",
                "NO LSDA: the FDE record in .eh_frame (section "
                "offset 0x3533f4, length 0x20, initial_location "
                "0x5e59cd0, range 0x303) has augmentation length 0, "
                "so there is no LSDA pointer, no call-site table, "
                "no landing pad, no catch and no cleanup in this "
                "FDE. The frame owns no destructible object (out is "
                "caller-owned sret; the canary is not a C++ "
                "object), so an exception from either Status ctor "
                "call needs no cleanup here.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 checks (each check failing alone, pairs "
                     "where the earlier one must win, boundaries: "
                     "4 vs 5 db_paths, keep_log 1 vs 0, buffer 1 vs "
                     "0, mixed bools) + 600 status (OK image, each "
                     "error image with code/subcode/severity/pad/"
                     "state_ content, the ctor's ': ' join with a "
                     "non-empty msg2) + 600 throw (BadAlloc in the "
                     "Status ctor at each of the 9 error sites with "
                     "the half-built status attached and no cleanup "
                     "in this frame, canary failures on OK and error "
                     "returns, BadAlloc beating a bad canary) + 600 "
                     "bindings (caller-site independence across "
                     "both callers, FDE/LSDA hashes as expected "
                     "values)",
            "tests": "tests/test_dbimpl_validate_options_1arg115.py",
            "tool": "tools/dbimpl_validate_options_1arg115.py",
            "what_is_checked": [
                "checks: the first failing check wins (later checks "
                "never run); the db_paths byte-size rule (4 x 0x28 "
                "= 160 = the 0xa0 limit, exactly OK; 5 fail); the "
                "bool-quad and u64 field reads at their exact "
                "offsets; check 7 reached through both entries and "
                "check 8 through both entries",
                "status: the Status byte layout the ctor proves "
                "(code u8 +0x0, subcode u8 +0x1, severity u8 +0x2, "
                "padding +0x3..+0x7 zero with +0x6..+0x7 unwritten, "
                "state_ +0x8); the state_ buffer is msg + NUL with "
                "alloc len+1; the ctor's ': ' join when msg2 is "
                "non-empty (ctor behavior, never fired by this FDE)",
                "throw: a BadAlloc from the Status ctor leaves out "
                "half-built (code/subcode/severity written, state_ "
                "null) and runs NO cleanup in this frame (no LSDA); "
                "canary failures raise StackCheckFailed on the "
                "return path only -- a throw never reaches the "
                "epilogue, so it is not masked by a canary failure",
                "bindings: the result depends only on the options, "
                "never on the caller site; the FDE body hash, the "
                "source hash (21 relocations zeroed), the no-LSDA "
                "fact and the engine-call counts match the binary",
            ],
        },
        "engine_callees": {
            "0x61cf670": "rocksdb::Status::Status(Code, SubCode, "
                         "const Slice&, const Slice&, Severity) "
                         "(247 B, census-bound, status.o): the "
                         "five-argument Status ctor, called twice "
                         "(0x5e59e06 with code 3, 0x5e59f2e with code "
                         "4). ORACLE in the sense that its body is "
                         "not reconstructed here -- but its observable "
                         "behavior IS pinned from its disassembly: "
                         "code u8 +0x0, subcode u8 +0x1, severity u8 "
                         "+0x2, zeroes +0x3..+0x5, state_ = new "
                         "char[size+1] holding msg + (': ' + msg2 if "
                         "len2) + NUL. Its trailing delete[] of the "
                         "old state_ is DEAD (state_ is zeroed at "
                         "0x61cf6b0 before the read at 0x61cf6e4).",
            "0x63f0d70": "PLT __stack_chk_fail: the canary failure "
                         "at the epilogue (0x5e59fce).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this VM. "
            "The target binary is never executed. The tool models the "
            "validator in Python from its whole-FDE disassembly; the "
            "Status ctor's observable behavior is pinned from its "
            "own disassembly (its body is not reconstructed here). "
            "Status state_ buffers are deterministic heap ids, not "
            "real pointers; the subcode padding bytes (+0x6..+0x7) "
            "the binary never writes are modelled as zero. The live "
            "check (--live) reads the binary: the FDE body hash, "
            "the source hash, the no-LSDA fact, the engine-call "
            "counts, the field cmp instructions, the nine message "
            "bytes and the two-site caller census. make verify/test/"
            "catalogue-check in a tooled environment is still owed "
            "upstream.",
        "functions": functions,
        "layouts": {
            "status": {
                "+0x00": "code (u8; the Code enum; 0 = kOk). Written "
                         "by the ctor (mov %sil) and by the OK path "
                         "(movl $0x0 covers +0x0..+0x3).",
                "+0x01": "subcode (u8). Written by the ctor "
                         "(mov %dl); 0 in every result this FDE "
                         "produces.",
                "+0x02": "severity (u8). Written by the ctor "
                         "(mov %r9b); 0 in every result this FDE "
                         "produces.",
                "+0x03": "padding (5 bytes, +0x3..+0x7). The ctor "
                         "writes +0x3..+0x5 zero; the OK path writes "
                         "+0x3..+0x5 zero; +0x6..+0x7 are NEVER "
                         "written by any path in this FDE -- modelled "
                         "as zero, recorded as unwritten.",
                "+0x08": "state_ (char*, 8 bytes). nullptr = no "
                         "message; otherwise a heap buffer of "
                         "len(msg)+1 bytes holding msg + NUL (msg2 "
                         "is always empty here), freed by the "
                         "caller's move/delete[], never in this FDE.",
                "size": "0x10 (16 bytes)",
            },
            "db_options_fields_read": {
                "+0x70/+0x78": "db_paths vector begin/end (byte size "
                              "= end - begin; limit 0xa0 = 4 DbPaths "
                              "of 0x28 bytes).",
                "+0x128": "allow_mmap_reads (bool).",
                "+0x129": "allow_mmap_writes (bool).",
                "+0x12a": "use_direct_reads (bool).",
                "+0x12b": "use_direct_io_for_flush_and_compaction "
                         "(bool; read twice).",
                "+0xf0": "keep_log_file_num (u64).",
                "+0x180": "writable_file_max_buffer_size (u64).",
                "+0x1d0": "enable_pipelined_write (bool; read "
                         "twice).",
                "+0x1d1": "unordered_write (bool).",
                "+0x1d2": "allow_concurrent_memtable_write (bool).",
                "+0x218": "atomic_flush (bool; read twice).",
                "+0x238": "best_efforts_recovery (bool).",
            },
            "lsda": "none: the FDE augmentation length is 0, so "
                    "there is no LSDA pointer, no call-site table, "
                    "no landing pad, no catch and no cleanup. The "
                    ".eh_frame record is at section offset 0x3533f4 "
                    "(length 0x20, initial_location 0x5e59cd0, range "
                    "0x303, aug_len 0, then the CFI instructions).",
            "landing_pads": "none in this FDE.",
            "error_blocks": {
                "0x5e59dc8": "check 1 (db_paths): msg 0x969600 len "
                            "47 -> NotSupported tail 0x5e59df1.",
                "0x5e59e78": "check 2 (mmap reads): msg 0x95e2f8 len "
                            "113 -> NotSupported tail 0x5e59df1.",
                "0x5e59d90": "check 3 (mmap writes): msg 0x967eb8 "
                            "len 138 -> NotSupported tail 0x5e59df1.",
                "0x5e59ef0": "check 4 (keep_log_file_num): msg "
                            "0x967670 len 40 -> InvalidArgument tail "
                            "0x5e59f19.",
                "0x5e59f40": "check 5 (unordered_write): msg "
                            "0x963508 len 69 -> InvalidArgument tail "
                            "0x5e59f19.",
                "0x5e59f70": "check 6 (pipelined): msg 0x96a248 len "
                            "59 -> InvalidArgument tail 0x5e59f19.",
                "0x5e59e46": "check 7 (atomic_flush+pipelined): msg "
                            "0x95ee48 len 56 -> InvalidArgument tail "
                            "0x5e59f19.",
                "0x5e59ebd": "check 8 (atomic_flush+best_efforts): "
                            "msg 0x965460 len 65 -> InvalidArgument "
                            "tail 0x5e59f19.",
                "0x5e59fa0": "check 9 (direct IO buffer): msg "
                            "0x95ee88 len 61 -> InvalidArgument tail "
                            "0x5e59f19.",
            },
        },
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
