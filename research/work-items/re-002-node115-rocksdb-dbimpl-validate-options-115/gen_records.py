#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
ranges. The main FDE is vendor-census-bound (member
4d429ab1cb2d8f8b-db_impl_open.o, librocksdb-sys 0.11.0+8.1.1); its
source hash is reproduced exactly by zeroing the 8 census
relocations (kinds 2/4, no relaxation). The .cold FDE has NO vendor
census record, so it is bound by body hash only (9a82fbb2...), per
the no-census convention. The LSDA call-site tables were decoded
from .gcc_except_table with the repo's tools/fde_extents.py FDE
index (main LSDA at 0x40fa2d, 10 bytes + 1 call-site entry; .cold
LSDA at 0x40fa37, 8 bytes + 1 entry; see records.json) and are
recorded as data, not re-derived here.
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
    ("0x5e5a000", "0x5e5a151",
     "rocksdb::DBImpl::ValidateOptions",
     "dbimpl-validate-options-5e5a000", True),
    ("0x5e59fd4", "0x5e59fff",
     "rocksdb::DBImpl::ValidateOptions.cold",
     "dbimpl-validate-options-5e59fd4-cold", False),
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
        if census_bound:
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
        else:
            assert body_hash == \
                "9a82fbb229028dc489614db7989d2521b930301f6fda856b380bed01ed468da2", \
                name
            source_hash = ""
            relocs = "no census record (body hash only)"
            symbol = ("rocksdb::DBImpl::ValidateOptions.cold "
                      "(no census record)")
            raw_equal = "n/a"
        row = {
            "name": name, "start": start_s, "end": end_s,
            "size": str(end - start), "body_sha256": body_hash,
            "source_sha256": source_hash,
            "raw_equal": raw_equal,
            "relocations": relocs,
            "census_id": "node115-vendor-%s" % start_s[2:] if census_bound
                         else "none (body hash only)",
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
    main_calls = [s for s in sites if s["target"] == "0x5e5a000"]
    functions["0x5e5a000"]["callers"] = [s["site"] for s in main_calls]
    functions["0x5e5a000"]["model"] = (
        "337-byte two-argument validator "
        "DBImpl::ValidateOptions(const DBOptions&, const "
        "vector<ColumnFamilyDescriptor>&) (result by value, sret out "
        "in rdi = rbx; db_options in rsi = r12; the descriptor vector "
        "in rdx, begin in rbp, end in r14; stack canary used). "
        "out = OK (code u32 +0x0 = 0, subcode u16 +0x4 = 0, state_ "
        "+0x8 = nullptr; padding +0x6..+0x7 never written). For each "
        "descriptor in order (stride 0x320): call "
        "ColumnFamilyData::ValidateOptions(db_options, "
        "descriptor.options at +0x20) 0x5d8e3b0 with the sret temp "
        "on the stack, MOVE the temp status into out (code u32 + "
        "subcode u16 + state_ ptr copied, temp zeroed, old "
        "out.state_ freed with operator delete[] if non-null), and "
        "if out.code != 0 return out at once (first failure wins; "
        "later column families and the DB-options check never run). "
        "After the loop -- including the empty-list case, which "
        "jumps straight here -- call DBImpl::ValidateOptions"
        "(db_options) 0x5e59cd0 (the one-argument overload), MOVE "
        "its result into out the same way, and return out. Only "
        "the code byte at out+0x0 is ever tested (movzbl (%rbx),"
        "%eax; test %al,%al; je). The descriptor NAME is never "
        "read. Both callees are oracles in this packet (see "
        "bound_context); the packet pins the dispatcher's loop, "
        "move, gate, LSDA and pad, and the call order/targets.")
    functions["0x5e59fd4"]["model"] = (
        "43-byte .cold landing-pad FDE for DBImpl::ValidateOptions. "
        "Entered only through the endbr64 stub at 0x5e5a145 (mov "
        "%rax,%rbp; jmp 0x5e59fd4). It frees out.state_ if non-null "
        "(operator delete[] PLT 0x63f0dc0), checks the stack canary "
        "(__stack_chk_fail on mismatch) and resumes unwinding with "
        "_Unwind_Resume(%rbp). It never touches the temp status on "
        "the stack or any descriptor. Its own LSDA routes the "
        "_Unwind_Resume call to NO pad (already inside the cleanup).")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-dbimpl-createwal-115 (open, PR "
            "#6222): reconstructs DBImpl::CreateWAL 0x5e5c270, the "
            "next step of the same open sequence -- DBImpl::Open "
            "0x5e62c50 validates the options here (site 0x5e62e52) "
            "before it creates the WAL.",
            "RE-002-node115-rocksdb-build-db-options-115 (open, PR "
            "#6297): reconstructs BuildDBOptions 0x60c2e20, which "
            "builds the DBOptions this validator checks; the "
            "default-ctor packet (open PR #6337, 0x60b2db0) builds "
            "the 93 defaults the 1-arg oracle reads.",
            "RE-002-node115-vendor-census: the main FDE is "
            "census-bound (member 4d429ab1cb2d8f8b-db_impl_open.o, "
            "librocksdb-sys 0.11.0+8.1.1). Body 8b4ef727... / source "
            "b3d3ffa3... (8 relocations, kinds 2/4, no relaxation). "
            "The .cold FDE has NO census record (body 9a82fbb2... "
            "only).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "db/db_impl/db_impl_open.cc:380-390 defines this "
            "dispatcher exactly as the binary behaves (loop over "
            "the descriptors calling ColumnFamilyData::"
            "ValidateOptions, first failure returns, then "
            "ValidateOptions(db_options)); :392-484 defines the "
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
            "with the messages quoted verbatim in the reference "
            "oracle. db/column_family.cc (same-era source, read "
            "live via the rust-rocksdb mirror) gives the per-CF "
            "check order (CheckCompressionSupported, then "
            "CheckConcurrentWritesSupported only when the DB options "
            "allow concurrent memtable writes, then the "
            "unordered_write + max_successive_merges rule, then "
            "CheckCFPathsSupported, then the ttl / "
            "periodic-compaction table-factory rules).",
            "Binary-vs-source observation (recorded, not hidden): "
            "the binary calls ColumnFamilyData::ValidateOptions "
            "0x5d8e3b0 per column family, NOT the free function "
            "rocksdb::ValidateOptions(DBOptions, "
            "ColumnFamilyOptions) 0x60b94c0 -- the anonymous-"
            "namespace ValidateOptionsByTable helper in "
            "db_impl_open.cc calls the free function, but "
            "DBImpl::ValidateOptions does not use that helper. "
            "The binary returns the moved status directly (no "
            "extra copy) and the empty-list path skips the loop "
            "entirely by jumping to the DB-options call.",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "target, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "DBImpl::ValidateOptions 0x5e5a000: exactly 1 direct "
                "call, 0 tail jumps, 0 LEA refs -- DBImpl::Open "
                "0x5e62c50 (site 0x5e62e52, census-bound, "
                "db_impl_open.o). The validator runs once per DB "
                "open, before any column family is created.",
                "The main LSDA call-site table was decoded from "
                ".gcc_except_table (LSDA at 0x40fa2d, 10 bytes, "
                "header ff ff 01 06 + 1 call-site entry: "
                "FDE+0x6a..+0xf3 -> pad 0x5e5a145, action 0, "
                "cleanup only). The .cold LSDA is at 0x40fa37 (8 "
                "bytes, header ff ff 01 04 + 1 entry: FDE+0x21.."
                "+0x26 -> NO pad). The single guarded range covers "
                "both ValidateOptions calls and all four delete[] "
                "calls.",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 loop (descriptor lists of 0-5, per-CF "
                     "failures at each position, DB failures, "
                     "CF-failure-masks-DB-failure, name-independence) "
                     "+ 600 move (Status move semantics: state_ "
                     "transfer, temp zeroing, old state_ freed) + "
                     "600 throw (oracle BadAlloc at each call site, "
                     "pad cleanup lists, canary failures) + 600 "
                     "bindings (caller-site independence, FDE/LSDA "
                     "hashes as expected values)",
            "tests": "tests/test_dbimpl_validate_options115.py",
            "tool": "tools/dbimpl_validate_options115.py",
            "what_is_checked": [
                "loop: the first non-OK per-CF result is returned "
                "at once (later CFs never validated, DB check never "
                "runs); an all-OK list runs the DB check exactly "
                "once; the empty list runs only the DB check; "
                "descriptor names never change the result",
                "move: every move copies code u32 + subcode u16 + "
                "state_ ptr, zeroes the temp, and frees exactly the "
                "old out state_ (or nothing when it was null)",
                "throw: a BadAlloc from either oracle raises "
                "ValidateOptionsThrow with the pad's cleanup list "
                "(out.state_ freed iff non-null); canary failures "
                "raise StackCheckFailed on the return path and in "
                ".cold",
                "bindings: the result depends only on the options, "
                "never on the caller site or descriptor names; "
                "both FDE body hashes, the main source hash, and "
                "both LSDA byte strings match the binary; the "
                "engine-call counts match the disassembly",
            ],
        },
        "engine_callees": {
            "0x5d8e3b0": "rocksdb::ColumnFamilyData::ValidateOptions "
                         "(1555 B, census-bound, column_family.o): "
                         "the per-CF validator, called once per "
                         "descriptor with (sret temp, db_options, "
                         "&descriptor.options). ORACLE in this "
                         "packet -- its body is an open follow-up; "
                         "the reference oracle follows its upstream "
                         "check order (see the tool docstring).",
            "0x5e59cd0": "rocksdb::DBImpl::ValidateOptions(const "
                         "DBOptions&) (771 B, census-bound, "
                         "db_impl_open.o, 21 relocations): the "
                         "one-argument overload, called once after "
                         "the loop with (sret temp, db_options). "
                         "ORACLE in this packet -- its body is an "
                         "open follow-up; the reference oracle "
                         "implements its nine upstream checks with "
                         "verbatim messages.",
            "0x63f0dc0": "PLT operator delete[]: frees the old "
                         "out.state_ in both Status moves (4 sites: "
                         "0x5e5a0aa, 0x5e5a0b9, 0x5e5a12a, 0x5e5a139) "
                         "and out.state_ in .cold (1 site: "
                         "0x5e59fdd).",
            "0x63f0d70": "PLT __stack_chk_fail: the canary failure "
                         "at the epilogue (0x5e5a140) and in .cold "
                         "(0x5e59ffa).",
            "0x63f0a50": "PLT _Unwind_Resume: the cleanup epilogue "
                         "in .cold (0x5e59ff5).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this VM. "
            "The target binary is never executed. The tool models the "
            "dispatcher in Python; the two callees are reference "
            "oracles derived from upstream RocksDB v8.1.1 source "
            "read live this cycle (their binary bodies, 0x5d8e3b0 "
            "and 0x5e59cd0, are NOT reconstructed here). Status "
            "state_ buffers are deterministic heap ids, not real "
            "pointers; the subcode padding bytes (+0x6..+0x7) the "
            "binary never writes are modelled as zero. The live "
            "check (--live) reads the binary: both FDE body hashes, "
            "the main source hash, both LSDAs, the 1-site caller "
            "census, the engine-call counts, the descriptor stride "
            "and options offset, the code-byte gate, the canary "
            "sites and the pad (20/20 legs). make verify/test/"
            "catalogue-check in a tooled environment is still owed "
            "upstream.",
        "functions": functions,
        "layouts": {
            "status": {
                "+0x00": "code (u32; low byte is the Code enum; "
                         "0 = kOk). Copied by mov; tested by movzbl "
                         "+ test %al,%al at the gate.",
                "+0x04": "subcode (u16). Copied by movzwl; never "
                         "tested in this FDE.",
                "+0x06": "padding (2 bytes). NEVER written by the "
                         "init or the move; modelled as zero.",
                "+0x08": "state_ (char*, 8 bytes). nullptr = no "
                         "message; otherwise a heap buffer freed by "
                         "operator delete[] on move-out and in .cold.",
                "size": "0x10 (16 bytes)",
            },
            "column_family_descriptor": {
                "+0x00": "name (std::string, 0x20 bytes). NEVER read "
                         "by this FDE.",
                "+0x20": "options (ColumnFamilyOptions, 0x300 "
                         "bytes). Passed as rdx to "
                         "ColumnFamilyData::ValidateOptions.",
                "size": "0x320 (800 bytes)",
            },
            "lsda_call_sites": {
                "FDE+0x6a..+0xf3": "Both ValidateOptions calls "
                                   "(0x5e5a06a, 0x5e5a0ee) and all "
                                   "four delete[] calls -- pad "
                                   "0x5e5a145, action 0 (cleanup "
                                   "only): mov %rax,%rbp; jmp "
                                   "0x5e59fd4 (.cold: free out.state_ "
                                   "if non-null, canary check, "
                                   "_Unwind_Resume).",
                ".cold FDE+0x21..+0x26": "_Unwind_Resume (0x5e59ff5) "
                                        "-- NO pad (already inside "
                                        "the cleanup).",
            },
            "lsda": {
                "va": "0x40fa2d",
                "bytes_hex": "ffff01066a8901c50200",
                "note": "10 bytes: header ff ff 01 06 + 1 call-site "
                        "entry (start 0x6a, length 0x89, landing pad "
                        "0x145, action 0). Landing pads are "
                        "FDE-relative offsets from 0x5e5a000.",
            },
            "cold_lsda": {
                "va": "0x40fa37",
                "bytes_hex": "ffff010421050000",
                "note": "8 bytes: header ff ff 01 04 + 1 call-site "
                        "entry (start 0x21, length 0x05, landing pad "
                        "0, action 0). Landing pads are FDE-relative "
                        "offsets from 0x5e59fd4.",
            },
            "landing_pads": {
                "0x5e5a145": "stub -> .cold 0x5e59fd4 (mov %rax,%rbp, "
                            "then jmp): the only landing pad of the "
                            "main FDE.",
                "0x5e59fd4": ".cold entry: free out.state_ if "
                            "non-null (delete[] 0x5e59fdd), canary "
                            "check, _Unwind_Resume(%rbp).",
            },
        },
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
