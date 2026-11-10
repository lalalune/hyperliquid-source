#!/usr/bin/env python3
"""Generate functions.tsv and records.json for this packet from the
vendor census + the binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
ranges. Both FDEs are vendor-census-bound (member
25dac13516458d4d-column_family.o, librocksdb-sys 0.11.0+8.1.1);
their source hashes reproduce exactly by zeroing the census
relocations (main: 69, kinds 2/4/42; cold: 12, kind 4 -- no
relaxation; the five kind-42 sites are plain cmp displacements).
The main FDE has an LSDA at 0x40a2a0 (17 entries, all cleanup);
the .cold FDE has an LSDA at 0x40a307 (1 entry, for the two
_Unwind_Resume calls).
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
    ("0x5d8dcc0", "0x5d8e356",
     "rocksdb::CheckCompressionSupported",
     "check-compression-supported-5d8dcc0", True),
    ("0x5d8dc2c", "0x5d8dcb5",
     "rocksdb::CheckCompressionSupported (.cold)",
     "check-compression-supported-5d8dc2c-cold", True),
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
    main_calls = [s for s in sites if s["target"] == "0x5d8dcc0"]
    functions["0x5d8dcc0"]["callers"] = [s["site"] for s in main_calls]
    functions["0x5d8dcc0"]["model"] = (
        "1686-byte helper "
        "CheckCompressionSupported(const ColumnFamilyOptions&) "
        "(result by value, sret out in rdi = r12; cf_options in "
        "rsi = rbp; stack canary used). Checks in binary order, "
        "first failure wins: compression_per_level non-empty: "
        "every byte must be CompressionTypeSupported, else "
        "'Compression type <name> is not linked with the binary.' "
        "(InvalidArgument); empty: the same test on compression "
        "(+0x220). compression_opts.zstd_max_train_bytes (+0x268) "
        "> 0: use_zstd_dict_trainer (+0x280) and ZSTD < 1.1.3 -> "
        "'zstd dictionary trainer cannot be used because ZSTD "
        "1.1.3+ is not linked with the binary.' (89 B); else "
        "(trainer off) ZSTD < 1.4.5 -> 'zstd finalizeDictionary "
        "cannot be used because ZSTD 1.4.5+ is not linked with "
        "the binary.' (89 B); then max_dict_bytes (+0x264) == 0 "
        "-> 'The dictionary size limit "
        "(`CompressionOptions::max_dict_bytes`) should be nonzero "
        "if we're using zstd's dictionary generator.' (126 B). "
        "blob_compression_type (+0x1a8) must be supported, else "
        "(via std::ostringstream) 'The specified blob compression "
        "type <name> is not available.' (InvalidArgument). Else "
        "OK (out = {0, 0, nullptr}). CompressionTypeSupported is "
        "inlined: 0-5 and 0x40 (ZSTDNotFinal) constant true; 6 "
        "Xpress constant false; 7 ZSTD is ZSTD_versionNumber() "
        ">= 800 (linked ZSTD 1.5.6, version 10506 from the "
        "10-byte function at 0x620dd50); 0xff and every other "
        "byte false (default arm). CompressionTypeToString names: "
        "0 NoCompression, 1 Snappy, 2 Zlib, 3 BZip2, 4 LZ4, 5 "
        "LZ4HC, 6 Xpress, 7 ZSTD, 0x40 ZSTDNotFinal, 0xff "
        "DisableOption, anything else '' (so byte 8 reports an "
        "empty name). The three stack strings (S1 0x30(%rsp), "
        "S2 0x50(%rsp), S3 0x70(%rsp)) hold the built message on "
        "the per-level/single paths; the blob path reuses the "
        "0x70(%rsp) slot for the ostringstream. Main LSDA at "
        "0x40a2a0: 17 entries, all cleanup; the .cold FDE "
        "(0x5d8dc2c..0x5d8dcb5) holds the ten landing pads.")
    functions["0x5d8dc2c"]["model"] = (
        "137-byte .cold FDE for the helper: the landing-pad "
        "bodies. cold+0x0 disposes the rbx string, destroys the "
        "r13 ostringstream, checks the canary and calls "
        "_Unwind_Resume; cold+0x2b disposes rbx then jumps to "
        "cold+0x8 (destroy ostringstream); cold+0x35 disposes "
        "the r13/rbx/rbp strings then canary + resume; cold+0x3d "
        "disposes rbx/rbp then canary + resume; cold+0x45 "
        "disposes rbp then canary + resume; cold+0x65 disposes "
        "rbx then jumps to cold+0x8; cold+0x77 disposes r13 then "
        "jumps to cold+0x7f (dispose rbx, then cold+0x45); "
        "cold+0x7f disposes rbx then jumps to cold+0x45. Its "
        "LSDA at 0x40a307 has 1 entry (38,81,0,0) for the two "
        "_Unwind_Resume calls (pad 0).")
    records = {
        "artifact": "node #115",
        "artifact_sha256": DIGEST,
        "bound_context": [
            "RE-002-node115-rocksdb-column-family-data-validate-"
            "options-115 (open, PR #6449): reconstructs "
            "ColumnFamilyData::ValidateOptions 0x5d8e3b0, which "
            "calls this helper once as its first check (site "
            "0x5d8e3fb). The #6449 packet's reference oracle for "
            "this function is superseded by this full "
            "reconstruction.",
            "RE-002-node115-vendor-census: both FDEs are "
            "census-bound (member 25dac13516458d4d-column_family.o, "
            "librocksdb-sys 0.11.0+8.1.1). Main body cde4dcaa... / "
            "source ba0cad22... (69 relocations, kinds 2/4/42, no "
            "relaxation; the five kind-42 sites are plain cmp "
            "displacements); cold body 8b4d3b78... / source "
            "8f60ab2c... (12 kind-4 relocations, no relaxation).",
            "meta/rocksdb v8.1.1, read live this cycle: "
            "db/column_family.cc:113-159 defines this helper "
            "exactly as the binary behaves (per-level loop or "
            "single compression, the zstd trainer / finalize / "
            "max_dict_bytes gates, the blob compression type via "
            "ostringstream); util/compression.h:547-571 defines "
            "the CompressionTypeSupported switch, :510-513 "
            "ZSTD_Supported (>= 800), :1435-1440 "
            "ZSTD_TrainDictionarySupported (>= 10103), :1495-1498 "
            "ZSTD_FinalizeDictionarySupported (>= 10405); "
            "include/rocksdb/compression_type.h:17-39 defines the "
            "enum (kZSTDNotFinalCompression = 0x40, "
            "kDisableCompressionOption = 0xff); "
            "include/rocksdb/advanced_options.h:87-210 defines "
            "CompressionOptions; include/rocksdb/options.h "
            "declares ColumnFamilyOptions. The binary matches "
            "v8.1.1 step for step, including the three version "
            "thresholds (799/10102/10404 as the exclusive bounds).",
            "ColumnFamilyOptions field offsets verified this cycle "
            "by compiling offsetof() against the real v8.1.1 "
            "headers (g++): compression_per_level +0x70, "
            "blob_compression_type +0x1a8, compression +0x220, "
            "bottommost_compression +0x221, "
            "bottommost_compression_opts +0x228, compression_opts "
            "+0x258 (max_dict_bytes +0x264, zstd_max_train_bytes "
            "+0x268, use_zstd_dict_trainer +0x280); the #6449 "
            "anchors reproduce too (compaction_style +0xe8, ttl "
            "+0x160, table_factory +0x2b8, sizeof "
            "ColumnFamilyOptions 0x300). All 10 binary-read "
            "offsets match the computed layout exactly.",
            "Binary-vs-source observations (recorded, not hidden): "
            "the +1222 _M_replace call's LSDA entry names pad "
            "0x636, whose .cold body disposes the r13 and rbx "
            "string slots -- but at that call site only the rbp "
            "string is constructed (r13/rbx are set up later, at "
            "+1288/+1235). The pad is shared with the Status ctor "
            "at +1347, where all three strings ARE live; the "
            "model follows the pad code literally. The blob path's "
            "_M_assign call at +1489 runs only when the "
            "ostringstream's string is empty (r8 == 0 at "
            "0x5d8dfcd); the composed message is never empty (the "
            "36-byte prefix alone), so the branch is unreachable "
            "for real inputs -- its LSDA entry (1489,5,1578) and "
            "pad are still pinned, and the throw group does not "
            "rotate it. The two __throw_length_error calls "
            "(+1530/+1561) are reached only when a string exceeds "
            "max_size; names are <= 13 bytes, so they never fire "
            "for real inputs -- they are modelled as fail_at "
            "sites. ZSTD_versionNumber 0x620dd50 is NOT in the "
            "vendor census (a vendored-ZSTD routine): its identity "
            "is pinned by its 10-byte body (mov $0x290a,%eax; "
            "ret) and its FDE record (0x620dd50..0x620dd5a).",
        ],
        "caller_census": {
            "method": "Whole-.text scan for E8 calls, E9 tail jumps "
                      "and RIP-relative LEA references landing on the "
                      "target, validated by decoding forward from the "
                      "enclosing FDE start with Capstone (census.py). "
                      "A site counts only on a real instruction "
                      "boundary with the expected mnemonic.",
            "notes": [
                "CheckCompressionSupported 0x5d8dcc0: exactly 1 "
                "direct call, 0 tail jumps, 0 LEA refs -- "
                "ColumnFamilyData::ValidateOptions 0x5d8e3b0 (site "
                "0x5d8e3fb, census-bound, column_family.o, open PR "
                "#6449). The helper runs once per ValidateOptions "
                "call, as its first check.",
                "LSDA: the main FDE record in .eh_frame (section "
                "offset 0x735a04, length 0x40, initial_location "
                "0x5d8dcc0, range 0x696, aug_len 4) carries an LSDA "
                "pointer (pcrel sdata4) to 0x40a2a0: header ff ff "
                "01, table length 0x63, 17 entries, all action 0 "
                "(cleanup only). The .cold FDE record (section "
                "offset 0x735a48, length 0x1c, initial_location "
                "0x5d8dc2c, range 0x89, aug_len 4) points to "
                "0x40a307: header ff ff 01, table length 0x04, 1 "
                "entry (38,81,0,0) for the two _Unwind_Resume "
                "calls (pad 0).",
            ],
            "sites": sites,
            "validated_sites": len(sites),
        },
        "cases": {
            "count": 2400,
            "ledger": "cases.tsv",
            "split": "600 checks (each check failing alone, pairs "
                     "where the earlier one must win, boundaries: "
                     "per-level [] vs [0..5,0x40], byte 7 at zstd "
                     "799/800, byte 8 (empty name), byte 0xff "
                     "(DisableOption), trainer 10102/10103, "
                     "finalize 10404/10405, train_bytes 0/1, "
                     "max_dict 0/1, blob 0x40/0xff, mixed options) "
                     "+ 600 status (OK image, each error image with "
                     "code/subcode/severity/pad/state_ content, the "
                     "ctor's ': ' join with a non-empty msg2, the "
                     "empty-name and DisableOption messages) + 600 "
                     "throw (BadAlloc in the Status ctor at each of "
                     "the 4 error sites with the half-built status "
                     "and the pad's cleanup attached, callee throws "
                     "at every string / ostream / length-error site "
                     "with its LSDA pad, canary failures on OK and "
                     "error returns, BadAlloc beating a bad canary "
                     "via the pad's canary check, alloc_ok=False "
                     "with no fail_at) + 600 bindings (caller-site "
                     "independence across the single caller, "
                     "FDE/LSDA hashes as expected values)",
            "tests": "tests/test_check_compression_supported115.py",
            "tool": "tools/check_compression_supported115.py",
            "what_is_checked": [
                "checks: the first failing check wins (later checks "
                "never run); the per-level loop vs the single-"
                "compression else branch (empty vector only); the "
                "inlined decision table (0-5 and 0x40 true, 6 "
                "false, 7 version-gated, 0xff and others false); "
                "the three ZSTD version thresholds (800 / 10103 / "
                "10405) with the exclusive-bound comparisons; the "
                "trainer gate masking the max_dict_bytes gate; "
                "train_bytes == 0 skipping all zstd gates",
                "status: the Status byte layout the ctor proves "
                "(code u8 +0x0, subcode u8 +0x1, severity u8 +0x2, "
                "padding +0x3..+0x7 zero with +0x6..+0x7 unwritten, "
                "state_ +0x8); the state_ buffer is msg + NUL with "
                "alloc len+1; the ctor's ': ' join when msg2 is "
                "non-empty (ctor behavior, never fired by this FDE); "
                "the empty-name message for byte 8 and the "
                "DisableOption message for byte 0xff",
                "throw: each throwing call names its LSDA pad and "
                "cleanup (0x68a dispose rbp; 0x64e/0x672 dispose "
                "rbx/rbp; 0x65a/0x666/0x636 dispose r13/rbx/rbp; "
                "0x67e destroy ostringstream; 0x61e/0x62a/0x642 "
                "dispose rbx + destroy ostringstream; pad 0 no "
                "cleanup); a BadAlloc leaves out half-built "
                "(code/subcode/severity written, state_ null); "
                "canary failures raise StackCheckFailed on the "
                "return path -- a throw never reaches the "
                "epilogue, but the pad's own canary check fires "
                "first, so a throw with a bad canary raises "
                "StackCheckFailed instead of resuming",
                "bindings: the result depends only on the options, "
                "never on the caller site; the FDE body hashes, the "
                "source hashes (69 + 12 relocations zeroed), the "
                "LSDA entries and the engine-call counts match the "
                "binary",
            ],
        },
        "engine_callees": {
            "0x5d8b3c0": "rocksdb::CompressionTypeToString "
                         "(census-bound, column_family.o): called 3 "
                         "times (per-level 0x5d8dd3b, blob 0x5d8df3d, "
                         "single 0x5d8e16d). Jump-table over the "
                         "byte: 0 NoCompression, 1 Snappy, 2 Zlib, 3 "
                         "BZip2, 4 LZ4, 5 LZ4HC, 6 Xpress, 7 ZSTD, "
                         "0x40 ZSTDNotFinal, 0xff DisableOption, "
                         "anything else '' (empty string at "
                         "0x4376fd).",
            "0x620dd50": "ZSTD_versionNumber (NOT in the vendor "
                         "census -- a vendored-ZSTD routine): called "
                         "5 times (per-level kZSTD 0x5d8de20, "
                         "finalize 0x5d8de66, trainer 0x5d8e0c0, blob "
                         "kZSTD 0x5d8e210, single kZSTD 0x5d8e26a). "
                         "10-byte body: endbr64, mov $0x290a,%eax, "
                         "ret -- returns 10506 (ZSTD 1.5.6). Its FDE "
                         "record is 0x620dd50..0x620dd5a.",
            "0x61cf670": "rocksdb::Status::Status(Code, SubCode, "
                         "const Slice&, const Slice&, Severity) "
                         "(census-bound, status.o): the five-argument "
                         "Status ctor, called 4 times (per-level "
                         "0x5d8ddd1, shared max-dict/trainer/finalize "
                         "0x5d8dec1, blob 0x5d8e031, single "
                         "0x5d8e203). Its observable behavior IS "
                         "pinned from its disassembly: code u8 +0x0, "
                         "subcode u8 +0x1, severity u8 +0x2, zeroes "
                         "+0x3..+0x5, state_ = new char[size+1] "
                         "holding msg + (': ' + msg2 if len2) + NUL. "
                         "Its trailing delete[] of the old state_ is "
                         "DEAD (state_ is zeroed at 0x61cf6b0 before "
                         "the read at 0x61cf6e4).",
            "0x63f0d90": "PLT _M_replace: called 3 times (per-level "
                         "0x5d8dd54, blob 0x5d8e001, single 0x5d8e186) "
                         "-- inserts the 17-byte 'Compression type ' "
                         "prefix (per-level/single) or copies the "
                         "ostringstream string into S2 (blob).",
            "0x63f0f40": "PLT _M_append: called 2 times (per-level "
                         "0x5d8dd91, single 0x5d8e1c3) -- appends the "
                         "31-byte ' is not linked with the binary.' "
                         "suffix. Each call is preceded by the "
                         "length check (max_size - len <= 30 -> "
                         "__throw_length_error).",
            "0x63f0eb0": "PLT string move ctor: called 4 times "
                         "(per-level S2 0x5d8dd64, per-level S3 "
                         "0x5d8dda1, single S2 0x5d8e196, single S3 "
                         "0x5d8e1d3). Noexcept.",
            "0x63f0db0": "PLT _M_dispose: called 6 times in the main "
                         "FDE (0x5d8ddd9, 0x5d8dde1, 0x5d8dde9, "
                         "0x5d8df93, 0x5d8e039, 0x5d8e05c) and 8 times "
                         "in the .cold FDE. Noexcept.",
            "0x63f10e0": "PLT basic_ostringstream ctor: called once "
                         "(blob path 0x5d8df15).",
            "0x63f10f0": "PLT __ostream_insert: called 3 times (blob "
                         "path 0x5d8df29 prefix, 0x5d8df4f name, "
                         "0x5d8df63 suffix).",
            "0x63f0f00": "PLT _M_assign: called once (blob path "
                         "0x5d8e291) -- the dead empty-string branch.",
            "0x63f1100": "PLT locale dtor: called once (blob path "
                         "0x5d8e079). Noexcept.",
            "0x63f1110": "PLT ios_base dtor: called once (blob path "
                         "0x5d8e0b6). Noexcept.",
            "0x63f0de0": "PLT __throw_length_error: called twice "
                         "(single path 0x5d8e2ba, per-level path "
                         "0x5d8e2d9) -- the string length check "
                         "failing (max_size - len <= 30).",
            "0x63f0d70": "PLT __stack_chk_fail: the canary failure "
                         "at the epilogue (0x5d8e29b) and in the "
                         ".cold pad (0x5d8dc8c).",
            "0x63f1120": "PLT basic_ostringstream dtor: called once "
                         "in the .cold FDE (0x5d8dc37).",
            "0x63f0a50": "PLT _Unwind_Resume: called twice in the "
                         ".cold FDE (0x5d8dc52, 0x5d8dc9e).",
        },
        "environment_limits": "No cargo/rustc/git-lfs/Ghidra on this VM. "
            "The target binary is never executed. The tool models the "
            "helper in Python from its whole-FDE disassembly; the "
            "ZSTD version gates take the linked version number as an "
            "input (default 10506, read from the 10-byte "
            "ZSTD_versionNumber body); the Status ctor's observable "
            "behavior is pinned from its own disassembly. Status "
            "state_ buffers are deterministic heap ids, not real "
            "pointers; the subcode padding bytes (+0x6..+0x7) the "
            "binary never writes are modelled as zero. The live "
            "check (--live) reads the binary: the FDE body hashes, "
            "the source hashes, the LSDA bytes and FDE records, the "
            "engine-call counts, the field cmp instructions, the "
            "seven message bytes and the one-site caller census. "
            "make verify/test/catalogue-check in a tooled "
            "environment is still owed upstream.",
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
            "cf_options_fields_read": {
                "+0x70": "compression_per_level (vector begin; end "
                        "at +0x78; elements are 1-byte "
                        "CompressionType values).",
                "+0x1a8": "blob_compression_type (1 byte).",
                "+0x220": "compression (1 byte; read only on the "
                        "empty-vector path).",
                "+0x264": "compression_opts.max_dict_bytes (u32).",
                "+0x268": "compression_opts.zstd_max_train_bytes "
                         "(u32).",
                "+0x280": "compression_opts.use_zstd_dict_trainer "
                         "(bool).",
                "not_read": "bottommost_compression (+0x221) and "
                            "bottommost_compression_opts (+0x228) are "
                            "never read by this FDE.",
            },
            "lsda": {
                "main": "LSDA at 0x40a2a0 (103 bytes): header ff ff "
                        "01, table length 0x63, 17 entries, all action "
                        "0 (cleanup only): (123,5,0), (148,5,1674), "
                        "(209,5,1614), (273,5,1626), (352,250,0), "
                        "(617,25,1662), (655,25,1602), (833,5,1578), "
                        "(881,5,1566), (1024,178,0), (1222,5,1590), "
                        "(1283,5,1650), (1347,5,1638), (1360,95,0), "
                        "(1489,5,1578), (1530,5,1650), (1561,5,1614) "
                        "(start, length, landing_pad, all FDE-relative).",
                "cold": "LSDA at 0x40a307 (8 bytes): header ff ff 01, "
                        "table length 0x04, 1 entry (38,81,0,0) for the "
                        "two _Unwind_Resume calls at cold+0x26 and "
                        "cold+0x72 (pad 0).",
            },
            "landing_pads": {
                "0x000": "no landing pad: the noexcept calls "
                         "(ZSTD_versionNumber x5, string move ctors "
                         "x4, _M_dispose x6, locale/ios_base dtors) "
                         "and the calls with nothing live "
                         "(CompressionTypeToString at +123/+1197, the "
                         "Status ctor at +513, the ostringstream "
                         "ctor at +597).",
                "0x61e": "Status ctor at +881 (blob): cold+0x0 -- "
                         "dispose the rbx string, destroy the r13 "
                         "ostringstream, canary check, _Unwind_Resume.",
                "0x62a": "_M_replace at +833 (blob) and _M_assign at "
                         "+1489 (blob-empty): cold+0x2b -- dispose "
                         "the rbx string, destroy the r13 "
                         "ostringstream, canary check, resume.",
                "0x636": "_M_replace at +1222 (single): cold+0x35 -- "
                         "dispose the r13/rbx/rbp strings, canary "
                         "check, resume. QUIRK: at +1222 only rbp is "
                         "constructed; the pad is shared with the "
                         "Status ctor at +1347.",
                "0x642": "__ostream_insert at +655/+675 (blob): "
                         "cold+0x65 -- dispose the rbx string, "
                         "destroy the r13 ostringstream, canary "
                         "check, resume.",
                "0x64e": "_M_append at +209 (per-level) and "
                         "__throw_length_error at +1561 (per-level): "
                         "cold+0x7f -- dispose the rbx/rbp strings, "
                         "canary check, resume.",
                "0x65a": "Status ctor at +273 (per-level): cold+0x77 "
                         "-- dispose the r13/rbx/rbp strings, "
                         "canary check, resume.",
                "0x666": "Status ctor at +1347 (single): cold+0x35 "
                         "-- dispose the r13/rbx/rbp strings, "
                         "canary check, resume.",
                "0x672": "_M_append at +1283 (single) and "
                         "__throw_length_error at +1530 (single): "
                         "cold+0x3d -- dispose the rbx/rbp strings, "
                         "canary check, resume.",
                "0x67e": "__ostream_insert at +617 (blob) and "
                         "CompressionTypeToString at +637 (blob): "
                         "cold+0x8 -- destroy the r13 ostringstream, "
                         "canary check, resume.",
                "0x68a": "_M_replace at +148 (per-level): cold+0x45 "
                         "-- dispose the rbp string, canary check, "
                         "resume.",
            },
            "error_blocks": {
                "0x5d8dd1a": "per-level / single shared message build "
                            "(CompressionTypeToString -> _M_replace "
                            "prefix -> move S2 -> length check -> "
                            "_M_append suffix -> move S3 -> Status "
                            "ctor -> dispose S3/S2/S1 -> epilogue). "
                            "Reached from the per-level loop (byte 6 "
                            "or > 7 except 0x40, or kZSTD with version "
                            "<= 799) and from the single-compression "
                            "path (same dispatch on +0x220).",
                "0x5d8de80": "max_dict_bytes error: msg 0x967428 len "
                            "126 -> Status ctor 0x5d8dec1 into out, "
                            "epilogue.",
                "0x5d8e0d0": "trainer error: msg 0x9647e8 len 89 -> "
                            "shared Status ctor 0x5d8dec1 (Slices "
                            "built at 0x5d8e0d0), epilogue.",
                "0x5d8e22e": "finalize error: msg 0x95e1a8 len 89 -> "
                            "shared Status ctor 0x5d8dec1 (Slices "
                            "built at 0x5d8e22e), epilogue.",
                "0x5d8df0d": "blob error: ostringstream build "
                            "(prefix + CompressionTypeToString + "
                            "suffix), _M_replace into S2, Status ctor "
                            "0x5d8e031 into out, dispose S2, destroy "
                            "the ostringstream (locale + ios_base "
                            "dtors), epilogue.",
                "0x5d8e10a": "OK path: movl $0x0,(%r12); movw "
                            "$0x0,0x4(%r12); movq $0x0,0x8(%r12), "
                            "then the epilogue (canary check).",
            },
        },
    }
    with open(PACKET / "records.json", "w") as fh:
        json.dump(records, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote records.json")


if __name__ == "__main__":
    main()
