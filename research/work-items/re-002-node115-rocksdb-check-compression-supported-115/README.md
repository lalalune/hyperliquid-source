# RE-002: reconstruct node #115 `rocksdb::CheckCompressionSupported` (compression support gate)

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `CheckCompressionSupported(const ColumnFamilyOptions&)` --
the helper that checks a CF's compression settings against the
codecs linked into the binary and returns the first non-OK status,
or OK. It is called once, as the first check, by
`ColumnFamilyData::ValidateOptions` (open PR #6449, 0x5d8e3b0, site
0x5d8e3fb). 2,400 byte-checked cases; 33 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Two FDEs:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::CheckCompressionSupported` | `0x5d8dcc0..0x5d8e356` | 1686 B | `cde4dcaa3d2f878a82348aeee686792e771a72cc82b3e4111cdc1fb0dfc7a670` | `25dac13516458d4d-column_family.o`, `_ZN7rocksdb25CheckCompressionSupportedERKNS_19ColumnFamilyOptionsE` |
| same symbol `.cold` | `0x5d8dc2c..0x5d8dcb5` | 137 B | `8b4d3b7883f7b077631b57b19b1d8cde3c18b6baec296a75f79fd3b9f4e3795d` | same member, `.cold` suffix |

The source hashes reproduce exactly by zeroing the census
relocations (main: 69, kinds 2/4/42; cold: 12, kind 4 -- no
relaxation; the five kind-42 sites are plain `cmp` displacements).
The main FDE has an LSDA at 0x40a2a0 (17 entries, all cleanup); the
`.cold` FDE has an LSDA at 0x40a307 (1 entry, for the two
`_Unwind_Resume` calls). This packet supersedes the reference
oracle for this function in the per-CF validator packet (open PR
#6449) with the full reconstruction.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `Status CheckCompressionSupported(const ColumnFamilyOptions&
cf_options)` -- the result is returned by value (hidden sret out
in `rdi` = `r12`), `cf_options` in `rsi` = `rbp`. A stack canary IS
used (`%fs:0x28`, stored at `0x1e8(%rsp)`, checked on the epilogue
at 0x5d8ddee and in every LSDA pad via the `.cold` FDE; the two
`__throw_length_error` paths check it too). Three stack strings:
S1 at `0x30(%rsp)` (`rbp`, the `CompressionTypeToString` result),
S2 at `0x50(%rsp)` (`rbx`, move of S1), S3 at `0x70(%rsp)` (`r13`,
move of S2) for the per-level and single-compression error paths;
the blob error path reuses the `0x70(%rsp)` slot for the
`std::ostringstream` (`r13`) and builds its message there instead.
The Status ctor's Slices live at `0x10/0x20(%rsp)` (msg + the empty
msg2 at 0x4376fd). In binary order:

1. `compression_per_level` (+0x70 begin, +0x78 end): if non-empty,
   for each byte `b` (1-byte `CompressionType`): if
   `!CompressionTypeSupported(b)` -> InvalidArgument (code 4),
   message `Compression type <name> is not linked with the
   binary.` (prefix 0x4408db len 17 + name + suffix 0x965df8 len
   31). If the vector is empty, the same test runs on
   `compression` (+0x220) instead (the else branch at 0x5d8e130).
   `CompressionTypeSupported` is inlined as a decision table:
   0 `kNoCompression`, 1 `kSnappyCompression`, 2
   `kZlibCompression`, 3 `kBZip2Compression`, 4 `kLZ4Compression`,
   5 `kLZ4HCCompression` -> true (constant-folded, no call);
   6 `kXpressCompression` -> false; 7 `kZSTD` ->
   `ZSTD_versionNumber() >= 800`; 0x40 `kZSTDNotFinalCompression`
   -> true; 0xff `kDisableCompressionOption` and every other byte
   -> false (default arm: `assert(false); return false`).
   `CompressionTypeToString` (0x5d8b3c0, census-bound) names: 0
   NoCompression, 1 Snappy, 2 Zlib, 3 BZip2, 4 LZ4, 5 LZ4HC, 6
   Xpress, 7 ZSTD, 0x40 ZSTDNotFinal, 0xff DisableOption, anything
   else "" (empty). So byte 8 reports `Compression type  is not
   linked with the binary.` (empty name, double space), and byte
   0xff reports `Compression type DisableOption is not linked with
   the binary.`
2. If `compression_opts.zstd_max_train_bytes` (+0x268, u32) > 0:
   if `use_zstd_dict_trainer` (+0x280, bool) != 0 and
   `ZSTD_versionNumber() < 10103` -> InvalidArgument, msg 0x9647e8
   len 89: `zstd dictionary trainer cannot be used because ZSTD
   1.1.3+ is not linked with the binary.`; else (trainer off) if
   `ZSTD_versionNumber() < 10405` -> InvalidArgument, msg 0x95e1a8
   len 89: `zstd finalizeDictionary cannot be used because ZSTD
   1.4.5+ is not linked with the binary.`; then if
   `max_dict_bytes` (+0x264, u32) == 0 -> InvalidArgument, msg
   0x967428 len 126: `The dictionary size limit
   (`CompressionOptions::max_dict_bytes`) should be nonzero if
   we're using zstd's dictionary generator.` The three version
   thresholds are the exclusive bounds in the binary (`cmp
   $0x31f` / `$0x2776` / `$0x28a4` with `jbe`/`ja`), matching
   v8.1.1 `ZSTD_Supported >= 800`, `ZSTD_TrainDictionarySupported
   >= 10103`, `ZSTD_FinalizeDictionarySupported >= 10405`.
   `ZSTD_versionNumber` (0x620dd50, NOT in the vendor census -- a
   vendored-ZSTD routine) is a 10-byte function: `endbr64; mov
   $0x290a,%eax; ret` -- it returns 10506 (ZSTD 1.5.6), so all
   three gates pass in this build.
3. Blob: if `!CompressionTypeSupported(blob_compression_type)`
   (+0x1a8, 1 byte) -> InvalidArgument via `std::ostringstream`:
   `The specified blob compression type <name> is not
   available.` (prefix 0x95cd48 len 36 + name + suffix 0x43820b
   len 18). The ostringstream is built at `0x70(%rsp)`, the
   message is copied into S2 with `_M_replace`, the Status ctor
   runs at 0x5d8e031, S2 is disposed, and the ostringstream is
   destroyed (locale + `ios_base` dtors).
4. Else return OK: out = {0, 0, nullptr} (`movl $0x0,(%r12)`;
   `mov %ax,0x4(%r12)`; `movq $0x0,0x8(%r12)` at 0x5d8e10a), then
   the epilogue (canary check).

Status plumbing: every error builds the Status DIRECTLY into out
via the 5-arg Status ctor 0x61cf670 (census-bound,
`6cca28ae25285154-status.o`; args out, code 4, subcode 0, &msg
Slice, &msg2 Slice = {0x4376fd, 0} where the byte at 0x4376fd is
0x00, severity 0) then jumps to the epilogue (0x5d8ddee). The
trainer/finalize/max_dict errors share one ctor call (0x5d8dec1);
each builds its own Slices first. The OK path writes out directly
(no move-assign is used anywhere in this FDE). Bytes +0x6..+0x7
of out are never written by any path -- the model zeroes them and
records them as unwritten padding.

LSDA (decoded from `.gcc_except_table`; `.eh_frame` records at
section offsets 0x735a04 (main, length 0x40, range 0x696) and
0x735a48 (cold, length 0x1c, range 0x89), both aug_len 4 with the
LSDA pointer as pcrel sdata4): main LSDA at 0x40a2a0, 103 bytes,
header `ff ff 01`, table length 0x63, 17 entries, all action 0
(cleanup only) -- pads 0x61e/0x62a/0x642 dispose the rbx string +
destroy the ostringstream, 0x636/0x65a/0x666 dispose the
r13/rbx/rbp strings, 0x64e/0x672 dispose the rbx/rbp strings,
0x67e destroys the ostringstream, 0x68a disposes the rbp string,
pad 0 = no landing pad (the noexcept calls and the calls with
nothing live). Cold LSDA at 0x40a307, 8 bytes, 1 entry (38,81,0,0)
for the two `_Unwind_Resume` calls (pad 0). Every pad runs its
cleanup, then the canary check, then resumes -- so a throw with a
bad canary raises `__stack_chk_fail` from the pad instead of
resuming.

The five messages are the upstream strings quoted verbatim
(meta/rocksdb v8.1.1, `db/column_family.cc:113-159` and
`util/compression.h`, read live this cycle), each verified
byte-for-byte against the .rodata string at its address.

Binary-vs-source observations (recorded, not hidden): the +1222
`_M_replace` call's LSDA entry names pad 0x636, whose `.cold`
body disposes the r13 and rbx string slots -- but at that call
site only the rbp string is constructed (r13/rbx are set up
later, at +1288/+1235). The pad is shared with the Status ctor at
+1347, where all three strings ARE live; the model follows the
pad code literally. The blob path's `_M_assign` call at +1489 runs
only when the ostringstream's string is empty (`r8 == 0` at
0x5d8dfcd); the composed message is never empty (the 36-byte
prefix alone), so the branch is unreachable for real inputs --
its LSDA entry (1489,5,1578) and pad are still pinned. The two
`__throw_length_error` calls (+1530/+1561) are reached only when
a string exceeds max_size; names are <= 13 bytes, so they never
fire for real inputs -- they are modelled as `fail_at` sites.
`ZSTD_versionNumber` 0x620dd50 is NOT in the vendor census (a
vendored-ZSTD routine): its identity is pinned by its 10-byte
body and its FDE record (0x620dd50..0x620dd5a).

ColumnFamilyOptions field offsets were verified this cycle by
compiling `offsetof()` against the real v8.1.1 headers (g++):
`compression_per_level` +0x70, `blob_compression_type` +0x1a8,
`compression` +0x220, `bottommost_compression` +0x221,
`bottommost_compression_opts` +0x228, `compression_opts` +0x258
(`max_dict_bytes` +0x264, `zstd_max_train_bytes` +0x268,
`use_zstd_dict_trainer` +0x280); the #6449 anchors reproduce too
(`compaction_style` +0xe8, `ttl` +0x160, `table_factory` +0x2b8,
`sizeof(ColumnFamilyOptions)` 0x300). All 10 binary-read offsets
match the computed layout exactly. Note the corrected enum values
vs the #6449 oracle's table: `kZSTDNotFinalCompression` is 0x40
and `kDisableCompressionOption` is 0xff
(`include/rocksdb/compression_type.h:17-39`), so the binary's
`cmp $0x40` skip is the ZSTDNotFinal-supported arm, not a
disable-option arm.

## Caller census

Exactly 1 direct call, 0 tail jumps, 0 LEA refs (whole-`.text`
scan, Capstone-validated, `census.py`):
`ColumnFamilyData::ValidateOptions` 0x5d8e3b0 (site 0x5d8e3fb,
census-bound, `column_family.o`, open PR #6449). The helper runs
once per ValidateOptions call, as its first check.

## Cases and checks

- `cases.tsv`: 2,400 cases -- 600 checks (each check failing
  alone, pairs where the earlier one must win, boundaries:
  per-level [] vs [0..5,0x40], byte 7 at zstd 799/800, byte 8
  (empty name), byte 0xff (DisableOption), trainer 10102/10103,
  finalize 10404/10405, train_bytes 0/1, max_dict 0/1, blob
  0x40/0xff, mixed options) + 600 status (OK image, each error
  image with code/subcode/severity/pad/`state_` content, the
  ctor's `": "` join with a non-empty msg2, the empty-name and
  DisableOption messages) + 600 throw (BadAlloc in the Status
  ctor at each of the 4 error sites with the half-built status
  and the pad's cleanup attached, callee throws at every string /
  ostream / length-error site with its LSDA pad, canary failures
  on OK and error returns, BadAlloc beating a bad canary via the
  pad's canary check, alloc_ok=False with no fail_at) + 600
  bindings (caller-site independence across the single caller,
  FDE/LSDA hashes as expected values).
  `tools/check_compression_supported115.py --verify-cases`
  reproduces all 2,400 with 0 mismatches.
- `tests/test_check_compression_supported115.py`: 33 tests, all pass.
- Live check (`tools/check_compression_supported115.py --live`):
  93/93 legs -- the FDE body hashes, the source hashes (69 + 12
  relocations zeroed), the census symbols/members, the LSDA bytes
  and both `.eh_frame` records (lengths 0x40/0x1c, ranges
  0x696/0x89, aug_len 4, LSDA pointers 0x40a2a0/0x40a307), the
  engine-call counts (3x CompressionTypeToString, 4x Status ctor,
  5x ZSTD_versionNumber, 3x `_M_replace`, 2x `_M_append`, 4x string
  move ctor, 6x `_M_dispose`, 3x `__ostream_insert`, 1x
  ostringstream ctor, 1x `_M_assign`, 1x locale dtor, 1x ios_base
  dtor, 2x `__throw_length_error`, 1x `__stack_chk_fail`, 11x
  endbr64, canary refs x4, msg2 lea x6, length-check movabs x2,
  37 call lines; cold: 8x `_M_dispose`, 1x ostringstream dtor, 2x
  `_Unwind_Resume`, 1x `__stack_chk_fail`, 0x endbr64, canary refs
  x2, 12 call lines; ZSTD_versionNumber returns 0x290a), the
  fourteen field cmp instructions, all seven message bytes plus
  the empty msg2, the 1-site caller census, and the model
  end-to-end legs (defaults OK, each of the 5 checks failing with
  its message, check 1 masking check 5, trainer gate masking
  max_dict gate, version boundaries 799/800, 10102/10103,
  10404/10405, byte 8 empty name, byte 0xff DisableOption, byte
  0x40 passing, ctor `state_` buffer = msg + NUL, ctor `": "`
  join).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is
never executed. The tool models the helper in Python from its
whole-FDE disassembly; the ZSTD version gates take the linked
version number as an input (default 10506, read from the 10-byte
`ZSTD_versionNumber` body); the Status ctor's observable behavior
is pinned from its own disassembly. Status `state_` buffers are
deterministic heap ids, not real pointers; the subcode padding
bytes (+0x6..+0x7) the binary never writes are modelled as zero.
`make verify`/`test`/`catalogue-check` in a tooled environment is
still owed upstream.

## Open unknowns

- Whether the `new char[]` in the Status ctor can throw for these
  five messages on a real allocation failure is modelled, not
  observed: the binary is never executed, so the BadAlloc path is
  a reconstruction of the ctor's control flow, not a witnessed
  throw. The same holds for the string ops, the ostream inserts
  and the version calls: their exception types are never named by
  the binary (all LSDA actions are 0, cleanup only), so the model
  records the throwing site, its pad and the pad's cleanup, not an
  exception type.
- The exact linked-codec set of the node #115 build is now pinned
  for this helper (Snappy/Zlib/BZip2/LZ4/ZSTD linked, Xpress not
  linked, ZSTD 1.5.6): the decision table is the binary's, not an
  oracle input. The trainer/finalize version gates are testable
  through the `zstd_version` model input.

## Next candidates (noted, not submitted)

- `CheckConcurrentWritesSupported` 0x5d8ba60 (6 relocations) and
  `CheckCFPathsSupported` 0x5d8bb50 (6 relocations): the other two
  helper oracles of the #6449 packet, as full reconstructions.
- `DBImpl::SetDBOptions` 0x5d71fe0..0x5d72e50 (3696 B,
  census-bound): the second caller of the one-argument validator
  and of the per-CF validator; validates rebuilt options before
  applying them.
- `DBImpl::Open` 0x5e62c50..0x5e65462 (10258 B, census-bound): the
  sole caller of the two-argument validator; the whole open
  sequence. NOTE: at 10 KB / 206 calls it is far larger than any
  Shape A packet so far; model it only as a full reconstruction
  or not at all, never as a partial bind.
- `DBImpl::SwitchMemtable` 0x5e8a890..0x5e8c518 (7304 B,
  census-bound).
