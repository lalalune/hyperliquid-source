# RE-002: reconstruct node #115 `rocksdb::CheckCFPathsSupported` (CF/DB paths support gate)

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `CheckCFPathsSupported(const DBOptions&, const
ColumnFamilyOptions&)` -- the helper that checks whether a column
family's `cf_paths` (or, when empty, the DB's `db_paths`) are
compatible with its compaction style, and returns the first non-OK
status, or OK. It is called once by
`ColumnFamilyData::ValidateOptions` (open PR #6449, 0x5d8e3b0, site
0x5d8e4a7), as its fourth check. 2,400 byte-checked cases; 23 tests,
all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). One FDE:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::CheckCFPathsSupported` | `0x5d8bb50..0x5d8bc55` | 261 B | `938266cf7f2128574dad9589c1fca12b9f3a2e26b653114864225eca844fac82` | `25dac13516458d4d-column_family.o`, `_ZN7rocksdb21CheckCFPathsSupportedERKNS_9DBOptionsERKNS_19ColumnFamilyOptionsE` |

The source hash reproduces exactly by zeroing the census
relocations (6, kinds 2/4 -- no relaxation; all six are PC32/PLT32
disp32s: 132/144 the two msg2 leas, 191 the Status ctor call,
238/250 the two message leas, 257 the `__stack_chk_fail` call).
The FDE has NO `.cold` FDE and NO LSDA (the `.eh_frame` record at
section offset 0x34ba28 has length 0x18, range 0x105, aug_len 0):
no landing pad, no catch, no cleanup. This packet supersedes the
reference oracle for this function in the per-CF validator packet
(open PR #6449) with the full reconstruction.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `Status CheckCFPathsSupported(const DBOptions&
db_options, const ColumnFamilyOptions& cf_options)` -- the result
is returned by value (hidden sret out in `rdi` = `rax`),
`db_options` in `rsi`, `cf_options` in `rdx`. A stack canary IS
used (`%fs:0x28`, stored at `0x38(%rsp)`, checked on the epilogue
at 0x5d8bbab; a failure calls `__stack_chk_fail` at 0x5d8bc50).
The Status ctor's Slices live at `0x10(%rsp)`/`0x18(%rsp)` (msg,
len 0x54) and `0x20(%rsp)`/`0x28(%rsp)` (msg2 = the empty string
at 0x4376fd). In binary order:

1. `compaction_style` (+0xe8, u8) <= 1 (`kCompactionStyleLevel` 0 /
   `kCompactionStyleUniversal` 1) -> OK regardless of paths
   (`cmpb $0x1,0xe8(%rdx)`; `jbe 0x5d8bb97`).
2. `cf_paths` (+0x2c8..+0x2d0, `vector<DbPath>`) byte size > 0x28
   (more than one path) -> NotSupported (code 3), message `More
   than one CF paths are only supported in universal and level
   compaction styles. ` (0x956f18, 84 B, trailing space).
3. `cf_paths` empty AND `db_paths` (+0x70..+0x78,
   `vector<DbPath>`) byte size > 0x28 (more than one path) ->
   NotSupported (code 3), message `More than one DB paths are
   only supported in universal and level compaction styles. `
   (0x963340, 84 B, trailing space).
4. Else return OK: out = {0, 0, nullptr} (`xor %edx,%edx`; `movl
   $0x0,(%rax)`; `mov %dx,0x4(%rax)`; `movq $0x0,0x8(%rax)` at
   0x5d8bb97), then the epilogue (canary check).

Status plumbing: both error paths build their Slices on the stack
and share the single Status ctor call at 0x5d8bc0e (0x61cf670,
census-bound, `status.o`; args out, code 3, subcode 0, &msg, &msg2,
severity 0). The second error block stores its own message
pointer and jumps back into the first block's tail, so the two
paths share one message-length store (`movq $0x54,0x18(%rsp)`)
and one ctor call. The OK path writes out directly (no
move-assign is used anywhere in this FDE). Bytes +0x6..+0x7 of
out are never written by any path -- the model zeroes them and
records them as unwritten padding.

The two messages are the upstream strings quoted verbatim
(meta/rocksdb v8.1.1, `db/column_family.cc:173-192`, read live
this cycle), each verified byte-for-byte against the .rodata
string at its address.

ColumnFamilyOptions/DBOptions field offsets were verified this
cycle by compiling `offsetof()` against the real v8.1.1 headers
(g++): `compaction_style` +0xe8, `cf_paths` +0x2c8, `db_paths`
+0x70, `sizeof(DbPath)` 0x28, `sizeof(ColumnFamilyOptions)`
0x300, `sizeof(DBOptions)` 0x290; the #6449 anchors reproduce
too (`ttl` +0x160, `table_factory` +0x2b8). The byte-size
comparisons are exact: the binary subtracts vector begin/end
pointers, so `> 0x28` is a `> 1` element test for real vectors.

Binary-vs-source observations (recorded, not hidden): the FDE
has no LSDA and no `.cold` FDE, so there is no landing pad and no
cleanup for a throw from the Status ctor -- the exception
propagates straight through, and the canary is checked only on
normal returns. That makes the no-LSDA behavior observable in the
model: a BadAlloc with a bad canary still propagates as BadAlloc
(there is no pad canary check to fire first). The source writes
the style gate as two inequality tests (`style != universal &&
style != level`); the binary compiles it to one unsigned byte
compare (`cmpb $0x1`, `jbe`), so a style byte above 3 (e.g. 255)
also falls into the path checks -- the model follows the binary.

## Caller census

Exactly 1 direct call, 0 tail jumps, 0 LEA refs (whole-`.text`
scan, Capstone-validated, `census.py`):
`ColumnFamilyData::ValidateOptions` 0x5d8e3b0 (site 0x5d8e4a7,
census-bound, `column_family.o`, open PR #6449). The helper runs
once per ValidateOptions call, as its fourth check.

## Cases and checks

- `cases.tsv`: 2,400 cases -- 600 checks (each check failing
  alone, pairs where check 1 must win, boundaries: level and
  universal styles ignoring 2 cf + 2 db paths, one cf path never
  reading db_paths, empty cf_paths with one db path, mixed
  styles 0/1/2/3/4/255 x path counts 0..3) + 600 status (OK
  image, each error image with code/subcode/severity/pad/`state_`
  content, the ctor's `": "` join with a non-empty msg2, both
  verbatim messages) + 600 throw (BadAlloc in the Status ctor at
  each of the 2 error sites with the half-built status attached
  and no cleanup, canary failures on OK and error returns,
  BadAlloc beating a bad canary -- with no LSDA there is no pad
  canary check, so it still propagates as BadAlloc --
  `alloc_ok=False` with no `fail_at`, firing only on an error
  path and passing through on an OK path) + 600 bindings
  (caller-site independence across the single caller, FDE hashes
  as expected values).
  `tools/check_cf_paths_supported115.py --verify-cases`
  reproduces all 2,400 with 0 mismatches.
- `tests/test_check_cf_paths_supported115.py`: 23 tests, all
  pass.
- Live check (`tools/check_cf_paths_supported115.py --live`):
  42/42 legs -- the FDE body hash, the source hash (6
  relocations zeroed), the census symbol/member, the FDE record
  (section offset 0x34ba28, length 0x18, range 0x105, aug_len 0,
  no LSDA), the engine-call counts (1x Status ctor, 1x
  `__stack_chk_fail`, 1x endbr64, canary refs x2, msg2 lea x2, 2
  call lines), the field cmp instructions, both message bytes
  plus the empty msg2, the 1-site caller census, and the model
  end-to-end legs (defaults OK, each of the 2 checks failing
  with its message, check 1 masking check 2, level/universal
  styles ignoring paths, one cf path never reading db_paths,
  empty cf_paths with one db path, ctor `state_` buffer = msg +
  NUL, ctor `": "` join, BadAlloc + bad canary propagating as
  BadAlloc).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is
never executed. The tool models the helper in Python from its
whole-FDE disassembly; the Status ctor's observable behavior is
pinned from its own disassembly. Status `state_` buffers are
deterministic heap ids, not real pointers; the subcode padding
bytes (+0x6..+0x7) the binary never writes are modelled as zero.
`make verify`/`test`/`catalogue-check` in a tooled environment is
still owed upstream.

## Open unknowns

- Whether the `new char[]` in the Status ctor can throw for these
  two messages on a real allocation failure is modelled, not
  observed: the binary is never executed, so the BadAlloc path is
  a reconstruction of the ctor's control flow, not a witnessed
  throw. The exception type is never named by the binary (there
  is no LSDA at all), so the model records the throwing site, not
  an exception type.
- The model takes path counts as inputs and multiplies by 0x28
  (the `sizeof(DbPath)` the headers pin). A vector whose byte size
  is not a multiple of 0x28 cannot arise from a real
  `vector<DbPath>`; the binary's `> 0x28` test is exactly a `> 1`
  element test on real inputs.

## Next candidates (noted, not submitted)

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
