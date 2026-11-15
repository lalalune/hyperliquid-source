# RE-002: reconstruct node #115 `rocksdb::CheckConcurrentWritesSupported` (concurrent-writes support gate)

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: `CheckConcurrentWritesSupported(const ColumnFamilyOptions&)`
-- the helper that checks whether a column family's options allow
concurrent memtable writes, and returns the first non-OK status, or
OK. It is called once, when `allow_concurrent_memtable_write` is set,
by `ColumnFamilyData::ValidateOptions` (open PR #6449, 0x5d8e3b0,
site 0x5d8e7ee), as its second check. 2,400 byte-checked cases; 22
tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). One FDE:

| function | range | size | body SHA-256 | census |
|---|---|---|---|---|
| `rocksdb::CheckConcurrentWritesSupported` | `0x5d8ba60..0x5d8bb48` | 232 B | `a74c304849fb7d03189b349820271542e7cdbd92e18ce7dd1430a86244394de3` | `25dac13516458d4d-column_family.o`, `_ZN7rocksdb30CheckConcurrentWritesSupportedERKNS_19ColumnFamilyOptionsE` |

The source hash reproduces exactly by zeroing the census
relocations (6, kinds 2/4 -- no relaxation; all six are PC32/PLT32
disp32s: 124/136 the two msg2 leas, 175 the Status ctor call,
196/208 the two message leas, 228 the `__stack_chk_fail` call).
The FDE has NO `.cold` FDE and NO LSDA (the `.eh_frame` record at
section offset 0x34ba04 has length 0x20, range 0xe8, aug_len 0):
no landing pad, no catch, no cleanup. This packet supersedes the
reference oracle for this function in the per-CF validator packet
(open PR #6449) with the full reconstruction.

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `Status CheckConcurrentWritesSupported(const
ColumnFamilyOptions& cf_options)` -- the result is returned by value
(hidden sret out in `rdi` = `rbx`), `cf_options` in `rsi`. A stack
canary IS used (`%fs:0x28`, stored at `0x28(%rsp)`, checked on the
epilogue at 0x5d8baae; a failure calls `__stack_chk_fail` at
0x5d8bb43). The Status ctor's Slices live at `(%rsp)`/`0x8(%rsp)`
(msg) and `0x10(%rsp)`/`0x18(%rsp)` (msg2 = the empty string at
0x4376fd). In binary order:

1. `inplace_update_support` (+0x18, bool) != 0 -> InvalidArgument
   (code 4), message `In-place memtable updates
   (inplace_update_support) is not compatible with concurrent writes
   (allow_concurrent_memtable_write)` (0x95a210, 125 B).
2. `memtable_factory` (+0x128, `shared_ptr<MemTableRepFactory>`) ->
   load the vtable, call `IsInsertConcurrentlySupported()` at vtable
   slot 0xa8 (byte offset 168, slot 21); if it returns false ->
   InvalidArgument (code 4), message `Memtable doesn't concurrent
   writes (allow_concurrent_memtable_write)` (0x95e160, 68 B).
3. Else return OK: out = {0, 0, nullptr} (`movl $0x0,(%rbx)`;
   `mov %ax,0x4(%rbx)` -- `eax` was zeroed at 0x5d8ba7a; `movq
   $0x0,0x8(%rbx)` at 0x5d8ba9c), then the epilogue (canary check).

Status plumbing: both error paths build their Slices on the stack
and share the single Status ctor call at 0x5d8bb0e (0x61cf670,
census-bound, `status.o`; args out, code 4, subcode 0, &msg, &msg2,
severity 0), then jump to the epilogue (0x5d8baae). The OK path
writes out directly (no move-assign is used anywhere in this FDE).
Bytes +0x6..+0x7 of out are never written by any path -- the model
zeroes them and records them as unwritten padding.

The two messages are the upstream strings quoted verbatim
(meta/rocksdb v8.1.1, `db/column_family.cc:161-171`, read live this
cycle), each verified byte-for-byte against the .rodata string at
its address.

The vtable slot is verified two ways: by hand-counting the
`MemTableRepFactory` vtable (Configurable 14 slots, Customizable 5
more, `CreateMemTableRep` x2, then `IsInsertConcurrentlySupported`
at slot 21) and by compiling the pointer-to-member encoding with
g++ (vtable byte offset 168 = 0xa8), matching the binary's `call
*0xa8(%rax)`.

ColumnFamilyOptions field offsets were verified this cycle by
compiling `offsetof()` against the real v8.1.1 headers (g++):
`inplace_update_support` +0x18, `memtable_factory` +0x128; the
#6449 anchors reproduce too (`compaction_style` +0xe8, `ttl`
+0x160, `table_factory` +0x2b8, `sizeof(ColumnFamilyOptions)`
0x300). The base `MemTableRepFactory::IsInsertConcurrentlySupported`
returns false (`memtablerep.h:321`); `SkipListFactory` -- the
default memtable factory -- returns true (`:354`).

Binary-vs-source observations (recorded, not hidden): the FDE has
no LSDA and no `.cold` FDE, so there is no landing pad and no
cleanup for a throw from the Status ctor or the virtual call -- the
exception propagates straight through, and the canary is checked
only on normal returns. That makes the no-LSDA behavior observable
in the model: a BadAlloc with a bad canary still propagates as
BadAlloc (there is no pad canary check to fire first). The binary
loads the `memtable_factory` word and dereferences its vtable with
no null check; a null factory is not a reachable state for a valid
`ColumnFamilyOptions` (the default is `SkipListFactory`), so the
model takes the factory's `IsInsertConcurrentlySupported` answer as
an input and records the assumption. The gate on
`allow_concurrent_memtable_write` (+0x1d2) lives in the caller
(`ColumnFamilyData::ValidateOptions`), not in this helper: the
helper itself never reads +0x1d2.

## Caller census

Exactly 1 direct call, 0 tail jumps, 0 LEA refs (whole-`.text`
scan, Capstone-validated, `census.py`):
`ColumnFamilyData::ValidateOptions` 0x5d8e3b0 (site 0x5d8e7ee,
census-bound, `column_family.o`, open PR #6449). The helper runs
once per ValidateOptions call when `allow_concurrent_memtable_write`
is set, as its second check.

## Cases and checks

- `cases.tsv`: 2,400 cases -- 600 checks (each check failing
  alone, pairs where check 1 must win, boundaries: all four
  combinations of `inplace_update_support` x
  `memtable_factory_concurrent`, mixed options) + 600 status (OK
  image, each error image with code/subcode/severity/pad/`state_`
  content, the ctor's `": "` join with a non-empty msg2, both
  verbatim messages) + 600 throw (BadAlloc in the Status ctor at
  each of the 2 error sites with the half-built status attached
  and no cleanup, CalleeThrow at the virtual call, canary failures
  on OK and error returns, BadAlloc beating a bad canary -- with no
  LSDA there is no pad canary check, so it still propagates as
  BadAlloc -- `alloc_ok=False` with no `fail_at`) + 600 bindings
  (caller-site independence across the single caller, FDE hashes
  as expected values).
  `tools/check_concurrent_writes_supported115.py --verify-cases`
  reproduces all 2,400 with 0 mismatches.
- `tests/test_check_concurrent_writes_supported115.py`: 22 tests,
  all pass.
- Live check (`tools/check_concurrent_writes_supported115.py
  --live`): 36/36 legs -- the FDE body hash, the source hash (6
  relocations zeroed), the census symbol/member, the FDE record
  (section offset 0x34ba04, length 0x20, range 0xe8, aug_len 0, no
  LSDA), the engine-call counts (1x Status ctor, 1x virtual call
  `*0xa8(%rax)`, 1x `__stack_chk_fail`, 1x endbr64, canary refs x2,
  msg2 lea x2, 3 call lines), the field cmp instructions, both
  message bytes plus the empty msg2, the 1-site caller census, and
  the model end-to-end legs (defaults OK, each of the 2 checks
  failing with its message, check 1 masking check 2, ctor `state_`
  buffer = msg + NUL, ctor `": "` join, BadAlloc + bad canary
  propagating as BadAlloc).

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
  throw. The same holds for the virtual call: its exception type
  is never named by the binary (there is no LSDA at all), so the
  model records the throwing site, not an exception type.
- The exact factory object behind `memtable_factory` is never
  inspected: the model takes its `IsInsertConcurrentlySupported`
  answer as an input (default true, the `SkipListFactory`
  default). Any factory returning false (e.g. a hash-linked-list
  factory) reaches the same error path through the same vtable
  slot.

## Next candidates (noted, not submitted)

- `CheckCFPathsSupported` 0x5d8bb50 (6 relocations) -- the third
  helper oracle of the #6449 packet, as a full reconstruction.
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
