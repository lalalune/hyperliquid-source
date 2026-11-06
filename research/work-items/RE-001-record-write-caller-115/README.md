# RE-001: pin the node #115 record-write caller 0x5fc6070..0x5fc6e8b

Task ID: RE-001. Bounded question: what does the record-write
caller do end to end — how does it validate a write, choose
between the sibling record write 0x5f0f3d0 and the record-write
entry 0x5f0f930, insert a fresh handle, and produce a record
when the entry returns code 1?

Target: node #115, `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). All addresses are node #115.

## What the caller does

The caller takes `(out, owner, arg3, arg4, arg5, direct, arg7)`.
Status is 16 bytes `{+0 u32 code, +4 u16 code2, +8 msg ptr}`.

- Closed owner (`owner+0xb1` set) with a delegate at `owner+0xa0`
  delegates to the fallback `0x5fbed30` and returns; with no
  delegate it falls through to validation.
- Validation `0x5fb9a10`: slot `0x10` on `owner+0x10` must be
  true; `owner+0x30`, when set, must be >= the slot-`0x18`
  limit; `owner+0x60`, when set, has its byte set to 1;
  `owner+0x38`, when set, registers the min of `handle+0xc38`
  via `0x5f0a1a0`.
- On validation failure with an empty status and a delegate
  present, the fallback runs; if its code is 0 the
  duplicate-detector check `0x5fbe340` runs and the tag at
  `owner+0x8` is bumped when its return equals `owner+0xb0`.
- Tracked handle (`handle+0x31` set): the sibling `0x5f0f3d0`
  runs when `handle+0x40` is null or `direct != 1`; the
  record-write entry `0x5f0f930` runs when `handle+0x40` is
  set and `direct == 1`. Both take the tag `owner+0x8`.
- Fresh handle (`handle+0x31` clear): the hashmap at
  `owner+0x110` is initialised when `owner+0x102` is clear
  (buckets at `owner+0x140`, count 1, load factor 1.0) and
  the handle is found-or-inserted by `0x5fc5e30`; the
  std::map at `owner+0x70` is inserted by `0x5fb7040`
  lower_bound plus the inline insert; then the record insert
  `0x5f0e890` runs with the hashmap value slot, the map node
  value and the `owner+0x49` flag.
- The shared tail: code `0x0d` bumps the tag when `owner+0xb0`
  is set; code 0 bumps it when `owner+0xb0` is clear, then
  runs the post-write hook `0x5fb6a60` and the closed-path
  delegate when one is configured; any other code is returned
  as-is.

### Sibling record write 0x5f0f3d0

Key build `0x5eab0c0`, then product-1 (`owner+0xa50`): when
vtable slot `0x98` equals the GOT canonical `0x5f04d80`
(GOT slot `0x64ed778`) slot `0x90` runs, else the slot-`0x98`
function pointer. Slot `0x10` finds the record, slot `0x18`
reads it. Product-2 (`owner+0x10`): when slot `0x98` equals
`0x5d2ca80` (GOT slot `0x64ed010`) slot `0x10` runs on the
`+0x20` subobject, else the slot-`0x98` function pointer.
The record layout is varint(length) + payload (last 8 bytes
= trailer) + varint(value length) + value bytes.

An in-place update happens only when the new value fits
(new length <= stored length). A longer new value, a
missing product-1 record, a missing product-2 record, or a
trailer low byte differing from `direct` all take the insert
path. The update re-encodes the new value length, buckets
the key, takes the write lock, memcpys the new value,
notifies slot `0xb0` on `owner+0x50` with `(1, 0x27)`,
then folds arg7's first qword with the tag and the
trailer's high bytes under seed `0x77a00858ddd37f21`,
resolves and validates; with a null arg7 the resolve runs
with a null fold and the validate is skipped.

### Fallback 0x5fbed30

A key or value whose `+0x8` length exceeds `0xffffffff`
reports InvalidArgument with `key is too large` /
`value is too large`; otherwise it appends a leading byte
(5 when arg3 != 0, else 1), varint(arg3) when arg3 != 0,
varint(key length), the key, varint(value length), the
value, sets flags `|= 2`, and appends the four-way hash to
the vector at `obj+0x30` (seeds 0, `0xd28aad72f49bd50b`,
`0xa5155ae5e937aa16`, `0x4a2ab5cbd26f542c`).

Finalizer `0x5fbebc0`: a zero `+0x28` maximum disables the
check; a built key longer than the maximum rolls the key,
the counter and the vector back and reports Status `0x70a`
(code byte `0x0a` kAborted, subcode byte `0x07`); otherwise
the append stands and an empty Status is returned. The
counter the `0x5fbb000` getter reads is the key string's
size field; the setter bumps it by 1 before the leading-byte
append, so the byte at the old size index is whatever the
buffer held.

### Produce path (record-write code 1)

A `rocksdb::SnapshotImpl` is built on the stack (vtable
`0x64c92d0`, tag `owner+0x8`, flag 1; typeinfo
`N7rocksdb12SnapshotImplE` at `0x96ce30`) with a 0x90-byte
request (`+0x2c` qword `0x001` after the caller's fix,
`+0x78` -1, `+0x84` 4, `+0x88` `0x100`). The produce pointer
comes from virtual slot `0x28` on `owner+0x10`, or slot
`0x3e8` on `owner+0x40` when null; virtual slot `0xe8` on
`owner+0x40` performs the produce. With no produce object
or a set `owner+0x30`, the default outcome is Status code 3.

Produce code > 1 is copied out with the message duplicated
by strdup `0x61cf610`. Code <= 1 clears the error status
and calls the `handle+0x40` function pointer: code 0 passes
the key-slot string and its size, code 1 passes nulls; the
arg5 slice (16 bytes) and the request's str_a are always
passed. The function returns 0/1/2: 0 returns; 1 and 2
re-insert the record (insert type argument 1 in both cases)
with the value struct built from the key-slot string
(return 1) or the request's str_a (return 2); the
hash-combine feeds the same pair plus the arg5 slice,
seeded by `*arg7` when arg7 is given; a null arg7 skips the
combine and passes all-zero stack arguments. After a code-0
re-insert, slot `0xb0` on `handle+0x50` runs with `(1, 0x25)`.

### Post-write hook 0x5fb6a60

Called after a code-0 write: a once-only flush of
`owner+0x18` via `0x5ed88c0` guarded by a lock-CAS 1 -> 2
on the state field `+0xc68`, then a threshold check: when
the accumulated size (slot `0x78` of the two products + the
`+0xa00` field, plus the `0x5f13430` size) reaches the
`+0x5f8` limit, a lock-CAS 0 -> 1 on `+0x8f1` runs the
threshold flush `0x5f44db0`.

### Family

The caller is called by three routines, twice each:
`0x5fc6ec0..0x5fc70b6`, `0x5fc70e0..0x5fc72d6`,
`0x5fc7300..0x5fc74f6`. The validator and the check are
shared by five routines (the caller plus
`0x5fc2900..0x5fc3acf`, `0x5fc7b40..0x5fc806b`,
`0x5fc80a0..0x5fc852b`, `0x5fc8590..0x5fc8ece`); the
post-write hook by three (the caller, `0x5fc2900..0x5fc3acf`,
`0x5fc7520..0x5fc7b0e`). The singleton `0x61be810` has 9
calls plus 1 tail jump.

## Observations, inferences, unknowns

Observations are in `records.json` (the `observations`
field) and are stated above. Inferences (marked as such in
`records.json`):

- `owner+0x28` in the fallback is a maximum key length: a
  built key longer than it rolls the append back. Its
  writer is not pinned.
- The sibling's product-1/product-2 are two record stores
  behind the handle; the canonical GOT comparisons select
  the direct slot-`0x98` function pointer versus the
  slot-`0x90` / slot-`0x10` path.
- The produce path's slot-`0x28` / slot-`0xe8` struct
  arguments are recorded by slot number; their concrete
  callees are not pinned.

Unknowns (also in `records.json`): the exact register
assignment of the slot-`0x28` / slot-`0xe8` struct
arguments; the concrete callees behind the virtual produce
slots `0x28`, `0x3e8` and `0xe8`; the construction site of
the `-0x88` completion callback (never written in the
caller); the writer of the fallback's `+0x28`
maximum-length field; the exact prime list behind the
hashmap rehash growth (modelled as the next prime at or
above twice the old count); the 64-bit hash `0x61c3530`
body (contract-only; the model injects it).

## Evidence

- Raw disassembly excerpts, one whole-function file per
  window, generated by `export_excerpts.py` with
  `objdump -d --start-address=<start> --stop-address=<stop>
  work/hl-node-115.bin`. The mnemonics in the excerpts
  (`endbr64` included) are genuine instructions present in
  the target binary, not placeholders. Instruction-level
  detail lives only in these excerpt files; `records.json`
  holds semantic records only.
- Re-shipped excerpts, verified byte-identical to a fresh
  objdump run by the generator: `record_write.txt` from
  #3337 (SHA-256
  `5550dad838d3d2e25f1d57f11078906828db5d162a38eb4fb809d62b1b9a3b44`),
  `record_insert.txt` from #3330 (SHA-256
  `36ec095b1af9c250917442c044642a26530fbd7a3bb585fd3fd608f71b554109`),
  `varint_encode.txt` from #3330 (SHA-256
  `0f97f05548a830558b5c5442a107d1e60d4323438c274f7baca839ed3001effd`),
  `status_builder.txt` from #3330 (SHA-256
  `5c716d61c200e269e3dd526816c760497c7ba042ee7eede755475c1cb3845f3d`).
- Census (`census.py`, plus the supplementary hook census):
  direct calls / tail jumps / lea references / qwords /
  RELATIVE records per target, in `callers.tsv` and
  `relocations.txt`. Counts: main `0x5fc6070` 6 calls;
  sibling `0x5f0f3d0` 1; validator `0x5fb9a10` 5; hashmap
  `0x5fc5e30` 2; rehash `0x5fc5cf0` 1; map lower_bound
  `0x5fb7040` 6; hash combine `0x5fb70e0` 3; Status move
  `0x5fb71b0` 43; produce ctor `0x60b21f0` 61; strdup
  `0x61cf610` 425; stub `0x5d54f00` 10 calls + 1 jump;
  fallback `0x5fbed30` 5; fallback getter `0x5fbb000` 24
  + 1 jump; getter alias `0x5fbb010` 15 + 1 jump; setter
  `0x5fbbc30` 15; vector grow `0x5fb7440` 18; finalizer
  `0x5fbebc0` 11; min-register `0x5f0a1a0` 1; record-write
  entry `0x5f0f930` 1; record insert `0x5f0e890` 10;
  varint encoder `0x61bd410` 165; Status builder
  `0x61cf670` 847; hash `0x61c3530` 108; check `0x5fbe340`
  5; singleton `0x61be810` 9 + 1 jump; check throw helper
  `0x5fcf060` 252 + 1 jump; post-hook `0x5fb6a60` 3;
  hook sub-callees `0x5ed88c0` 1, `0x5f13440` 1,
  `0x5f13430` 1, `0x5f44db0` 0 calls + 1 tail jump.
  The two GOT canonicals are installed at several slots
  each (0x5f04d80 also at 0x64d2780 and 0x64d2970; 0x5d2ca80
  also at 0x64d7310; 0x5d484b0 also at 0x64ed3d8); the
  sibling reads the slots 0x64ed778 and 0x64ed010.
- Model: `tools/record_write_caller_115.py` with
  `tests/test_record_write_caller_115.py` — 32 tests, 0
  failed. The model exercises the dispatcher end to end
  (closed, validation-failure, sibling, record-write,
  produce, re-insert, fresh-handle paths) with stubbed
  virtual slots and record operations, plus unit checks
  per helper.

## Verification

`python3 research/work-items/RE-001-record-write-caller-115/verify.py`
checks: the artifact digest, `MANIFEST.sha256`, that a
fresh objdump run reproduces every excerpt byte-for-byte,
that every excerpt line matches the raw binary
byte-for-byte, three seeded spot instructions per window
against a fresh objdump run, the FDE ranges, the
relocation set, the pinned literals (validator/fallback
messages, seeds, produce-request constants), the census
counts against `records.json`, and that the semantic
records re-derive from the packet. All checks pass.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java,
so no Rust build or `make verify`/`make test` run is
claimed. The model is deterministic offline Python and its
tests run directly (`python3
tests/test_record_write_caller_115.py`). The virtual
produce slots, the 64-bit hash and the duplicate-detector
check are cited by contract, not re-implemented from a
body this VM cannot execute.
