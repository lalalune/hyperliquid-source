# RE-001: six timestamp-guarded WriteBatch operations (node #115)

Bounded question: what do the six sibling routines at
0x5e94540..0x5e95ef7 do around the timestamp guard 0x5d58810
(mapped in PR #3202), and what operation does each one perform?

Answer, in one line each: each is a `Status`-returning database
operation that (1) runs the timestamp guard, (2) builds a
`rocksdb::WriteBatch` on the stack, (3) appends exactly one
record to the batch through one `WriteBatch` vtable function,
and (4) dispatches the batch through virtual slot 0xe0 of the
rsi-object. The six operations, identified by the record-type
byte each inner appender writes (rocksdb `ValueType`) and
cross-checked against the Merge wrapper's merge-operator gate:

| operation | wrapper | impl | middle (vtable slot) | inner | record type default / CF | flag bit |
|---|---|---|---|---|---|---|
| Put | 0x5e94540 | 0x5e943f0 | 0x5fbf5d0 (slot 2) | 0x5fbf0b0 | 0x01 / 0x05 | 0x0002 |
| PutEntity | 0x5e94b20 | 0x5e94970 | 0x5fc4db0 (slot 7) | 0x5fc46c0 | 0x16 / 0x17 | 0x1000 |
| Delete | 0x5e94da0 | 0x5e94c70 | 0x5fc0320 (slot 13) | 0x5fbff40 | 0x00 / 0x04 | 0x0004 |
| SingleDelete | 0x5e952c0 | 0x5e95190 | 0x5fc1010 (slot 18) | 0x5fc0c30 | 0x07 / 0x08 | 0x0008 |
| DeleteRange | 0x5e95800 | 0x5e956b0 | 0x5fc1e60 (slot 23) | 0x5fc1980 | 0x0f / 0x0e | 0x0200 |
| Merge | 0x5e95d70 | 0x5e95c20 | 0x5fc4020 (slot 8) | 0x5fc3b00 | 0x02 / 0x06 | 0x0010 |

## How the identification was made

* The stack struct built by 0x5fb9f90 is a `rocksdb::WriteBatch`:
  its first qword is the vtable at 0x64cd498, whose typeinfo
  pointer record (RELATIVE at 0x64cd490, addend 0x64cd338)
  names `rocksdb::WriteBatch` (`N7rocksdb10WriteBatchE`), and
  its embedded string is resized to 12 NUL bytes — the batch
  `rep_` header (8-byte sequence 0 + 4-byte count 0). The
  destructor is 0x5fb7ee0 (vtable slot 0).
* The six middle callees are the functions listed in that
  vtable at the slots above (RELATIVE addends at 0x64cd498..;
  slots counted from the vtable pointer, slot 0 = the
  destructor 0x5fb7ee0 — see `relocations.txt` and
  `census.py`). Each middle resolves the column family
  through 0x5fbbc90, validates the record, and calls its
  inner appender.
* Each inner appender writes one record type byte into the
  batch `rep_`: Put pushes 0x05 (CF) or 0x01 (default CF);
  Delete stores 0x04 / 0x00; SingleDelete 0x08 / 0x07;
  Merge pushes 0x06 or stores 0x02; DeleteRange stores
  0x0e / 0x0f; PutEntity pushes 0x17 (CF) or 0x16 (default).
  The branch is the column-family id: id == 0 takes the
  default-CF type, id != 0 the CF type. The choice of the
  default-CF byte is confirmed independently by each
  inner's hash-combine epilogue, which carries the default
  type byte (Put 0x01, Delete 0x00, SingleDelete 0x07,
  Merge 0x02, DeleteRange 0x0f).
* The Merge identification is confirmed a second way: the
  Merge wrapper 0x5e95d70 is the only wrapper with a second
  gate — after the timestamp guard it calls virtual slot
  0x30 on the rcx-object and, when the result's +0x5c8
  field is null, returns `Status::NotSupported`
  ("Provide a merge_operator when opening DB", code 3).
* Each inner also sets one flag bit in the batch's +0x24
  word (see the table) and bumps the `rep_` count by one.

## Pipeline, per operation

1. **Wrapper** (`wrap_<op>.txt`): calls the timestamp guard
   0x5d58810 with (out = stack-temp Status, factory = rsi,
   obj = rcx). Guard non-OK: the Status is copied into the
   caller's out (message deep-copied with the strdup helper
   0x61cf610) and the wrapper returns. Guard OK: all
   arguments are forwarded to the implementation. The Merge
   wrapper additionally runs the merge-operator gate above.
2. **Implementation** (`impl_<op>.txt`): constructs a
   `WriteBatch` on the stack via 0x5fb9f90 (vtable 0x64cd498,
   `rep_` = 12 NUL bytes), calls its middle callee with
   (temp Status, batch, ...op args), and on success calls
   virtual slot 0xe0 on the rsi-object with
   (out, rsi-object, rdx, batch). On a middle failure the
   Status is moved into out — except PutEntity's impl, which
   deep-copies the message with 0x61cf610, because its
   shared cleanup frees the temp message. The batch is
   destroyed with 0x5fb7ee0 on every path. PutEntity's impl
   (and only it, among the six) first resolves the name
   through the factory's virtual slot 0x3e8 and slot 0x28,
   the same resolve the guard performs.
3. **Middle** (`mid_<op>.txt`): fills the 0x28-byte
   column-family resolution record via 0x5fbbc90
   (`cf_resolve.txt`): timestamp size at +0x00, CF id
   (dword) at +0x08, Status code at +0x10, subcode bytes at
   +0x11..+0x15, message pointer at +0x18. Code != 0: that
   Status is written into out and the middle returns.
   Timestamp size == 0: the middle calls the tail callee
   (`tail_<op>.txt`), which appends the record with the plain
   key (no timestamp suffix). The tails write the same
   record-type bytes as the inners (Put 0x01/0x05, Delete
   0x00/0x04, SingleDelete 0x07/0x08, DeleteRange 0x0f/0x0e,
   Merge by push_back), pinned from their movb / push_back
   sites. Timestamp size != 0: the middle builds a
   zero-filled string of that size — the timestamp — and
   calls the inner appender with the parts [key Slice,
   timestamp string], so the record key is the key bytes
   followed by ts_size NUL bytes. PutEntity is the
   exception: it takes the inner only when the timestamp
   size is 0, and otherwise returns InvalidArgument
   "Cannot call this method on column family enabling
   timestamp"; with no column-family handle (rdx == 0) it
   returns InvalidArgument "Cannot call this method
   without a column family handle".
4. **Inner** (`inner_<op>.txt`): appends the one record to
   `rep_` (type byte, varint32 CF id when nonzero,
   varint32 key length + key, varint32 value length +
   value for Put / Merge / PutEntity; end key instead of a
   value for DeleteRange), sets its flag bit, bumps the
   count, and runs the shared hash-combine epilogue.

## The column-family resolver (0x5fbbc90)

`cf_resolve(struct, batch, cf_obj, rcx, r8)`:

* `cf_id = 0x5d8d4b0(cf_obj)` is stored at struct+0x08
  (0 for the default column family).
* If `cf_obj` is null, the timestamp size is taken from
  `batch+0x38` and the code is 0.
* Otherwise virtual slot 0x28 is called on `cf_obj`; its
  result `P` is null -> timestamp size 0, code 0. `P`
  non-null -> timestamp size `*(P+0x28)`.
* When the CF id is 0 (default CF) and the timestamp size
  differs from `*(batch+0x38)`, the record carries
  InvalidArgument "Default cf timestamp size mismatch"
  (34 bytes at 0x95d110).

## Errors, verbatim

* Merge, no merge operator: code 3 NotSupported,
  "Provide a merge_operator when opening DB" (40 bytes at
  0x968af8; wrapper 0x5e95d70).
* PutEntity, no CF handle: code 4 InvalidArgument,
  "Cannot call this method without a column family handle"
  (54 bytes at 0x95e658; middle 0x5fc4db0).
* PutEntity, timestamped CF: code 4 InvalidArgument,
  "Cannot call this method on column family enabling
  timestamp" (59 bytes at 0x96a420; middle 0x5fc4db0).
* Default-CF timestamp size mismatch: code 4
  InvalidArgument, "Default cf timestamp size mismatch"
  (34 bytes at 0x95d110; resolver 0x5fbbc90).
* PutEntity, oversize key / entity: code 4
  InvalidArgument, "key is too large" (16 bytes at
  0x44d099) / "wide column entity is too large" (31 bytes
  at 0x965750; inner 0x5fc46c0).
* The guard's message is mapped in PR #3202
  ("cannot call this method on column family <name> that
  enables timestamp", code 4).

## Evidence format

* `records.json` holds semantic records only — no
  per-instruction mnemonic list. Instruction-level detail
  lives only in the verbatim whole-function excerpts
  (`wrap_*.txt`, `impl_*.txt`, `mid_*.txt`, `inner_*.txt`,
  `batch_ctor.txt`, `batch_dtor.txt`, `strdup.txt`,
  `cf_resolve.txt`, `tail_*.txt`, `guard_main.txt`).
  The mnemonics in them (`endbr64` included) are genuine
  instructions present in the target binary, not
  placeholders.
* `guard_main.txt` is re-shipped byte-identical from PR
  #3202 (SHA-256 455f831e6787d422a80cda71839d12ed4e26e3c3ab93ac5148d917ebcd73ce5a);
  the guard, the Status builder 0x61cf670 and the default
  getter 0x5d48510 are mapped in full there.
* `verify.py` re-checks the packet against the binary;
  `census.py` reproduces the caller census; `frames.txt`
  lists every FDE range; `callers.tsv` lists every direct
  call site; `relocations.txt` lists the RELATIVE records
  naming the pinned addresses (including the WriteBatch
  vtable slots and the typeinfo pointer).
* `tools/writebatch_ops_115.py` models the pipeline and
  the record bytes; `tests/test_writebatch_ops_115.py`
  checks it (182 checks).

## Unknowns

* What the virtual slot 0xe0 dispatch does with the batch:
  the model records the dispatch call (DB object, batch
  rep_, operation) but does not claim the callee's
  identity — a `DB::Write` is the natural reading, not a
  pinned fact. The slot's target cannot be resolved from
  the file because the rsi-object's vtable is a runtime
  value.
* The exact object identities behind the wrapper/impl
  argument slots (arg1 = the rsi-object whose slot 0xe0 is
  called; arg2 = the rdx-object the resolver and the slice
  builder read; arg3..arg5 = op arguments). They are
  described positionally, not named.
* The internals of the five tail callees (the
  timestamp-size-zero path): their addresses, sizes, call
  sites and record-type bytes are pinned (each tail has
  five direct callers — its middle plus four other
  functions — and writes the same type byte as its inner);
  their length-encoding, count bump and hash epilogue are
  not resolved this cycle, so the model treats the tail
  path as the same record shape with the plain key.
* The batch's post-append hash-combine epilogue
  (0x61c3c00 / 0x61c3530 with magic constants) is pinned
  as a shared shape; the hash function itself is not
  resolved.
* When the middle's timestamp error can fire given the
  wrapper guard already checks a timestamp indicator on
  a different object (rcx vs rdx) is not resolved from
  the file; both checks are pinned as observed.

## Target

Node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).
Work binary `work/hl-node-115.bin`, digest verified by
`verify.py`. Environment limits (this VM): no cargo/rustc,
no git-lfs, no Ghidra/Java — the reconstruction is the
deterministic offline Python model in `tools/` plus its
tests; `make verify` / `make test` could not be run here.
