# RE-001: five timestamp-gated SliceParts WriteBatch operations (node #115)

Bounded question: what do the five sibling routines at
0x5e94690..0x5e961bc do around the timestamp-size gate
0x5e882b0, and what operation does each one perform?

Answer, in one line each: each is a `Status`-returning database
operation that (1) runs the timestamp-size gate, (2) builds a
`rocksdb::WriteBatch` on the stack with the resolved timestamp
size, (3) appends exactly one record to the batch through one
`WriteBatch` vtable function that builds the record from Slice
parts, and (4) dispatches the batch through virtual slot 0xe0
of the rsi-object. The five operations, identified by the
record-type byte each inner appender writes (rocksdb
`ValueType`):

| operation | wrapper | impl | middle (vtable slot) | inner | record type default / CF |
|---|---|---|---|---|---|
| Put | 0x5e94800 | 0x5e94690 | 0x5fbf7d0 (slot 4) | 0x5fbf0b0 | 0x01 / 0x05 |
| Delete | 0x5e95040 | 0x5e94ee0 | 0x5fc04f0 (slot 15) | 0x5fbff40 | 0x00 / 0x04 |
| SingleDelete | 0x5e95560 | 0x5e95400 | 0x5fc11e0 (slot 20) | 0x5fc0c30 | 0x07 / 0x08 |
| DeleteRange | 0x5e95ac0 | 0x5e95950 | 0x5fc2080 (slot 25) | 0x5fc1980 | 0x0f / 0x0e |
| Merge | 0x5e960a0 | 0x5e95f30 | 0x5fc4220 (slot 10) | 0x5fc3b00 | 0x02 / 0x06 |

These are the timestamp-enabled counterparts of the six
operations in PR #3209: where #3209's guard 0x5d58810 rejects a
column family that ENABLES timestamp, this gate 0x5e882b0
rejects one that does NOT enable it (or whose timestamp size
mismatches the caller's). The wrappers sit in the adjacent
slots of the same four parallel tables as #3209's wrappers,
and the middles sit in the same `WriteBatch` vtable
(0x64cd498) at the slots above.

## The timestamp-size gate (0x5e882b0)

`gate(out, factory, ts_slice, flag)` (3437 bytes, FDE
0x5e882b0..0x5e8901d). Five direct callers, one per wrapper
(0x5e94848, 0x5e95081, 0x5e955a1, 0x5e95b08, 0x5e960e8). All
five call sites pass flag 0 (`xor %ecx,%ecx`); the flag branch
below is mapped from the gate disassembly only, not from a
caller-observed call.

* Factory null: `InvalidArgument` "column family handle
  cannot be null" (0x9600e8, 35 bytes).
* `resolved = factory slot 0x28()`; `ts = *(resolved+0x28)`.
  `ts == 0`: `InvalidArgument` "cannot call this method on
  column family " (0x9600b8, 41) + the name (factory slot
  0x10 returns a `{ptr:+0, len:+8}` view) + " that does not
  enable timestamp" (0x95ccc0, 31), built through an
  ostringstream and the Status builder 0x61cf670 (code 4).
  The second view in that message is `{ptr 0x4376fd,
  len 0}` — the byte at 0x4376fd is 0x00 and the bytes
  after it read a `oneshot.rs` source path, but the view
  length is 0, so the path is never copied into the message
  (same pattern as PR #3202).
* `ts != *(ts_slice+0x08)` (the ts slice's length):
  `InvalidArgument` "Timestamp sizes mismatch: expect "
  (0x960f08, 33) + the resolved size + ", " (0x4360a5, 2) +
  the caller's size + " given" (0x4350be, 6). The first
  number is the column family's size ("expect"), the second
  is the caller's ("given").
* Flag branch (`flag != 0`): `obj2 = factory slot 0x30()`;
  the std::string at `obj2+0x9a8` (ptr) / `+0x9b0` (len) is
  copied into a local string (heap-allocated when len > 15).
  Length 0 skips the check and returns OK; length >= 1
  proceeds. Then `rcx = *(resolved_vtable + 0xc8)` is
  compared with the qword at GOT slot 0x64ecfa8 (RELATIVE
  addend 0x5d48400, the always-OK stub `endbr64; xor %eax,
  %eax; ret`): equal means OK without calling it, different
  means call `slot(resolved, ts_slice, &str_slice)`; a
  return < 0 gives `InvalidArgument` "Read timestamp: "
  (0x4350c5, 16) + hex(ts_slice) + " is smaller than
  full_history_ts_low: " (0x963e60, 38) + hex(str). The hex
  uses the helper 0x61c7e30 (`rdx=1` hex-encodes, `rdx=0`
  copies verbatim) and is UPPERCASE — the nibble helper
  0x61c7da0 returns `'0'+n` for n <= 9, `'A'+n-10` otherwise.
* OK path writes Status code 0, subcode 0, message ptr null
  (16-byte Status: code u16 +0x00, subcode u32 +0x02,
  message ptr +0x08).

## The timestamp-size resolver (0x5fb6910)

`resolve(out, cf_obj, ts_slice)` (288 bytes, FDE
0x5fb6910..0x5fb6a30). Five direct callers, one per middle
(0x5fbf80d, 0x5fc0528, 0x5fc1218, 0x5fc20c0, 0x5fc425d).

* `cf_obj` null: `InvalidArgument` "column family handle
  cannot be null".
* `P = cf_obj slot 0x28()`; `*(P+0x28) == 0`:
  `InvalidArgument` "timestamp disabled" (0x445389, 18).
* `*(P+0x28) != ts_slice.len`: `InvalidArgument`
  "timestamp size mismatch" (0x433186, 23).
* Otherwise OK. The ts slice's length is the timestamp size
  being checked — the second key part's length must equal
  the column family's timestamp size.

## How the identification was made

* The stack struct built by 0x5fb9f90 is a
  `rocksdb::WriteBatch`: its first qword is the vtable at
  0x64cd498, whose typeinfo pointer record (RELATIVE at
  0x64cd490, addend 0x64cd338) names `rocksdb::WriteBatch`
  (`N7rocksdb10WriteBatchE`), and its embedded string is
  resized to 12 NUL bytes — the batch `rep_` header
  (8-byte sequence 0 + 4-byte count 0). The destructor is
  0x5fb7ee0 (vtable slot 0).
* The five middle callees are the functions listed in that
  vtable at the slots in the table above (RELATIVE addends
  at 0x64cd498..; slots counted from the vtable pointer,
  slot 0 = the destructor 0x5fb7ee0 — see `relocations.txt`
  and `census.py`). Slot 35 (0x64cd5b0) has no RELATIVE
  relocation record; the qword at 0x64cd5b8 (slot 36) is
  0x64cd368, a data address, not a function. Each middle
  calls the resolver 0x5fb6910, sets `batch+0x22 = 1`, reads
  the CF id from virtual slot 0x18 of the cf_obj, and calls
  its inner appender with the Slice-parts arrays.
* Each inner appender writes one record type byte into the
  batch `rep_`: Put pushes 0x05 (CF) or 0x01 (default CF);
  Delete stores 0x04 / 0x00; SingleDelete 0x08 / 0x07;
  Merge pushes 0x06 or stores 0x02; DeleteRange stores
  0x0e / 0x0f. The branch is the column-family id: id == 0
  takes the default-CF type, id != 0 the CF type. The choice
  of the default-CF byte is confirmed independently by each
  inner's hash-combine epilogue, which carries the default
  type byte (Put 0x01, Delete 0x00, SingleDelete 0x07,
  Merge 0x02, DeleteRange 0x0f). The inner excerpts are
  re-shipped byte-identical from PR #3209 (SHA-256 pinned
  in `verify.py`).
* The wrappers are the five functions that call the gate
  and then their implementation: Put 0x5e94800, Delete
  0x5e95040, SingleDelete 0x5e95560, DeleteRange 0x5e95ac0,
  Merge 0x5e960a0. The Merge wrapper was found through the
  gate's fifth call site (0x5e960e8); it is not named in
  the earlier candidate notes. Each wrapper is a RELATIVE
  addend in four parallel tables with identical spacing
  (Put +0x28 Delete +0x20 SingleDelete +0x20 DeleteRange
  +0x18 Merge from the first table's Put slot); the PR
  #3209 wrappers sit in the adjacent slots. The four
  tables are four related classes' function tables; their
  bases are not pinned from the file alone, so no absolute
  slot numbers are claimed for the wrappers.
* The implementations resolve the default timestamp size
  through factory slot 0x3e8 (the default getter
  0x5d48510: `mov 0x740(%rdi),%rax; ret` — it returns
  `*(factory+0x740)` when the slot is the default getter,
  otherwise the slot is called) then slot 0x28 and
  `*(result+0x28)`, and pass that size as the constructor's
  r8 argument, stored at `batch+0x38` (PR #3209's
  implementations passed 0 there). The DeleteRange
  implementation 0x5e95950 additionally has two RELATIVE
  records (0x64c8380, 0x64d9890) and two stored qwords
  (file offsets 0x101800, 0x12d480); the table behind those
  registrations is not identified this cycle.
* The hex helper 0x61c7e30 has 120 direct callers,
  including the gate's two (0x5e88d94, 0x5e88dfb); the
  nibble helper 0x61c7da0 has exactly 2, both inside the
  hex helper. The Status builder 0x61cf670 has 847 direct
  callers and the strdup helper 0x61cf610 has 425; the
  batch constructor 0x5fb9f90 has 27 and the destructor
  0x5fb7ee0 has 65.

## Pipeline, per operation

1. **Wrapper** (`wrap_<op>.txt`): calls the gate 0x5e882b0
   with (out = stack-temp Status, factory = rcx, obj = r9,
   flag = 0). Gate non-OK: the Status is copied into the
   caller's out (message deep-copied with the strdup helper
   0x61cf610) and the wrapper returns. Gate OK: all
   arguments are forwarded to the implementation. Put,
   DeleteRange and Merge use the rbp-frame variant; Delete
   and SingleDelete the rsp-frame variant.
2. **Implementation** (`impl_<op>.txt`): resolves the
   default timestamp size via factory slot 0x3e8 then slot
   0x28 and `*(result+0x28)`; constructs a `WriteBatch` on
   the stack via 0x5fb9f90 (vtable 0x64cd498, `rep_` = 12
   NUL bytes, `batch+0x38` = the timestamp size, protector
   = `*(rdx+0x10)`); calls its middle callee with (temp
   Status, batch, ...op args); on a middle failure the
   Status is moved into out; on success calls virtual slot
   0xe0 on the rsi-object with (out, rsi-object, rdx,
   batch). The batch is destroyed with 0x5fb7ee0 on every
   path.
3. **Middle** (`mid_<op>.txt`): calls the resolver
   0x5fb6910 with (temp Status, cf_obj, ts_slice); a nonzero
   code is propagated into out; sets `batch+0x22 = 1`
   (contrast PR #3209's middles, which set
   `batch+0x21/+0x22 = 0x0101`); reads the CF id from
   virtual slot 0x18 of the cf_obj; builds the key parts
   `[key1, ts]` (2 Slice parts) and, for Put/Merge, the
   value parts `[value]` (1 part), and calls the inner
   appender. Delete and SingleDelete take no value;
   DeleteRange takes key parts `[key1, ts]` and end-key
   parts `[end1, ts]` (the same ts slice appended to both).
4. **Inner** (`inner_<op>.txt`): appends the one record to
   `rep_` (type byte, varint32 CF id when nonzero,
   varint32 key length + key-part bytes, varint32 value
   length + value for Put / Merge; end key instead of a
   value for DeleteRange), sets its flag bit, bumps the
   count, and runs the shared hash-combine epilogue
   (0x61c3c00 / 0x61c3530).

## Evidence

* `records.json` — semantic records only: the gate, the
  resolver, the hex/nibble helpers, the always-OK stub,
  the five operations (wrapper / implementation / middle /
  inner, vtable slot, record types, parts), the pipeline,
  the WriteBatch layout and full vtable slot map, the
  wrapper tables, the message literals, the Status layout,
  and the unknowns. Instruction-level detail lives only in
  the verbatim excerpts below.
* `gate_main.txt`, `hex_helper.txt`, `nibble.txt`,
  `ok_stub.txt`, `resolver.txt`, `wrap_<op>.txt`,
  `impl_<op>.txt`, `mid_<op>.txt` — whole-function
  verbatim objdump excerpts, generated with
  `objdump -d --start-address=<start> --stop-address=<end>
  work/hl-node-115.bin` (see `export_excerpts.py`).
  `inner_<op>.txt`, `batch_ctor.txt`, `batch_dtor.txt`,
  `strdup.txt` are re-shipped byte-identical from PR #3209;
  `status_builder.txt` and `default_getter.txt` from PR
  #3202 (SHA-256 pinned in `verify.py`). The mnemonics in
  them (`endbr64` included) are genuine instructions
  present in the target binary, not placeholders.
* `frames.txt` — the FDE range of every pinned routine
  (30 lines). `callers.tsv` — every direct call and tail
  jump to a pinned routine, with the smallest enclosing
  FDE as the caller (1526 rows). `relocations.txt` — the
  WriteBatch vtable range plus every RELATIVE record naming
  a pinned routine (74 lines). `census.py` regenerates the
  census; `verify.py` re-checks everything against a
  fresh objdump / readelf / census run.
* `tools/ts_gate_ops_115.py` + `tests/test_ts_gate_ops_115.py`
  — a Python model of the gate, the resolver, the hex
  helper, the middle part assembly and the full
  wrapper-to-dispatch pipeline (69 checks). The model does
  NOT claim the inner appenders' full byte encoding
  (length-encoding, count bump, hash epilogue): it models
  the pinned record shape.

## Unknowns (recorded, not modelled)

* What the virtual slot 0xe0 dispatch does with the batch
  (a DB write is the natural reading, not a pinned fact).
* The exact object identities behind the wrapper/impl
  argument slots (factory vs column-family handle vs DB
  object vs timestamp slice).
* Which concrete column-family names occur at runtime, and
  what the slot 0x30 low-watermark string and slot 0xc8
  validator denote beyond the pinned message.
* The full internals of the five inner appenders
  (length-encoding, count bump, hash epilogue) beyond the
  record shape pinned in PR #3209.
* The two non-packet direct callers of each inner appender
  (0x5fbfa54/0x5fbfbac, 0x5fc0749/0x5fc0899,
  0x5fc1439/0x5fc1589, 0x5fc2324/0x5fc247c, 0x5fc44a4/0x5fc45fc).
* The tables behind the DeleteRange implementation's two
  RELATIVE registrations (0x64c8380, 0x64d9890).
* The absolute vtable slot numbers of the five wrappers
  (four parallel tables, bases not pinned).

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so
`make verify` / `make test` cannot run here; the packet's
own `verify.py` (run from the repository root) and the model
tests (`python3 tests/test_ts_gate_ops_115.py`) are the
checks. All findings are bound to the node #115 artifact
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, entry
`artifacts/node/115/hl-node`).
