# RE-001: map node #94 WAL replay driver 0x520c120

Task: RE-001 (#94 function map). Bounded question: given an out status
struct, a context struct, a file type, a log number, and an out-pointer
slot, what exact sequence of type dispatch, replay-cache lookup, filename
building, single-record replay, error handling, and cache insertion does
node #94's WAL replay driver run, and what does it write into the out
struct and the out-pointer slot?

- Component: node #94 WAL replay driver, window `0x520c120..0x520d31d`
  (4605 bytes, single FDE).
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the argument roles, the unsigned type
  dispatch, the signed-decimal formatting rule and its digit-count
  thresholds, the digit-pair table assembly, the unknown-type log line
  and code-3 status, both filename builders and their `%06llu.log`
  shape, the cache-table layout and both lookup walks, the found path,
  both replay call sites and their arguments, the status-byte save and
  copy rules, the cache-insert rules and rehash call contract, both
  error-chain walks (10 links each, identity field +0xe8 against the
  runtime value at 0x5778258), the byte-1 zeroing arm, and the type-1
  retry-as-type-0 arm; inference for the "WAL replay driver", "file
  type", "log number", and "error callback chain" readings (offsets
  and uses are pinned, source-level names are not); unresolved for
  the chain objects' types and method semantics, the runtime path
  component's content, the logger object's identity, the cache policy
  float, and every callee's internals beyond its pinned contract.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Scope included: the whole replay-driver function, its single direct
  caller (census only), and the call contracts of the replay step, the
  two filename builders and their shared name formatter, the detail
  builder, the variadic log dispatcher, the mutex lock/unlock wrappers,
  and the rehash auxiliary. Scope excluded: the internals of every
  callee, the behavior of the caller beyond its call setup, and the
  replay step itself (its own packet).

## Answer

`replay_driver(out, ctx, file_type, log_number, out_slot)` returns
`out`. The phases below run in order.

1. Entry: the out-pointer slot is zeroed. The file type is compared
   UNSIGNED: 0 and 1 take the driver paths; anything else takes the
   unknown-type path (step 2) and returns without touching the cache.
2. Unknown type (file_type > 1 unsigned): the value is formatted as a
   SIGNED decimal (sign = bit 31, magnitude = abs with the INT_MIN
   edge keeping 2147483648; digit counts 1..10 by the thresholds
   9/99/999/9999/99999/999999/9999999/99999999/999999999; digits
   least-significant-pair first against the "00".."99" pair table).
   The log dispatcher 0x522ea30 is called with level argument 3, the
   logger argument `(context)+0x30`, format
   `[%s:381] [WalManger] Unknown file type %s` (verbatim spelling,
   file `db/wal_manager.cc`), rendering
   `[db/wal_manager.cc:381] [WalManger] Unknown file type <decimal>`.
   The detail builder 0x542f040 then builds a code-3, subcode-0
   status whose message is `File Type Not Known ` (20 bytes, trailing
   space) prepended to the same decimal. The out status is that
   code-3 status; the out-pointer slot stays 0.
3. Cache lookup (types 0 and 1): the mutex at context +0x110 is
   locked. The table is buckets +0xd8, bucket count +0xe0, head
   +0xe8, element count +0xf0, policy +0xf8 (next-resize +0x100).
   Nodes are {next +0, key +8, value +16}. When the element count is
   zero, the head chain is walked linearly; otherwise bucket =
   log_number mod bucket count is walked as a bucket segment (stop at
   chain end or at the first node whose key hashes to a different
   bucket). On a hit, the cached value is stored into the out-pointer
   slot, the out status is zeroed, the mutex is unlocked, and the
   function returns. On a miss, the mutex is unlocked BEFORE the
   filename is built.
4. Filename: type 0 uses helper 0x529d060, type 1 uses helper
   0x529ca20 (both take the directory pair at context +0x148 and the
   log number). Type 1 yields
   `<dir>/<"%06llu.log" % log_number>`; type 0 yields
   `<dir>/<runtime component>/"%06llu.log" % log_number`, where the
   runtime component comes from a runtime-set (pointer, length) pair
   at 0x578df20/0x578df28 whose content is not pinned from the
   binary. Both delegate the final component to 0x529c540, which
   formats `%06llu.%s` with ("log").
5. Replay: the replay step 0x520ad30 is called with (scratch status
   at rsp+0x40, context, filename string object, log number,
   out-pointer slot) at 0x520ca74 (type 0) or 0x520cd74 (type 1).
   Immediately afterwards the scratch status bytes are saved (byte 0,
   bytes 1..5, pointer field) and the scratch fields are zeroed.
6. Type-0 post-replay: byte 0 == 0 runs the cache-insert path (step
   7) and then propagates the saved status to out (byte forced 0).
   Byte 0 != 0 runs the error chain (step 8); afterwards, if the
   scratch byte 0 is 1, out is zeroed entirely and the function
   returns; otherwise the saved status is propagated to out.
7. Cache insert: the mutex is re-locked. A fresh 0x18-byte node
   {next 0, key = log number, value = out-slot value} is allocated.
   `_M_need_rehash` is called with (policy +0xf8, bucket count,
   element count, 1) after saving next-resize; on need, rehash
   auxiliary 0x5160ad0 runs and the bucket is recomputed. If the key
   is already present, the fresh node is freed and the table is
   unchanged. Empty bucket: the new node becomes the head, the old
   head's bucket entry (if any) is repointed at it, and this bucket's
   entry becomes the sentinel (context +0xe8). Nonempty bucket: the
   new node is inserted after the before-node. Element count +1.
   The mutex is unlocked.
8. Error chain: the chain head is the object at context +0xa0; links
   advance through +0x48; each link's identity field at +0xe8 is
   compared against the runtime value at 0x5778258. Ten links are
   examined; on the first mismatch that link's +0xe8 target is
   called directly with (status scratch pointer, filename string
   object pointer) and the walk stops; if all match, the tenth
   link's +0xe8 target is called. The call may rewrite the scratch
   status byte 0, which decides the next step.
9. Type-1 post-replay: byte 0 == 0 propagates the saved status
   directly (no cache insert). Byte 0 != 0 runs the error chain;
   afterwards, if the scratch byte 0 is still nonzero, the filename
   is rebuilt with the TYPE-0 builder and the replay step runs
   again, followed by the full type-0 post-replay sequence
   (step 6); if it is zero, the saved status is propagated.
10. Status copy: out receives the six saved status bytes (bytes
    0..5) plus the saved pointer at +8. Path A and path B copy the
    same six bytes in different orders (compiler scheduling only).

## Unknowns (kept separate from observations)

- The error-chain objects' types, the +0xe8 method's semantics, and
  the meaning of the runtime value at 0x5778258.
- The content of the runtime path component at 0x578df20/0x578df28.
- The identity of the logger object behind (context)+0x30.
- The cache policy float value at context+0xf8 (only its call
  contract is pinned: policy pointer, bucket count, element count,
  1, with next-resize saved first).
- LSDA/exception-pad mapping: landing stubs at 0x520d299..0x520d31d
  jump into the 0x520c054..0x520c120 region; the mapping is not
  pinned.
- The internals of every callee beyond its pinned contract, and the
  caller's behavior beyond its call setup (single direct caller at
  0x520d5a9 in 0x520d3a0..0x520e12e; 0 tail jumps; 0 qword refs).

## Verification

- `python3 research/work-items/RE-001-wal-replay-driver-94/verify.py`
  checks the excerpts against a fresh objdump run, the semantic
  records, the pinned rodata strings, the digit-table assembly, four
  sampled instructions byte-for-byte, and the caller census.
- `python3 -m unittest tests.test_wal_replay_driver -v` runs the
  model tests: decimal formatting (thresholds, sign, INT_MIN, pair
  bands), both filename shapes, the unknown-type log line and
  status, cache hit/miss/insert rules, both post-replay sequences
  (including the byte-1 zeroing arm and the type-1 retry), and
  packet agreement plus corruption controls.

## Tool versions and analysis options

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=<lo> --stop-address=<hi>
  work/hl-node-94.bin` from the repo root (repo-relative binary
  path, so the header spelling matches the committed excerpts).
- Python: 3.12.3; the packet checker uses numpy 1.26.4 for the
  vectorized census scans. Tests run under unittest (pytest is not
  installed on this VM).
- No cargo/rustc, no git-lfs, no Ghidra/Java on this VM; all
  analysis is static objdump/readelf work on the digest-verified
  binary above.
