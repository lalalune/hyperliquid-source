# RE-001: map node #115 insert helper 0x5f90bb0

Task: RE-001 (#115 function map). Bounded question: what does the
insert helper at 0x5f90bb0, left open as "rehash internals" by
RE-001-distinct-key-sum-115, do end to end — its two find phases,
its insert linking, its rehash trigger, its result pair and its
exception cleanup? This item maps the helper itself, its shared
cleanup block and its rehash body.

Artifact binding: every result below is bound to node #115, provenance
record `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
materialized locally as `work/hl-node-115.bin` (hash verified exactly
before use). The packet's JSON (`records.json`) holds semantic records
only: window identities, branch site→target pairs, census results, and
by-contract callee notes. Instruction-level detail lives only in the
verbatim whole-function disassembly excerpts in this directory, exported
with the commands below. Mnemonics such as `endbr64` in those excerpts
are genuine instructions present in the target binary, not placeholders:
each excerpt regenerates byte-for-byte from a fresh objdump run (see
`verify.py`), and sampled instructions were checked byte-for-byte
against both a fresh objdump run and the raw binary.

## Windows (whole functions)

- Insert helper, 0x5f90bb0..0x5f90d72 (450 bytes; FDE .eh_frame
  offset 0x74a43c, length 0x44, CIE 0x730230, with LSDA). Args:
  rdi = table, rsi = key holder. Vendor window
  node115-vendor-5f90bb0 registers this body as a librocksdb-sys
  0.11.0+8.1.1 build copy of `_Hashtable<u64, u64, Identity,
  equal_to<u64>, hash<u64>, _Mod_range_hashing, _Default_ranged_hash,
  _Prime_rehash_policy, _Hashtable_traits<false, true,
  true>>::_M_insert_unique`; this packet pins the observed behaviour
  of the window itself. The landing pad at 0x5f90d66 jumps to the
  shared cleanup block at 0x5f90b86; the stack canary is checked
  before both normal returns and a failure calls `__stack_chk_fail`.
- Shared cleanup block, 0x5f90b86..0x5f90bb0 (42 bytes; FDE offset
  0x74a484, length 0x20, CIE 0x730230). A bare continuation with no
  prologue, entered by jump with the throwing frame live (rbx =
  node to free, rbp = exception object, canary slot at rsp + 0x8):
  sized operator delete (rbx, 0x10), canary check, then
  `_Unwind_Resume` (rbp).
- Rehash body, 0x5da04d0..0x5da060d (317 bytes; FDE offset
  0x7364a0, length 0x3c, CIE 0x730230, with LSDA). Args: rdi =
  table, rsi = new bucket count, rdx = pointer to the caller's
  saved next_resize. Vendor window node115-vendor-5da04d0.

## Semantics, stated literally

Table layout (offsets from the table base): +0x00 bucket array
pointer, +0x08 bucket count, +0x10 before-begin (its qword is the
list head), +0x18 element count, +0x20 rehash policy (float max
load factor at +0x20, next_resize at +0x28), +0x30 inline single
bucket used while the count is 1. A bucket slot holds the node
whose `next` is the bucket's first node, or the before-begin slot
address (table + 0x10) when that first node is the list head. A
node is 16 bytes: +0x00 next, +0x08 key (the value equals the key;
the set is an identity map). The bucket of a key is
`key % bucket_count` (unsigned divide; the hash is the identity).

```
insert(table, holder):                     # returns (node, inserted?)
  key = [holder]
  if [table + 0x18] != 0:                  # bucketed find
    b = key % [table + 0x08]
    pred = buckets[b]
    if pred is set:
      node = next(pred)
      loop:
        if [node + 0x8] == key: return (node, false)
        nxt = [node]
        if nxt == 0 or [nxt + 0x8] % [table + 0x08] != b: break
        node = nxt
  else:                                    # zero count: linear scan
    node = [table + 0x10]
    while node != 0:
      if [node + 0x8] == key: return (node, false)
      node = [node]
    b = key % [table + 0x08]
  node = operator new(0x10)                # [node] = 0, [node + 0x8] = [holder]
  saved = [table + 0x28]
  (grow, new_count) = _M_need_rehash(table + 0x20, [table + 0x08],
                                     [table + 0x18], 1)     # PLT, see below
  if grow:
    rehash_0x5da04d0(table, new_count, &saved)
    b = key % [table + 0x08]
  if buckets[b] is set:                    # link after predecessor
    [node] = [buckets[b]]; [buckets[b]] = node
  else:                                    # link as new list head
    [node] = [table + 0x10]; [table + 0x10] = node
    if old head existed: buckets[[old head + 0x8] % [table + 0x08]] = node
    buckets[b] = table + 0x10
  [table + 0x18] += 1
  return (node, true)
```

Notes on the observed code, all verifiable in the excerpts:

- The find runs before any allocation, and the key is read from
  the holder twice: once at entry into r12 and again when the new
  node's value is stored (0x5f90c9c). Nothing in the window writes
  the holder, so both reads agree on any call the consumers make.
- The bucketed find stops the chain walk at the first node whose
  own bucket differs (0x5f90c25); the matched-node fallthrough at
  0x5f90c2f re-tests the node pointer for null (0x5f90c34) before
  returning — unreachable on a well-formed table, since the
  pointer tested is the node whose key just matched; the model
  does not reproduce that defensive branch.
- The zero-count find scans the whole list and never touches the
  bucket array; on a well-formed table a zero count implies an
  empty list, but the branch is observable whenever the count
  field and the list disagree (the differential harness exercises
  exactly that forged state, and the model follows the binary).
- The policy call's arguments are loaded before the node's value
  store completes the node, and the pre-insert counts are what the
  policy sees: (bucket count, element count, 1).
- Exception shape, from the decoded LSDA (landing-pad base =
  function start, no type table, cleanup actions only): the
  call-site row for the operator new call (0x5f90c81..0x5f90c86)
  names no landing pad — a throw there cleans up nothing in this
  frame; the row for 0x5f90cb1..0x5f90d1b (the policy call through
  the end of the rehash call) names the pad at 0x5f90d66, which
  jumps to the shared cleanup block: the freshly allocated node is
  deleted and unwinding resumes.
- The rehash body allocates and zeroes a new array (operator new
  of `8 * new_count`, then memset), or reuses the inline slot at
  table + 0x30 when the new count is 1; it then detaches the list
  and re-links each node in original list order — after its
  bucket's current slot owner when that slot is taken, otherwise
  as the new list head, updating the previous bucket's slot to the
  node when the node's successor exists — frees the old array
  unless it was the inline slot, and adopts the new array and
  count. Its catch block (0x5da05e0) restores [table + 0x28] from
  the saved-state pointer and rethrows.

## By-contract callees (stated explicitly)

- Rehash body 0x5da04d0: called only at 0x5f90d16 from this
  window. Its success path is modelled in
  `tools/insert_helper_5f90bb0_115.py` and the body is executed
  byte-for-byte in the differential harness; its exception path
  is pinned only as the restore-and-rethrow above. It has seven
  direct call sites file-wide; the other six belong to sibling
  table instantiations and are not claimed.
- `_Prime_rehash_policy::_M_need_rehash` (PLT 0x63f0ef0) is an
  external libstdc++ function — there is no body for it in this
  binary; it is resolved at run time. The caller consumes `al`
  (grow?) and `rdx` (new count), and the callee may update
  [policy + 0x8]. Its algorithm is pinned from the runtime
  library: with `total = element_count + n_ins`, no growth while
  `total <= next_resize`; otherwise `min_bkts` is
  `11.0 / max_load_factor` when `next_resize == 0 and total <= 10`
  and `total / max_load_factor` otherwise; below the current
  bucket count the answer stays no and `next_resize` becomes the
  truncated product `bucket_count * max_load_factor`; otherwise
  the table grows to the first prime in the policy list strictly
  above `max(int(min_bkts), 2 * bucket_count)` and `next_resize`
  becomes `int(new_count * max_load_factor)`. This was probed on
  a 3,500-case grid against the host `libstdc++.so.6` symbol of
  the same mangled name (0 mismatches), and the prime list in the
  model was extracted from that library's `__prime_list` symbol.
- Operator new (PLT 0x63f0dd0), sized operator delete (PLT
  0x63f0d80), `__stack_chk_fail` (PLT 0x63f0d70) and
  `_Unwind_Resume` (PLT 0x63f0a50) are used as named; the new is
  also the rehash body's array allocator, with `memset` (PLT
  0x63f0a90) zeroing the array.

## Census (whole-file scan; see census.py)

- Insert helper 0x5f90bb0: exactly 2 direct calls (0x5f90f9c
  inside walk 0x5f90da0 and 0x5f91217 inside the getter window
  0x5f91010..0x5f91253), 0 tail jumps, 0 qword hits, 0 RELATIVE
  addends. Both callers ignore the returned pair.
- Twin window 0x5da0640 (the other registered copy of the same
  build function): exactly 2 direct calls (0x5da0e6e, 0x5da17cb),
  0 tail jumps, 0 qword hits, 0 RELATIVE addends. Its 450 bytes
  differ from this window at 13 offsets, all inside relative
  branch displacement fields (the operator new, policy, rehash
  and `__stack_chk_fail` calls and the pad's jump). The twin's
  consumers are not claimed.
- Rehash body 0x5da04d0: exactly 7 direct calls (0x5da07a6,
  0x5dee099, 0x5e2d3dc, 0x5ec7964, 0x5f4dab6, 0x5f90d16,
  0x5fa5732), 0 tail jumps, 0 qword hits, 0 RELATIVE addends.

## Validation

- `verify.py` (this packet) — digest, manifest, excerpt
  regeneration, sampled bytes, FDE records, census, model tests.
- Unicorn differential (scratch harness, not committed; method
  follows the earlier packets): the real bytes of the helper, the
  rehash body and the cleanup block run under Unicorn with the
  PLT stubs above (operator new as a bump allocator mirrored by
  the model, the policy call decided host-side through the system
  libstdc++ symbol). After every call the full table state —
  bucket array contents, list order, node keys, element count,
  next_resize, allocator frontier — and the returned pair are
  compared against the model. Scenarios: 40 sequential inserts
  (growth 1 → 13 → 29 → 59), collisions with interleaved
  duplicates, keys at the 2^64 boundary, max load factors 0.5 and
  2.0, a forged 101-bucket table hitting the no-growth
  next_resize update, a forged zero-count table exercising the
  linear-scan find, and randomized soaks up to 200 inserts
  (final bucket counts up to 409). All runs matched.

## Objections / limits, stated openly

- The vendor registration gives the window a libstdc++
  instantiation name; this packet pins the window's observed
  behaviour, not the source-level identity of any other copy.
- The holder is given no type name: only its first qword is read.
- The policy function's algorithm is pinned from the host runtime
  library on this machine (libstdc++.so.6.0.33); a node host
  running a different libstdc++ build could in principle behave
  differently, and no bytes inside this artifact decide it.
- Exception behaviour is pinned from the LSDA and the cleanup
  blocks' code, not by raising exceptions through the emulated
  body; the differential exercises success paths only.

## Excerpt commands

```
objdump -d --start-address=0x5f90bb0 --stop-address=0x5f90d72 work/hl-node-115.bin
objdump -d --start-address=0x5f90b86 --stop-address=0x5f90bb0 work/hl-node-115.bin
objdump -d --start-address=0x5da04d0 --stop-address=0x5da060d work/hl-node-115.bin
```

Regenerate with `python3 export_excerpts.py` from anywhere; verify
with `python3 verify.py` from the repository root.
