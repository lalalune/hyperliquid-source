# RE-001: node #94 hashtable counted-key increment-or-insert 0x5160dd0

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x5160dd0 do with a mutex-guarded hashtable of (key,
count) pairs — when does it increment instead of inserting, how
does its find-or-insert callee place a new key, and how does the
rehash callee move the table to a new bucket count?

## Bound to

work/hl-node-94.bin SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
matching provenance/artifacts.json for node #94.

## A note on the excerpts

The packet's disassembly files are verbatim objdump output for
whole functions, exactly as objdump emitted them. Instruction
mnemonics that appear there (for example the `endbr64` at each
window start) are genuine instructions present in the target
binary, not placeholders and not sanitized tokens. The JSON file
in this packet carries semantic records only; instruction-level
detail lives in the raw excerpt text files.

## What the window does

The window (0x5160dd0..0x5160ebd, FDE 0x00635118, 237 bytes,
3 int3 padding to the next FDE 0x5160ec0) takes the outer struct
in rdi and a key in rsi, and returns void. The outer struct holds
a hashtable at +0x40 (buckets +0x00, bucket count +0x08,
before-begin next +0x10, element count +0x18, policy +0x20,
next-resize +0x28, single-bucket slot +0x30) guarded by the mutex
at +0x78. Those offsets match PR #1798's pending-key table: the
sweep erases from this table, this window increments and inserts
into it. The window never touches outer +0x00..+0x38, so that
range is not claimed here. Nodes are 24 bytes: next +0x00, key
+0x08, value (the count) +0x10. Keys are compared by 64-bit
equality and the bucket is the key modulo the bucket count
(unsigned division); there is no separate hash call, so the hash
is the key itself for this instantiation.

- Locking. The mutex at +0x78 is locked first; a nonzero lock
  result throws system_error (0x5160eaa path). The mutex is
  unlocked on the normal epilogue (0x5160e23) and on the
  exception path via the cleanup stub 0x5160dc0 (FDE 0x00635148,
  unlock then _Unwind_Resume, reached from the landing pad at
  0x5160eb1).
- Lookup. When the element count (+0x58) is zero, the window
  walks the chain linearly from the before-begin next; in a
  consistent table the head is null there and the walk falls
  straight to the insert path. Otherwise it walks the bucket
  segment: bucket = key mod bucket count, comparing keys until
  a match, the chain end, or the first node whose bucket
  differs (segment ended).
- Found. The matching node's value field (+0x10) is increased by
  1 (addq, so it wraps modulo 2^64), the mutex is unlocked, and
  the window returns. The found arm re-loads the before-node's
  next and falls to the insert path on null; that arm is recorded
  as observed but cannot fire from a consistent walk, because the
  node was just dereferenced.
- Miss. The window calls the find-or-insert callee 0x5160c10
  with (table at outer+0x40, the address of the key stack slot)
  and stores 1 into the returned value slot, then unlocks and
  returns.

## The find-or-insert callee 0x5160c10

Whole function 0x5160c10..0x5160dbf (FDE 0x006350d0, 431 bytes,
1 int3 padding to the next FDE 0x5160dc0). It takes (table rdi,
key pointer rsi) and returns the address of the node's value
slot (+0x10), on both the found and the inserted path.

- Lookup. The same bucket segment walk as the window: entry
  null means a never-written bucket and a miss; otherwise the
  first node and then each next node is compared, stopping at
  the chain end or at a node whose bucket differs.
- Miss allocation. A fresh 0x18-byte node is allocated: next 0,
  key copied from [rsi], value 0.
- Rehash decision. _M_need_rehash is called through the PLT with
  (policy at table+0x20, bucket count, element count, 1); the
  next-resize value (table+0x28) is copied to a stack slot before
  the call. The policy's prime table is not pinned here; the
  model takes it as a caller-supplied callable and pins only this
  call contract. On need, the rehash aux 0x5160ad0 is called with
  (table, the new count from the policy's rdx return, the saved
  pointer), and the bucket is recomputed as key mod new count.
- Insert after the before-node. When the bucket entry is set, the
  new node's next is the before-node's next, the before-node's
  next becomes the new node, and the entry is unchanged.
- Head insert. When the bucket entry is unset, the new node
  becomes the head; the old head's bucket entry (when there is
  an old head) is repointed at the new node, then this bucket's
  entry is the sentinel address (table+0x10).
- Element count +1 on both insert paths. Exception pad
  0x5160dae..0x5160dbf: on exception the fresh node is freed
  with operator delete (size 0x18), then _Unwind_Resume. Canary
  fs:0x28 at rsp+0x08.

## The rehash callee 0x5160ad0

Whole function 0x5160ad0..0x5160c0d (FDE 0x00635090, 315 bytes,
3 int3 padding to the next FDE 0x5160c10). It takes (table rdi,
new count rsi, saved next-resize pointer rdx). This is a
different instantiation from PR #1751's rehash aux at 0x515a820:
that one reads the cached hash at node +0x70, this one buckets by
the key at node +0x08. Different node type, different caller
families — not a duplicate.

- Single-bucket arm. New count 1 reuses the table+0x30 slot
  (zeroed qword), with no allocation and the overflow checks
  skipped.
- Overflow arms. Count >> 60 nonzero throws bad_alloc for
  [2^60, 2^61) and bad_array_new_length for >= 2^61. Otherwise
  count * 8 bytes are allocated and zeroed with memset.
- Migration. The old head is read from table+0x10 and reset to
  null; nodes walk in existing order with bucket = key mod new
  count. A nonempty bucket inserts after the before-node,
  touching neither the fixup nor the previous index. An empty
  bucket prepends to the head with the entry set to the sentinel;
  when the displaced head is non-null, the previous bucket's
  entry is repointed at the new node, then the previous index
  follows (previous starts 0, updates on the empty path only).
- Epilogue. The old array is freed with operator delete[] over
  old count * 8 unless the old pointer is the +0x30 slot; the
  bucket count and buckets pointer are committed; the element
  count and policy are untouched.
- Catch pad 0x5160be0: __cxa_begin_catch, table+0x28 restored
  from [saved pointer], __cxa_rethrow; the 0x5160bf9 pad does
  __cxa_end_catch and _Unwind_Resume. The pad is reachable from
  the operator new call, where the saved pointer is still live
  in r12. LSDA mapping not claimed. No canary in this window.

## Callers

Caller census (full executable-segment e8/e9 scans plus a
whole-file qword scan) for the window: exactly 2 direct callers,
0x521d157 inside 0x521d080..0x521d277 and 0x521d9df inside
0x521d820..0x521db4b; no tail jumps, no qword references. Both
callers walk an Rb_tree (Rb_tree_increment at the loop tail) and
pass a tree node's +0x28 field as the key. Census only; the
enclosing routines are not modeled here. The rehash aux has 3
direct callers (this item's insert callee plus 0x51e59ae and
0x520d244): it is shared across hashtable instantiations, and
only the insert call is modeled here.

## Assumptions and unknowns

- The key is an unsigned 64-bit value; signedness is not claimed
  beyond the unsigned division and equality the bytes show.
- The libstdc++ prime rehash policy behind the PLT call is not
  pinned; the model takes it as a caller-supplied callable.
- The outer +0x00..+0x38 range and the +0x18 mutex from PR #1798
  are not touched by this window and not claimed here.
- Only the direct callers above were found; indirect
  reachability is not claimed.

## Verification

`python3 research/work-items/RE-001-counted-key-hashtable-94/verify.py --binary work/hl-node-94.bin`
checks the binary digest, byte-for-byte excerpt regeneration,
the MANIFEST, the semantic-only shape of records.json, first-byte
spot checks for the pinned sites, and both caller-site calls.
The model in tools/foundation_counted_key_hashtable.py and its
tests in tests/test_foundation_counted_key_hashtable.py cover the
lookup walks, both insert arms, the rehash migration and fixup,
the overflow and allocation-failure arms, the call contract, the
increment (including the 2^64 wrap), the lock-failure throw, and
the unlock-on-every-path rule.
