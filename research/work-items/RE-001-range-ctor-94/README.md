# RE-001: node #94 hashtable range constructor 0x515a960

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x515a960 do end to end — how does it build a hash table
from an input range of records, when does it skip a record as a
duplicate, and how does it link a new node into the bucket array?

## Bound to

work/hl-node-94.bin SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
matching provenance/artifacts.json for node #94.

## A note on the excerpts

The packet's disassembly files are verbatim objdump output for
whole functions, exactly as objdump emitted them. Instruction
mnemonics that appear there (for example the `endbr64` at the
window start) are genuine instructions present in the target
binary, not placeholders and not sanitized tokens. The JSON file
in this packet carries semantic records only; instruction-level
detail lives in the raw excerpt text files.

## What the window does

The window (0x515a960..0x515ae14, FDE 0x00634d28, 2740 bytes, no
padding — the next FDE 0x515ae14 starts immediately) builds a hash
table from a range of 0x68-byte records. It returns void; the table
is the result. Arguments: the output table in rdi, the first record
in rsi, the last record (exclusive end) in rdx, and a bucket-count
hint in rcx. The caller also pushes a fifth stack argument that
this window never reads; its role is not claimed.

- Table layout, as the window uses it: buckets pointer at +0x00,
  bucket count at +0x08, before-begin next pointer at +0x10,
  element count at +0x18, rehash policy at +0x20 (a float at +0x20,
  the next-resize count at +0x28), and a single-bucket storage slot
  at +0x30. A node carries its chain next pointer at +0x00, its key
  string at +0x08 (pointer), +0x10 (length), +0x18 (inline buffer or
  capacity), its payload at +0x28..+0x70, and its cached hash at
  +0x70. Bucket array entries point at the node *before* the
  bucket's first node (the before-begin sentinel, i.e. the address
  of the table+0x10 field, for a bucket whose first node is the
  chain head); an entry that was never written is empty, because
  the array is zeroed on allocation.
- Input record layout: key pointer at +0x00, key length at +0x08,
  payload at +0x20..+0x68 (0x48 bytes). Records step by 0x68.
- Initialization: count = 1, before-begin next = null, element
  count = 0, max load factor = 1.0, next-resize = 0, single-bucket
  slot = 0, buckets pointer = the +0x30 slot. Then _M_next_bkt is
  called on the hint. When the initial count (1) already covers the
  result, allocation is skipped. Otherwise the window allocates
  next-count * 8 bytes with operator new and zeroes the array with
  memset. Overflow guards run before the allocation: counts from
  2**60 up to (but not including) 2**61 throw bad_alloc, and counts
  of 2**61 or more throw bad_array_new_length. The single-bucket
  store arm at 0x515ad3f (zero the +0x30 slot when the next count
  is exactly 1) is unreachable from this initialization, because
  the count is set to 1 immediately above and the skip arm takes
  every count of 1; it is recorded as observed, not as a live path.
- Main loop, per record. The element count at loop head decides
  the search: while it is at most 20, the window scans the chain
  directly; above 20 it takes the hash path. (The count is tracked
  in a register that insertions update, so the decision follows the
  live count, and a duplicate skip leaves it unchanged.)
- Linear scan: when the head is null, or the chain ends without a
  match, the record falls through to the hash path. Empty keys use
  their own arm: walk while a node's length is nonzero, so the
  first zero-length node is the duplicate (a plain memcmp of
  length 0 would match any node, which is why the arm exists).
  Nonempty keys compare length, then memcmp over the key bytes.
  A match skips the record and the next record re-enters the
  linear loop head.
- Hash path: the key is hashed with _Hash_bytes and seed
  0xc70f6907, and the bucket is the unsigned hash remainder modulo
  the bucket count. When the element count is at most 20 the record
  inserts directly with no bucket walk. Otherwise the window walks
  the bucket's segment: the entry's before-node, then its next
  pointer as the first node. A node matches when its cached +0x70
  hash equals the computed hash and its key matches (length, then
  memcmp; empty keys match on length alone). On a mismatch the
  walk advances; it stops at the chain end, or at the first node
  whose bucket differs from the target bucket (that node's bucket
  segment ended), and the record inserts. On a match the record is
  skipped, and — unlike the linear skip — the next record goes
  straight to the hash path. The duplicate arm at 0x515ab07 checks
  the before-node's next pointer; on every consistent walk that
  pointer is the matched node itself, so the arm's insert branch
  cannot fire from a consistent table. It is implemented literally
  in the model and recorded here, not presented as a live path.
- Insertion: a 0x78-byte node is allocated; the key is copied
  (at most 15 bytes stay inline at node+0x18 with the length at
  node+0x10 and a NUL terminator after the bytes; longer keys go
  through _M_create with the capacity at node+0x18; a 1-byte key is
  copied directly with no memcpy call), and the record payload
  bytes +0x20..+0x68 are copied to node+0x28..+0x70. Then
  _M_need_rehash is called with (bucket count, element count, 1)
  against the policy at table+0x20; the table+0x28 value is copied
  to a stack slot before the call. When it reports need, the
  rehash auxiliary 0x515a820 (its own packet, PR #1751) is called
  with (table, new count, saved slot), and the bucket is recomputed
  as the hash modulo the new count before linking. When the bucket
  entry is empty, the node is prepended to the chain head; when an
  old head exists, the old head's bucket entry is repointed at the
  new node; and the new bucket's entry becomes the before-begin
  sentinel address. When the entry is already set, the node is
  inserted after the before-node (new node next = before-node next,
  before-node next = new node). The element count is incremented
  by 1, and the next record re-enters the linear loop head.
- Exception pads (inside the FDE range, LSDA mapping not claimed):
  a canary at fs:0x28 saved at rsp+0x28 and checked on the normal
  return and on the pads; a node-cleanup pad that begins a catch,
  deletes the 0x78-byte node and rethrows; a string-dispose pad
  that disposes the node's key string, deletes the node, and falls
  into a table-cleanup pad that ends the catch, calls the chain
  disposal 0x51524b0 (which walks the head at table+0x10 and
  disposes each node's key string), then resumes unwinding.
- Caller census (full .text e8/e9 scans plus a whole-file qword
  scan): exactly one direct caller, at 0x515f198 in the enclosing
  function 0x515b750..0x515f78b, which passes hint 0 (rcx zeroed),
  a static table address, a first pointer loaded from its stack,
  and a last pointer that is a stack address. No tail jumps and no
  absolute pointer references to the window exist.

## What is not claimed

- The payload fields at node+0x28..+0x70 are copied verbatim;
  their meanings are not claimed, and neither are the wrapper or
  owner identities behind the table, keys and payloads.
- The internals of the PLT callees (_M_next_bkt's prime table,
  _M_need_rehash's decision rule, _Hash_bytes) are not modelled;
  the model injects them as callables and pins their call
  contracts (arguments, results, and what the window does with
  them).
- The rehash auxiliary's own migration rule lives in its packet
  (PR #1751); here only its call contract is pinned.
- The caller's fifth stack argument, the single-bucket store arm's
  reachability, and the duplicate arm's insert branch are recorded
  as observed limits above, not explained away.

## Model and tests

tools/foundation_range_ctor.py models the window; tests/
test_foundation_range_ctor.py pins it, including the init arms,
both scans, both insertion rules, the rehash call contract, an
end-to-end range crossing the 20-element limit with duplicates,
packet verification, excerpt regeneration, and corruption controls.
