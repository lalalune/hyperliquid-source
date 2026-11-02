# RE-001: node #94 hashtable rehash auxiliary 0x515a820

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x515a820 do end to end — how does it move every node of
a hash table into a new bucket array of a requested size, what
does it do to the bucket array entries, and what happens on the
allocation and overflow arms?

## Bound to

work/hl-node-94.bin SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
matching provenance/artifacts.json for node #94.

## What the window does

The window (0x515a820..0x515a95d, FDE 0x00634ce8, 317 bytes,
3 int3 padding bytes to the next FDE 0x515a960) rehashes a hash
table into a new bucket array. It returns void; the table is the
result. There is no stack canary in this window.

- Arguments: table pointer in rdi (saved in rbp), requested new
  bucket count in rsi (saved in rbx), and a pointer in rdx to a
  saved copy of the table's next-resize field (see the catch
  arm below). The rdx value is only read on the allocation
  failure path; on success it is never dereferenced.
- Table layout, as the window uses it: buckets pointer at +0x00,
  bucket count at +0x08, before-begin next pointer at +0x10,
  element count at +0x18, rehash policy at +0x20 (a float at
  +0x20, the next-resize count at +0x28), and a single-bucket
  storage slot at +0x30. A node carries its chain next pointer
  at +0x00 and its cached hash at +0x70. The cached-hash reading
  is cross-checked in the sole caller: the enclosing function
  also divides a node's +0x70 value by the bucket count to find
  that node's bucket (site 0x515ad23).
- Single-bucket arm: when the requested count is exactly 1, the
  new bucket array is the table's own +0x30 slot, zeroed with a
  single qword store, and no allocation happens. This arm
  bypasses the overflow checks below.
- Heap arm: otherwise the window allocates requested-count * 8
  bytes with operator new and zeroes the whole array with
  memset. Overflow guards run before the allocation: a count
  with bit 60 or above set is rejected; counts from 2**60 up to
  (but not including) 2**61 throw bad_alloc, and counts of
  2**61 or more throw bad_array_new_length. The distinction is
  the second shift test: count >> 61 nonzero means the byte
  size itself overflowed, count >> 60 nonzero with count >> 61
  zero means the count is merely too large to allocate.
- Migration: the old head is read from table+0x10 and that
  field is reset to null before the loop. Nodes are walked in
  their existing chain order (each node's next pointer at
  +0x00), and the walk is not re-sorted by bucket. For each
  node, the bucket index is the unsigned remainder of the
  node's cached +0x70 hash divided by the new count. When the
  target bucket entry is empty, the node is prepended to the
  global head (node next = current head, head = node) and the
  bucket entry is set to the sentinel address, i.e. the address
  of the table+0x10 field itself. When the target bucket entry
  is already set, the node is inserted after that entry's
  before-node (node next = before-node next, before-node
  next = node). After each insertion, when the inserted node's
  next pointer is null, the bucket entry at the *previous*
  bucket index is overwritten with the node itself; the
  previous index starts at 0 and becomes the current bucket
  index after each node. The next pointer is null exactly when
  the node lands at the tail of the chain as it stands: always
  for the first node walked (the head was reset to null), and
  again for any later node inserted after the current tail
  node — for example successive nodes of a bucket whose
  before-node is the tail, or every node after the first in
  the single-bucket arm, where each insertion appends at the
  tail. Each firing overwrites the previous-bucket entry with
  the new node, so in the single-bucket arm bucket 0 ends up
  holding the last node, not the first. The model implements
  the condition literally rather than special-casing the first
  node, so the recorded behaviour is the algorithm's own, not
  a simplification of it.
- Epilogue: the old bucket array is freed with operator
  delete[] over old-count * 8 bytes, unless the old buckets
  pointer equals the table+0x30 single-bucket address, in which
  case no free happens. Then table+0x08 is set to the new count
  and table+0x00 to the new base. The element count at +0x18
  and the policy float at +0x20 are untouched.
- Catch arm: if operator new throws, the catch entry restores
  table+0x28 from the saved copy ([rdx]) and rethrows; the
  table's buckets, count and head are untouched because the
  failure happens before migration. The second landing entry
  ends the catch and resumes unwinding. The window's own
  landing stubs are the two endbr64 entries at the tail of its
  range; which call each serves is not claimed beyond the
  allocation region the catch covers.
- Empty table: with a null old head the loop is skipped, the
  old array is freed under the same rule, and the new (zeroed)
  array is committed. The table's head stays null.
- Zero requested count: there is no guard for it; the migration
  would divide by zero. The model raises for 0 instead of
  modelling a fault, and this arm is recorded as unclaimed
  binary behaviour, not as a verified outcome.

## Caller

Caller census (full .text direct-call scan, tail-jump scan,
whole-file qword scan): exactly one direct caller, at
0x515acf8, inside the enclosing function 0x515a960..0x515ae14
(the hashtable range-construction routine). No tail jumps and
no absolute references exist, so the reaching path beyond that
caller is left unclaimed. At the call site the caller passes
the table in rdi, the rehash-policy need-rehash result (in rdx
after that call) as the new count in rsi, and the address of a
stack slot in rdx; that slot holds a copy of table+0x28 taken
just before the need-rehash call, which is exactly the value
the window's catch arm restores. After the call returns, the
caller divides an element value by the new table+0x08 to get
that element's bucket index. The caller is census plus this
argument-passing contract only; the caller's own insertion
logic is not modelled here.

## Explicit unknowns

- The identity of the table's element type and of the hash
  function that produced the cached +0x70 values: the window
  only consumes the cached value, it never computes a hash.
- The meaning of node payload beyond the +0x00 next pointer
  and the +0x70 cached hash, and of the table's element count
  beyond it being untouched here.
- What the caller does with the table after rehashing, beyond
  the post-call bucket-index division noted above.
- The reaching path beyond the single caller, and the reason
  the first-node fixup writes bucket index 0 rather than the
  first node's own bucket: recorded as the algorithm's literal
  behaviour, not explained.

## Evidence format note

Instruction-level detail lives only in the raw disassembly
excerpt text files in this packet, kept verbatim and
whole-function. The JSON file in this packet holds semantic
records only. The raw excerpts are genuine objdump output from
the digest-verified binary: the endbr64 bytes at the window
start and the other excerpt bytes are the target binary's own
bytes, not placeholders. The verify script re-checks the
excerpts byte-for-byte against a fresh objdump run.
