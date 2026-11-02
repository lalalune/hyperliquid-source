# RE-001: node #94 pending-key erase sweep 0x5160560

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x5160560 do with a pending vector and a hash table — in
what order does it lock, look up, erase, compact, and return, and
what stops the sweep early?

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

The window (0x5160560..0x5160783, FDE 0x00634fbc, 547 bytes,
no padding — the next FDE 0x516055e's neighbour 0x5160790 is a
separate function) takes one argument, the outer struct in rdi,
and returns either 0 or a pending key. The outer struct holds a
pending vector at +0x00 (begin) / +0x08 (end) of 16-byte
elements, a mutex at +0x18, a hash table at +0x40 (buckets
pointer), +0x48 (bucket count), +0x50 (before-begin next),
+0x58 (element count), and a second mutex at +0x78. A pending
element is (key at +0x00, floor at +0x08). A hash node is 24
bytes: (next at +0x00, key at +0x08, value at +0x10). The
semantic types of key, floor, and value are not claimed; they
are compared as unsigned values and the key is returned
verbatim, so the packet records them neutrally.

- Locking. Mutex A (+0x18) is locked first; a nonzero result
  throws system_error. Then, per pending element, mutex B
  (+0x78) is locked (a nonzero result also throws). After an
  element's hash removal, B is unlocked before compaction, and
  re-locked for the next element. On a bail, B is unlocked,
  then A, and the element key is returned. On full completion
  the result is reset to 0, A is unlocked, and 0 is returned.
- Empty vector. When begin == end, the window returns 0 without
  touching mutex B or the table.
- Lookup, count zero. The chain is walked linearly from
  before_begin_next (+0x50): each node's +0x08 is compared to
  the element key; reaching null bails with the element key.
- Lookup, count nonzero. Bucket = key mod bucket_count
  (+0x48). Starting from the bucket predecessor's next, keys
  are compared while each subsequent node's key hashes to the
  same bucket; a null step or a node hashing to a different
  bucket bails with the element key.
- Guard. A found node is erased only when its +0x10 value is
  >= the element's floor (unsigned). A smaller value bails
  with the element key and removes nothing for that element.
  Earlier elements already erased stay erased; the bail
  returns the first key the sweep could not erase, so a caller
  can resume from it.
- Removal. The target node is unlinked and freed with operator
  delete, size 0x18, and element_count (+0x58) decrements by
  1. When the target is the first node of its bucket, its
  successor becomes the predecessor's next; if the successor
  hashes to a different bucket, that bucket's entry becomes
  the predecessor, and when the old bucket's entry was the
  before-begin sentinel (the +0x50 field address), the
  before-begin next becomes the successor and the old bucket's
  entry is cleared to 0 — the target was its sole node. When
  the target is not first, the predecessor's next becomes the
  successor, with the same different-bucket repointing. This
  predecessor/sentinel fixup shape matches the standard
  library unordered-container erase shape; whether this window
  is first-party code or an inlined library routine is left to
  the maintainer, and the sweep around it (pending vector,
  floor guard, mutex protocol, compaction, bail-with-key
  return) is the behavior pinned here.
- Compaction. The pending element is removed by shifting the
  tail left: memmove when more than 16 bytes remain, a single
  16-byte copy when 16 or fewer remain, skipped when the
  element is already last; the vector end moves down by 16
  and the loop re-examines the same slot, so the next element
  is processed without skipping.
- Throws and cleanup. The landing stub at 0x5160777 moves the
  exception object to rbx and jumps to the cleanup at
  0x516054e, which unlocks mutex A and resumes unwinding.
  (LSDA mapping is not claimed.)

## Callers (census only)

Exactly three direct calls, no tail jumps, no qword references
(full .text e8/e9 scan plus whole-file qword scan):

- 0x50abaf2 in 0x50abad0..0x50abb45 and 0x50b0722 in
  0x50b0700..0x50b0775: twin 117-byte wrappers. Each calls a
  getter, then the sweep over its r8 struct, then a second
  call, and returns the minimum of the getter result, the
  sweep result (when nonzero), and the second call's result
  (when nonzero) — zeros count as absent, not as minima.
- 0x50ec61e in 0x50ebfb0..0x50ec9d7: passes a struct field
  at +0x1698 as the sweep struct. The enclosing routine is
  2599 bytes and is not modelled here.

## Unknowns

- The semantic types of the pending key, floor, and hash node
  value, and what the outer +0x60/+0x68/+0x70 table fields
  and the vector capacity slot hold (never read here).
- What the twin wrappers' getters and second calls compute
  (only their min-combination with the sweep result is
  pinned).
- Preconditions observed, not arms: on the bucket path the
  bucket count is nonzero (the window divides by it), the
  bucket predecessor's next is a live node in a consistent
  table, and the found node is reachable from its bucket
  predecessor.
