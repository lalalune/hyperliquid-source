# RE-001: node #94 mutex-guarded counted-key insert-or-increment 0x5160940

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x5160940 do with a mutex-guarded vector of (key, count)
pairs — in what order does it search, when does it increment instead
of inserting, where does a new key land, and what happens when the
vector is full?

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

The window (0x5160940..0x5160aca, FDE 0x00635030, 394 bytes,
6 int3 padding to the next FDE 0x5160ad0) takes the outer struct
in rdi and a key in rsi, and returns void. The outer struct holds
a vector at +0x00 (begin) / +0x08 (end) / +0x10 (capacity) of
16-byte elements (key at +0x00, count at +0x08) and a mutex at
+0x18. Keys are compared unsigned (jae) and stored verbatim; the
key's semantic type is not claimed.

- Locking. The mutex at +0x18 is locked first; a nonzero lock
  result throws system_error (0x5160aa7 path). Every normal exit
  unlocks the mutex (tail jump at 0x51609f5); the exception
  cleanup below unlocks it on the throwing path.
- Search. The vector is walked from the end toward the begin.
  Each step compares the key against the element at the current
  position minus 0x10. In AT&T syntax `cmp %rbx,-0x10(%rax)`
  computes element minus key, so `jae` is taken while the element
  is greater than or equal to the key: the scan steps toward the
  begin while elements exceed the key. Equal means the key is
  present.
- Increment. On a match, the element's count field (+0x08) is
  increased by 1 (addq, so it wraps modulo 2^64), the mutex is
  unlocked, and the window returns.
- Insert. On a miss, a new (key, 1) pair is inserted so the
  vector stays in ascending key order: if the key is greater
  than the last element (or the vector is empty) it is appended
  at the end; if it is greater than some element while smaller
  than the ones after it, it is inserted immediately after that
  element, shifting the tail right by 16 bytes (a single 16-byte
  copy for a one-element tail, memmove otherwise); if it is
  smaller than every element, it is inserted at the begin.
- Growth. When end equals capacity, the window does not insert
  itself: it calls the growth helper 0x5160790 (388 bytes, FDE
  0x0029b2cc, callee only) with (outer, pair pointer), which
  inserts the pair, and then takes the normal unlock epilogue.
  The helper's internals are not pinned by this item.
- Cleanup. The landing pad 0x5160914..0x5160940 (no FDE of its
  own) unlocks the mutex and calls _Unwind_Resume; the tail stub
  0x5160abe..0x5160aca inside the window moves the exception
  object to rbx and jumps to it. Canary fs:0x28 at rsp+0x18.

## Caller

Caller census (full .text e8/e9 scans plus a whole-file qword
scan): exactly one direct caller, 0x52251f2, inside
0x5225020..0x5225381, passing a field at its struct +0x1698 as
the outer struct and a key in r15. No tail jumps, no qword
references. The caller is census only; its enclosing routine is
not modeled here. Observation, not a claim: the same +0x1698
offset appears for the pending-erase sweep's site-3 caller in
PR #1798; whether the two structs are the same object is not
claimed.

## Assumptions and unknowns

- The key is an unsigned 64-bit value; signedness is not claimed
  beyond the unsigned comparison the bytes show.
- The growth helper's allocation strategy and failure behavior
  are not pinned; the model exposes it as a caller-supplied
  callback with the exact (table, key) contract the call site
  shows.
- Only one direct caller was found; indirect reachability
  through the growth helper or the caller routine is not claimed.

## Verification

`python3 research/work-items/RE-001-counted-key-insert-94/verify.py --binary work/hl-node-94.bin`
checks the binary digest, byte-for-byte excerpt regeneration,
the MANIFEST, the semantic-only shape of records.json, first-byte
spot checks for the pinned sites, and the caller-site call.
The model in tools/foundation_counted_key_insert.py and its
tests in tests/test_foundation_counted_key_insert.py cover the
search order, every insert arm, the increment (including the
2^64 wrap), the growth contract, the lock-failure throw, and
the unlock-on-every-path rule.
