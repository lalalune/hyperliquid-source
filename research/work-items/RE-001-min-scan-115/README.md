# RE-001: node #115 unmatched-node minimum scan 0x5f134b0

Bounded question: what does the function at 0x5f134b0 compute from
the list hanging off its argument object and the query record it is
given, and how does its smallest caller use the result?

## Windows and artifact

- Main window: 0x5f134b0..0x5f135c1 (273 bytes; FDE .eh_frame
  offset 0x3591d8, length 0x48, CIE 0, no LSDA, no landing pad).
- Value callee: 0x5f0a1d0..0x5f0a1dc (12 bytes; FDE .eh_frame
  offset 0x358b3c, length 0x10, CIE 0, no LSDA) — a single load of
  the qword at its argument + 0xc38.
- Caller window: 0x5d8bd30..0x5d8bd9d (109 bytes; FDE .eh_frame
  offset 0x34bac0, length 0x34, CIE 0, no LSDA, no landing pad).
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry
  artifacts/node/115/hl-node.
- Evidence in this packet: the whole-function verbatim objdump
  excerpts (main-5f134b0.objdump.txt, value-5f0a1d0.objdump.txt,
  caller-5d8bd30.objdump.txt), frames.txt, relocations.txt, and
  the semantic records in records.json. Instruction-level detail
  lives only in the raw excerpt text files, kept verbatim and
  whole-function; records.json carries semantic records, not a
  per-instruction list. The objdump commands that produced the
  excerpts are recorded in export_excerpts.py.
- Note on mnemonics: instructions such as `endbr64` in the excerpts
  are genuine instructions present in the target binary, not
  placeholders; verify.py checks sampled instructions byte-for-byte
  against a fresh objdump run and the raw binary.

## Object layout (as read from the windows)

- Outer list: sentinel at object + 0x08. A node's next pointer is
  at node + 0x00 and its key-record pointer at node + 0x10; the
  walk ends when the next pointer equals the sentinel itself.
- Query record: bucket array pointer at + 0x00, bucket count at
  + 0x08, linear chain head at + 0x10, mode flag at + 0x18.
- Chain entries link via + 0x00 and carry the compared key at
  + 0x08.
- Value field: key-record + 0xc38, read by the value callee.

## Semantics, stated literally

The window returns one 64-bit minimum in rax:

1. An empty outer list (the sentinel's next pointer equals the
   sentinel) returns 0 at once.
2. For each node, the window loads the node's key record from
   node + 0x10 and asks whether the query matches it:
   - Null query: no match is attempted; every node is unmatched.
   - Linear mode (query + 0x18 == 0): walk the chain from
     query + 0x10; a match is an entry whose + 0x08 field equals
     the node's key record. A null head or an exhausted chain
     means no match.
   - Hash mode (query + 0x18 != 0): divide the node's key value
     by the bucket count at query + 0x08 (unsigned div; a zero
     count faults, there is no guard) and take the remainder as
     the bucket index into the array at query + 0x00. A null
     bucket slot means no match. The first entry's key is
     compared directly, with no bucket check on it. Every later
     entry's key must hash to the same bucket, or the search ends
     as no match; a null next pointer also ends as no match.
   - On a hash hit the window tests the link field (%r9): nonzero
     advances as matched, zero falls to the call path. In every
     traced hit that field holds the matching entry itself, so the
     zero arm is not reachable from the traced paths; it is
     recorded as an open unknown, and the model treats a null link
     as no match.
3. A matched node advances the outer list with no call and no
   update.
4. An unmatched node calls 0x5f0a1d0 with the node's key record;
   the callee returns the qword at key-record + 0xc38. A zero
   result is skipped entirely; a nonzero result replaces the
   running minimum exactly when it is below it (the window
   computes r12 - 1 and takes the result on unsigned above-or-
   equal, which for a nonzero running value is exactly
   result < running, and for a zero running value always takes
   the nonzero result). The result is therefore the minimum over
   the nonzero callee results, or 0 when there is none.

## Caller (census-confirmed, modelled whole)

- 0x5d8bd5c inside 0x5d8bd30: when the byte at object + 0x978 is
  zero it returns the field at object + 0x948 at once. Otherwise
  it scans the list at object + 0x8f0 with a null query — so every
  node counts — takes the scan result when it is nonzero and below
  field948, and then takes the smaller of that candidate and the
  + 0xc38 value of the record at object + 0x8e8, with a zero value
  leaving the candidate in place instead of forcing zero. This is
  why the scan matters end to end: its minimum feeds a
  min-of-three selection, not a discarded computation.
- Two further direct call sites are census-confirmed
  (0x5e4bfca inside 0x5e4bea0, 0x5e4c2d5 inside 0x5e4c1a0); their
  internals were not read, so only their call sites are claimed.

## Unknowns, stated explicitly

- The owning component and the meaning of the outer list, the
  query record and the + 0xc38 field are not pinned; only their
  layout and the scan arithmetic are claimed.
- Whether the zero arm of the 0x5f13571 link test is reachable by
  any input the traced paths cannot produce.
- The internals of the two larger callers and of the query's
  producers; only their call sites are claimed.

## Verification

- `python3 research/work-items/RE-001-min-scan-115/verify.py`
  prints ALL CHECKS PASSED: binary and provenance digests, packet
  manifest, byte-identical excerpt regeneration, 10 sampled plus
  3 extra self-check instructions byte-for-byte against a fresh
  objdump run and the raw binary, frames rows, census reproduction,
  and the model tests.
- `python3 tests/test_min_scan_115.py` runs the model tests
  (empty list, null query, zero-result skipping, linear match and
  exhaustion, hash direct/chain hits, foreign-bucket termination,
  divisor-zero and null-head faults, and all caller arms). pytest
  is not installed on this VM, so the pytest-style file runs under
  plain python3 via its `__main__` runner.
- `make doctor` fails on missing providers on this VM
  (pre-existing: no cargo/rustc, no git-lfs, no Ghidra/Java);
  that failure is unrelated to this packet and is stated here
  honestly rather than hidden.

## Model

- tools/min_scan_115.py: the scan, both match modes, the value
  callee, and the null-query caller.
- tests/test_min_scan_115.py: tests for the scan and its caller.
