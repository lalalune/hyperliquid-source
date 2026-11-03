# RE-001: map node #115 slot lookup 0x5f45cf0 with its accumulator leaf and group append

Task: RE-001. Bounded question: what does the node #115 slot lookup at
0x5f45cf0 do with a slot, an accumulator and an element, end to end
— lookup hit, accumulator apply, group append?

## Answer, stated literally

Signature, in native argument order: lookup(slot_array, accumulator,
element, index). The slot is array base + 112 * index, where index is
the int32 argument sign-extended to 64 bits. The key is element+0x8
masked once up front with 0x3fffffffffffffff, and every comparison in
every stage uses that masked key.

Stage 1/2, selected by slot+0x18:

- If slot+0x18 == 0, walk the chain headed at slot+0x10. Each node
  compares its +0x8 key with the masked key and links via its +0x0
  qword. A key match runs the leaf. Exhausting the chain falls
  through to stage 3/list below.
- If slot+0x18 != 0, bucket = masked key % slot+0x8 (the count) and
  the bucket entry is slot+0x0 (the table)[bucket]. A null bucket
  entry falls through to stage 3/list. Otherwise walk the record
  chain: the first record's key is compared directly; each later
  record's key must first re-hash to the same bucket (key % count
  == bucket) or the walk falls through to stage 3/list, and a key
  match runs the leaf. At 0x5f45da4 the wrapper's first qword is
  re-checked nonzero before the leaf tail-jump; in every reachable
  state it is the record just dereferenced, so a stage-2 key match
  always reaches the leaf.

Stage 3/list, selected by slot+0x50 and reached on any stage 1/2 miss:

- If slot+0x50 != 0, bucket = masked key % slot+0x40 (the count) and
  the bucket entry is slot+0x38 (the table)[bucket]. A null bucket
  entry runs the append. Otherwise walk the record chain: the first
  record's key is compared directly; each later record's key must
  first re-hash to the same bucket or the walk runs the append, and
  a key match runs the owner test.
- If slot+0x50 == 0, walk the list headed at slot+0x48. Each node
  compares its +0x8 key with the masked key and links via its +0x0
  qword. A key match runs the owner test. Exhausting the list runs
  the append.
- Owner test: if the matched record's +0x10 pointer is the element
  itself, run the append; otherwise run the leaf.

Leaf (0x5f6b620, accumulator apply): if element+0xb5 == 0, return
without touching the accumulator. Otherwise, all arithmetic wrapping
at 64 bits: acc+0xfb0 = acc+0xfb0 + element+0x88 - element+0x80;
acc+0xfb8 = acc+0xfb8 - element+0x88; acc+0xfc0 = acc+0xfc0 - 1.

Append (0x5f78060, group append): group = accumulator+0xa98 entries
[index] (24 bytes; +0x8 is the cursor, +0x10 the capacity end; +0x0
is never read here). If cursor != capacity end: store the element
at the cursor, advance the cursor by 8, and increment element+0xb0
by 1. If cursor == capacity end: call the grow helper at 0x5d9ee20
with (group entry, cursor, pointer to a stack slot holding the
element), then increment element+0xb0 by 1. The grow callee is
recorded as a call site only and is not modelled here.

Cross-reference: the append handler writes into the same
accumulator+0xa98 group array (24-byte entries) that the 0x5f6b660
element-rate pass walks, and the leaf's element fields +0x80/+0x88
are the same offsets that pass reads as threshold/high — but the
rate pass itself is not re-modelled here.

## Evidence

- Binary: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json as artifacts/node/115/hl-node.
- Windows: lookup 0x5f45cf0..0x5f45e5d (365 bytes, FDE file offset
  0x35bff8, length field 0x44, CIE 0); leaf 0x5f6b620..0x5f6b660
  (64 bytes, FDE file offset 0x35dd8c, length field 0x10, CIE 0);
  append 0x5f78060..0x5f780bf (95 bytes, FDE file offset 0x35e8e8,
  length field 0x24, CIE 0). See frames.txt.
- `excerpts/lookup.txt`, `excerpts/leaf.txt` and
  `excerpts/append.txt` are the whole-function disassemblies exactly
  as objdump emitted them, produced by:
  `objdump -d --start-address=0x5f45cf0 --stop-address=0x5f45e5d work/hl-node-115.bin`
  `objdump -d --start-address=0x5f6b620 --stop-address=0x5f6b660 work/hl-node-115.bin`
  `objdump -d --start-address=0x5f78060 --stop-address=0x5f780bf work/hl-node-115.bin`
  (run from the clone root; export_excerpts.py does the same).
  Instruction-level detail lives in those excerpts only; records.json
  holds semantic records (branch sites, fields, census), not a
  per-instruction list. The `endbr64` at the leaf and append window
  starts is a genuine instruction present in the target binary, not
  a placeholder.
- Census (whole-file scan, reproduced by census.py): lookup has
  exactly 6 direct calls (0x5f53342, 0x5f53373, 0x5f5366d, 0x5f53df6,
  0x5f53e26, 0x5f53e72), 0 tail jumps, 0 stored qwords, 0 RELATIVE
  addends; leaf has 3 direct calls (0x5f53747, 0x5f537af,
  0x5f5390a) plus 2 tail jumps from the lookup (0x5f45d50,
  0x5f45df6); append has 3 direct calls (0x5f539e4, 0x5f53a84,
  0x5f53b24) plus 1 tail jump from the lookup (0x5f45dcd).
  Every one of those 12 call sites lies inside the single function
  0x5f52c50..0x5f53f02 (4690 bytes), recorded as call sites only;
  that function is not modelled here.
- Model: tools/slot_lookup_append_115.py. Tests:
  tests/test_slot_lookup_append_115.py (16 tests, run under plain
  python3 via its `__main__` runner; pytest is not installed on
  this VM).
- verify.py re-checks the digest and its provenance binding, the
  manifest, excerpt regeneration byte-for-byte from a fresh objdump
  run, 5 gate + 3 extra instructions byte-for-byte against a fresh
  objdump run and against the raw binary bytes, the FDE ranges, the
  census, and the model tests. It prints ALL CHECKS PASSED on success.

## Assumptions and unknowns

- The slot fields +0x20/+0x28/+0x30 and +0x58..+0x70 are never read
  by these windows; their meanings are unknown and not claimed.
- The stage selectors slot+0x18 and slot+0x50 are named by their
  roles only; what sets them is not established by these windows.
- The grow helper at 0x5d9ee20 is outside this work item's windows:
  its internals and the native post-grow capacity are unknown and
  not claimed; the model extends capacity by the minimal fitting
  amount, and tests assert only the appended items and the +0xb0
  increment on the grow path.
- The single caller function 0x5f52c50..0x5f53f02 is recorded as
  call sites only; what it passes at each site is not modelled here.
- Environment limits, stated honestly: this VM has no cargo/rustc,
  no git-lfs and no Ghidra/Java, so no Rust reconstruction is claimed
  and the packet binds to the materialized work/hl-node-115.bin rather
  than the LFS-pointer artifact.

## Next question

What does the caller function 0x5f52c50..0x5f53f02 pass at each of
its 6 lookup sites, and what does the grow helper 0x5d9ee20 do to a
full group — the two boundaries this work item leaves open?
