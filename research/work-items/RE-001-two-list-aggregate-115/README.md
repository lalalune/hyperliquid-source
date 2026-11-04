# RE-001: node #115 two-list aggregate 0x5f13130

Bounded question: what does the function at 0x5f13130 compute from the
two lists hanging off its argument object, and how do its two callers
use the result?

## Window and artifact

- Window: 0x5f13130..0x5f13231 (257 bytes; FDE .eh_frame offset
  0x35909c, length 0x44, CIE 0, no LSDA, no landing pad).
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry
  artifacts/node/115/hl-node.
- Evidence in this packet: the whole-function verbatim objdump excerpt
  (main-5f13130.objdump.txt), frames.txt, relocations.txt, and the
  semantic records in records.json. Instruction-level detail lives
  only in the raw excerpt text files, kept verbatim and
  whole-function; records.json carries semantic records, not a
  per-instruction list. The objdump command that produced the
  excerpt is recorded in export_excerpts.py.
- Note on mnemonics: instructions such as `endbr64` in the excerpt
  are genuine instructions present in the target binary, not
  placeholders; verify.py checks sampled instructions byte-for-byte
  against a fresh objdump run and the raw binary.

## Object layout (as read from the window)

- Object + 0x00: first-list header. A node's next pointer is at
  node + 0x00 and its payload pointer at node + 0x10; the walk ends
  when the next pointer equals the header itself.
- Object + 0x18: second-list header, same node layout.
- Object + 0x20: distinguished-object pointer, read only when the
  second list is non-empty (see below).
- Payload + 0xa50 and payload + 0xa58: pointers to subobjects whose
  virtual slot 0x78 is called; payload + 0xa00: a direct qword.

## Semantics, stated literally

The window returns one 64-bit total in rax, computed with wrapping
64-bit arithmetic:

1. Total starts at 0.
2. First-list loop (0x5f13147..0x5f1318b): for each node, add three
   terms: the slot-0x78 result of the subobject at payload + 0xa50,
   the slot-0x78 result of the subobject at payload + 0xa58, and
   the qword at payload + 0xa00. An empty first list (header's next
   pointer equals the header) contributes nothing.
3. Second-list loop (0x5f1318d..0x5f131da): the same three terms for
   every node of the second list. An empty second list contributes
   nothing and skips step 4 entirely.
4. Distinguished block (0x5f131e3..0x5f1321c), only when the second
   list is non-empty: take the object at object + 0x20, read its
   payload at + 0x10, compute the same three terms, and subtract
   them from the total (slot results first, then the direct qword).
   The window performs no null check on object + 0x20 here: a null
   pointer with a non-empty second list would fault on the load,
   and the model raises instead of inventing a value.

So: total = sum(list1 terms) + sum(list2 terms) - terms(distinguished)
when list2 is non-empty, and total = sum(list1 terms) when list2 is
empty (the distinguished object is never read in that case).

## Consumers (census-confirmed direct calls, no tail jumps)

- 0x5f1327b inside 0x5f13240, a threshold check: when the caller's
  field + 0x38 is greater than 0 (signed), it returns
  (base argument + aggregate) >= field + 0x38, compared unsigned;
  otherwise it falls back to a comparison of the sign-extended
  dword at field + 0x30 against field + 0x10 + field + 0x28
  (see records.json for the literal fallback rule). The aggregate
  is the observable quantity the threshold is judged against.
- 0x5f1345c inside 0x5f13450, a cache refresh: the aggregate of the
  object at holder + 0x08 is stored to holder + 0x20, and a byte
  flag at holder + 0x28 records whether that object's second list
  is non-empty. This is why the aggregate matters end to end: it
  is cached and re-read by later code, not computed and discarded.

## Callees by contract

The six slot-0x78 calls (0x5f1315e, 0x5f1316e, 0x5f131ae,
0x5f131be, 0x5f131f7, 0x5f13208) are virtual accessors on the
subobjects at payload + 0xa50 / + 0xa58. Their internals are not
modelled; the model takes their results as input values.

## Unknowns, stated explicitly

- The owning component and the meaning of the two lists and of the
  distinguished object at + 0x20 are not pinned; only their layout
  and the arithmetic are claimed.
- The identity of the slot-0x78 accessors is not derived; their
  results are inputs, not conclusions.
- Why the distinguished object is subtracted exactly when the
  second list is non-empty is not claimed; the rule is recorded
  literally as the window implements it.

## Verification

- `python3 research/work-items/RE-001-two-list-aggregate-115/verify.py`
  prints ALL CHECKS PASSED: binary and provenance digests, packet
  manifest, byte-identical excerpt regeneration, 7 sampled plus
  3 extra self-check instructions byte-for-byte against a fresh
  objdump run and the raw binary, frames rows, census reproduction,
  and the model tests.
- `python3 tests/test_two_list_aggregate_115.py` runs the model
  tests (empty lists, one list, both lists with the distinguished
  subtraction, empty second list ignoring the distinguished object,
  missing distinguished object raising, 64-bit wrapping, both
  consumers, and packet checks). pytest is not installed on this
  VM, so the pytest-style file runs under plain python3 via its
  `__main__` runner.
- `make doctor` fails on missing providers on this VM
  (pre-existing: no cargo/rustc, no git-lfs, no Ghidra/Java);
  that failure is unrelated to this packet and is stated here
  honestly rather than hidden.

## Model

- tools/two_list_aggregate_115.py: the aggregate plus thin models
  of the two consumers (threshold check and cache refresh).
- tests/test_two_list_aggregate_115.py: tests for the aggregate
  and its consumers.
