# RE-001: map node #115 sibling getters 0x5eeb490/0x5eeb4d0 with their list-sum and field-load callees

## Bounded question

What do the two sibling getters immediately following the predicate getter
0x5eeb460 (mapped by the previous PR) compute, and what do their callees
do? Both getters share one shape: read inner = outer + 0x788, read a base
qword from (inner + 0x8e8) + 0xcd0, add it to a value computed from
inner + 0x8f0, store the sum to *out, and return 1. This packet pins the
pair end to end: both getters whole, both callees whole, and the census
that shows each callee has exactly one caller.

## Windows

- List-sum getter: 0x5eeb490..0x5eeb4d0 (64 bytes), FDE at .eh_frame
  offset 0x356f48, length 0x24, CIE 0, no LSDA.
- Field-load getter: 0x5eeb4d0..0x5eeb510 (64 bytes), FDE at .eh_frame
  offset 0x356f70, length 0x24, CIE 0, no LSDA.
- List walk: 0x5f133e0..0x5f1341c (60 bytes), FDE at .eh_frame offset
  0x359140, length 0x28, CIE 0, no LSDA.
- Field load: 0x5f13420..0x5f13429 (9 bytes), FDE at .eh_frame offset
  0x35916c, length 0x10, CIE 0, no LSDA.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## Semantics (literal)

The outer object O carries inner = O + 0x788. The inner object carries a
record pointer at + 0x8e8 and the computed-value argument at + 0x8f0.
The record at inner + 0x8e8 carries a base qword at + 0xcd0.

List-sum getter (0x5eeb490):

1. It calls 0x5f133e0 with inner + 0x8f0.
2. It stores (list sum + base) to *out in 64-bit wrapping arithmetic
   and returns 1 unconditionally.

Field-load getter (0x5eeb4d0):

1. It calls 0x5f13420 with inner + 0x8f0.
2. It stores (field value + base) to *out in 64-bit wrapping arithmetic
   and returns 1 unconditionally.

List walk (0x5f133e0):

1. The list header is at argument + 0x08; the first node is the qword
   stored at the header itself; a node links to the next node via the
   qword at node + 0x00, and carries its payload pointer at + 0x10.
2. The walk ends when a next pointer equals the header itself; an
   empty list (first node == header) returns 0 at once.
3. For each node it calls 0x5f0e2d0 with the node's payload pointer
   and adds the returned value into a running sum in 64-bit wrapping
   arithmetic. The header itself is never passed to the callee.

Field load (0x5f13420):

1. It returns the qword at argument + 0x18, with no other effect.

## Census (whole-file scan, see census.py)

- 0x5f133e0: exactly 1 direct call, at 0x5eeb4b9 inside getter
  0x5eeb490; 0 tail jumps, 0 qword hits, 0 RELATIVE addends.
- 0x5f13420: exactly 1 direct call, at 0x5eeb4f9 inside getter
  0x5eeb4d0; 0 tail jumps, 0 qword hits, 0 RELATIVE addends.
- The getters themselves (0x5eeb490, 0x5eeb4d0): no direct calls, no
  tail jumps, no qword hits, no RELATIVE addends in the scanned ranges
  -- the same census shape as the neighbouring getters mapped by
  earlier PRs, which are reached through the object family rather than
  by direct calls.
- 0x5f0e2d0: 11 direct calls in the whole file (0x5d9115f, 0x5ecc153,
  0x5ecc18c, 0x5eccb2a, 0x5ed0c0d, 0x5ed0de1, 0x5ed19d5, 0x5ed29d0,
  0x5f127e2, 0x5f13404, 0x5f13e49), 0 tail jumps, 0 qword hits, 0
  RELATIVE addends. Only the in-window site 0x5f13404 is claimed here;
  the other ten callers' internals were not read.

## Evidence notes

- The packet's JSON (records.json) holds semantic records only. All
  instruction-level detail lives in the whole-function verbatim excerpts
  function_0x5eeb490.txt, function_0x5eeb4d0.txt,
  function_0x5f133e0.txt, and function_0x5f13420.txt, produced by
  running, from the repository root:
  `objdump -d --start-address=<start> --stop-address=<end> work/hl-node-115.bin`
  (see export_excerpts.py; running objdump from the repo root with the
  canonical relative path keeps the header byte-identical).
- Mnemonics such as `endbr64` in the excerpts are genuine instructions
  present in the target binary, not placeholders: verify.py checks sampled
  instruction bytes against the raw binary, and the excerpts regenerate
  byte-for-byte from a fresh objdump run.
- The four windows make no PLT calls, have no rip-relative references,
  and no stack canaries; the getters' sub rsp,8 is call alignment only.

## Model and tests

- tools/sibling_getters_115.py implements the semantics above: the
  header-terminated list walk with a per-element callback standing in
  for 0x5f0e2d0, the field load, and both getters with their shared
  base addend.
- tests/test_sibling_getters_115.py covers the empty list, single and
  multiple nodes, call order, 64-bit wrapping on both the sum and the
  getter addition, the field load, both getters' unconditional 1, the
  non-terminating chain raising, and the packet records.

## Unknowns

- The domain meaning of the record fields (what the base at + 0xcd0,
  the list at + 0x8f0, and the field at + 0x18 represent) is not
  claimed; only the arithmetic is.
- The internals of 0x5f0e2d0 are NOT claimed: it is modelled by
  contract only (called once per node with the node's payload pointer,
  its return added into the sum). A first read shows a spinlock-guarded
  body with virtual calls, too tangled to model honestly in this cycle;
  closing it is left as a follow-up item, exactly as the earlier PR
  left 0x5f6ad70 by contract before the next PR closed it.
- Whether the getters are reached through indirect branches beyond the
  scanned census is not claimed; the census covers direct calls, tail
  jumps, qword references, and RELATIVE relocations only.
