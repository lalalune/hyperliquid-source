# RE-001: map node #115 distinct-key sum 0x5f90da0

Task: RE-001 (#115 function map). Bounded question: what does the
hash-set walk at 0x5f90da0 compute end to end, given that it is
reached only through getter 0x5eeb3a0 and stub 0x5d8c9c0 (mapped by
#2298)? This item maps the walk itself, including its value leaf,
which the earlier item deliberately left open.

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

- Walk, 0x5f90da0..0x5f90fe2 (578 bytes; FDE .eh_frame offset
  0x74a4a8, length 0x50, CIE 0x730230, with LSDA). Arg: rdi = head.
  The landing pad at 0x5f90fd6 jumps to the cleanup block at
  0x5f90d72 (its own FDE 0x5f90d72..0x5f90d9f, not modelled here);
  the stack canary is checked before both normal returns and a
  failure calls `__stack_chk_fail`.
- Value leaf, 0x5dd3570..0x5dd357d (13 bytes; FDE offset 0x34e3e0,
  length 0x10, CIE 0, no LSDA). Arg: rdi = F. Returns
  `[F + 0x10] + 62` (0x3e), 64-bit wrapping.

## Semantics, stated literally

```
distinct_key_sum(head):
  total = 0
  seen = empty set of 64-bit keys
  node = [head + 0x1028]
  if node == head: return 0
  while node != head:
    for p in [node + 0xb18, node + 0xb20) step 16:
      E = [p]              # the second qword [p + 0x8] is never read
      F = [E]
      key = [F]            # first qword of F
      if key not in seen:
        seen.insert(key)   # via helper 0x5f90bb0, see below
        total += [F + 0x10] + 62    # 64-bit wrapping
    node = [node + 0x1028]
  return total
```

Notes on the observed code, all verifiable in the excerpt:

- The local set is built on the stack before the loop (single bucket
  inline, bucket count 1, max load factor 1.0) and destroyed after
  the loop (its nodes are freed with 0x10-byte operator delete and
  the bucket array is zeroed); the set has no observable output
  beyond the de-duplication above.
- Membership is observed in two forms, both skipping the entry on a
  match: a linear scan of the set's node chain when the set's element
  count field is 0 with a non-empty list, and a bucketed lookup
  (`key % bucket_count`, then a chain walk comparing each node's
  +0x8 key) otherwise. The bucketed-match fallthrough to the insert
  path, guarded on the predecessor's next pointer being null, never
  fires for a matched node in a consistent table (the predecessor's
  next pointer IS the matched node); the model treats a match as a
  skip.
- The set persists across chain nodes, so a key seen in any earlier
  entry of any earlier node contributes nothing when it recurs.
- A chain that never returns to head loops forever in the binary;
  the model raises ValueError instead, stated as model-only.

## By-contract callee (left open, stated explicitly)

- Insert helper 0x5f90bb0 (FDE 0x5f90bb0..0x5f90d72, CIE 0x730230,
  with LSDA): called with the local set and a holder containing the
  key. The packet pins only that it inserts the key: the walk calls
  it only after its own membership test already failed, its return
  is ignored, and the walk proceeds to add the leaf value, so the
  observable effect is insert-if-absent. Its rehash internals are
  NOT modelled here. Its other direct call site, 0x5f91217 inside
  the neighbouring function at 0x5f90fe2, is listed by site only
  and is not claimed.

## Census (whole-file scan; see census.py)

- Walk 0x5f90da0: 0 direct calls, exactly 1 tail jump (0x5d8c9c8,
  inside stub 0x5d8c9c0), 0 qword hits, 0 RELATIVE addends — so
  getter 0x5eeb3a0 + stub is the sole consumer path into the walk,
  as pinned by #2298.
- Insert helper 0x5f90bb0: exactly 2 direct calls (the walk's insert
  site 0x5f90f9c and 0x5f91217), 0 tail jumps, 0 qword hits,
  0 RELATIVE addends.
- Value leaf 0x5dd3570: exactly 10 direct calls (the walk's site
  0x5f90fa7 plus 0x5dd1694, 0x5eec2d2, 0x5eec342, 0x5ef06ca,
  0x5ef7376, 0x5f70b12, 0x5f7f67b, 0x5f8ee20, 0x5f8ee8b), 0 tail
  jumps, 0 qword hits, 0 RELATIVE addends. The leaf is shared; this
  item claims only the walk's call site.

## Objections / limits, stated openly

- The walk has no direct callers file-wide; it is reached only
  through the stub's tail jump. No vtable slot is claimed for it.
- The chain nodes and the F objects are not given type names: the
  packet pins only the offsets (+0x1028 chain, +0xb18/+0xb20
  range, entry +0x0 object, object +0x0 key, object +0x10 value
  field) and the arithmetic.
- This walk is a sibling of the distinct sum at 0x5f91010 (mapped
  by #2279), not a duplicate of it: different function, different
  layout (pointer ranges at +0xb18/+0xb20 versus groups at +0xad8),
  different key extraction (key = [[E]] versus [element + 0x08]),
  and a different summed source (a called leaf, [F + 0x10] + 62,
  versus a directly read field).

## Excerpt commands

```
objdump -d --start-address=0x5f90da0 --stop-address=0x5f90fe2 work/hl-node-115.bin
objdump -d --start-address=0x5dd3570 --stop-address=0x5dd357d work/hl-node-115.bin
```

Regenerate with `python3 export_excerpts.py` from anywhere; verify
with `python3 verify.py` from the repository root.
