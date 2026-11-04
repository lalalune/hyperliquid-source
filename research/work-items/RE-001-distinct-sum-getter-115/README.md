# RE-001: map node #115 distinct-sum getter 0x5eeb630 with its stub and distinct sum 0x5f91010

## Bounded question

Immediately before the aggregate-sum getter mapped by #2268, the binary
holds a getter that reads the same member at outer + 0x788 and reports
a sum through it: what does getter 0x5eeb630 return, and how does its
distinct sum 0x5f91010 differ from the plain aggregate sum? This packet
pins the whole behavior end to end, not lone-window fragments: the
getter whole, its whole 13-byte forwarding stub, and the whole
581-byte distinct sum, with every census-confirmed caller of each
window.

## Windows

- Getter: 0x5eeb630..0x5eeb64e (30 bytes), FDE at .eh_frame offset
  0x357024, length 0x18, CIE 0 (no LSDA). Ends at the `ret` at
  0x5eeb64d; the `int3` padding from 0x5eeb64e is excluded.
- Forwarding stub: 0x5d8c9b0..0x5d8c9bd (13 bytes), FDE at .eh_frame
  offset 0x34bbd0, length 0x10, CIE 0 (no LSDA). Ends at the tail
  jump at 0x5d8c9b8; the `int3` padding from 0x5d8c9bd is excluded.
- Distinct sum: 0x5f91010..0x5f91253 (581 bytes), FDE at .eh_frame
  offset 0x74a520, length 0x50, CIE 0x730230 (with LSDA). Ends at the
  `ret` at 0x5f911ad; the hash-lookup block at 0x5f911b0..0x5f91242
  and the landing pad at 0x5f91247 are inside the FDE range and are
  part of the window. The `int3` padding from 0x5f91253 is excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5eeb630 --stop-address=0x5eeb64e work/hl-node-115.bin
objdump -d --start-address=0x5d8c9b0 --stop-address=0x5d8c9bd work/hl-node-115.bin
objdump -d --start-address=0x5f91010 --stop-address=0x5f91253 work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. All
three windows start with `endbr64`; every mnemonic in the excerpts
is genuine objdump output from the target binary, not a placeholder,
and verify.py checks sampled instructions byte-for-byte against a
fresh objdump run and the raw binary. Instruction-level detail
lives only in the verbatim excerpts; records.json carries semantic
records, not a per-instruction list.

## Semantics (literal)

### Getter 0x5eeb630

Arguments (outer, out) in (rdi, rsi). The getter loads the member
at [outer + 0x788], calls the stub with it, stores the stub's return
to *out, and returns 1 unconditionally. No null check anywhere.

### Forwarding stub 0x5d8c9b0

Loads the distinct-sum head object at [member + 0x28] and
tail-jumps to 0x5f91010 with it; the distinct sum's return passes
through unchanged. The stub has no `ret` of its own.

### Distinct sum 0x5f91010

Argument: the head object in rdi. The function builds a local
seen-key set on the stack, then walks the +0x1028 cycle:

- node = [head + 0x1028]. If node == head at once (a self-loop),
  the set is destroyed and the function returns 0.
- For each cycle node, in walk order, while node != head:
  count = signed 32-bit [node + 0x50]. If count <= 0, that node
  contributes nothing and the walk moves on.
  Otherwise, for each of the first count 24-byte groups at
  [node + 0xad8]: begin = [group + 0], end = [group + 8]
  (the third qword of each group entry is never read). For every
  pointer p in [begin, end): element = *p, key = [element + 0x08].
  The function tests the key against the local set -- a linear
  scan of stored entries when the set's +0x18 field is 0, and a
  bucketed lookup (bucket = key % bucket count, then a chain walk
  comparing the stored +8 field) otherwise. On a match the element
  is a duplicate and contributes nothing. Otherwise the function
  inserts it via the direct call to 0x5f90bb0 with (set,
  element + 0x08) and then adds [element + 0x10] to the running
  total, 64-bit wrapping.
  After the groups, node = [node + 0x1028] and the walk repeats.
- Epilogue: the local set is destroyed (its node list is freed
  with operator delete at 0x10 bytes per node, its bucket array is
  zeroed, and the bucket array itself is deleted unless it is the
  inline single bucket on the stack), the stack canary is checked
  (mismatch calls __stack_chk_fail), and the total is returned.
- The head object's own groups are never summed: only the cycle
  nodes after it are visited. A chain that never returns to its
  head loops forever in the binary; the model takes the cycle as a
  finished list and does not express that case.

## What is by contract, not read

- The insert callee 0x5f90bb0 (direct call site 0x5f91217) was not
  read: the set-node layout and the insert's bucket mechanics are
  left by contract. What is pinned from this window is the
  observable contract: insert takes (set, element + 0x08), and the
  membership test before it compares the candidate key against a
  stored +8 field and skips on equality, in both lookup paths.
- The landing pad at 0x5f91247 (endbr64, then a jump to 0x5f90fe2,
  outside this window) was not read beyond its bytes in the
  excerpt; its entry edge and the code at 0x5f90fe2 are not
  modelled.
- The stub's sole caller is the getter in this packet (call site
  0x5eeb63f); the getter has no callers file-wide, so there is no
  external caller whose argument setup could be claimed.
- Neighbouring getter 0x5eeb6a0 and its target 0x5f6cb70 are not
  covered; they need their own scope check.
