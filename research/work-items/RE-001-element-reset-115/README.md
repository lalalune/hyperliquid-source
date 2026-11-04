# RE-001: map node #115 element reset 0x5f54ee0 with its five callers

## Bounded question

What does the element-reset function at 0x5f54ee0 do to an element
object, in what order, and which callers use it? This packet pins the
whole function end to end — not a lone-window fragment: the head
scalar clears, the three array disposals, the linked-list free with
its header reset, and the tail scalar stores, plus all five
census-confirmed callers that make the behavior observable end to
end. It closes the by-contract use of 0x5f54ee0 in
RE-001-element-prepare-115 (#2230), which called this function once
per element without reading its internals.

## Windows

- Element reset: 0x5f54ee0..0x5f551c2 (738 bytes), FDE at .eh_frame
  offset 0x35c7e8, length 0x38, CIE 0 (no LSDA). The window includes
  the three cold blocks at 0x5f55180, 0x5f55198 and 0x5f551b0, which
  jump back into the main body; the block at 0x5f551c2 belongs to
  the next function and is excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpt was produced

From the repository root:

```
objdump -d --start-address=0x5f54ee0 --stop-address=0x5f551c2 work/hl-node-115.bin
```

The excerpt file is that output verbatim, whole-function. The
instruction `endbr64` at the function entry is a genuine instruction
present in the target binary, not a placeholder: it appears in the
verbatim excerpt and is verified byte-for-byte against a fresh
objdump run and the raw binary by verify.py. Instruction-level
detail lives only in the verbatim excerpt; records.json carries
semantic records, not a per-instruction list.

## Semantics (literal)

The function takes one argument, an element object pointer (rdi),
and returns void. No stack canary is used (sub rsp,8 is call
alignment only) and no rip-relative reference appears in-window.

Head scalars, in order:

1. Store dword 0 at object + 0x00, qword 0 at object + 0x10, and
   byte 0 at the buffer pointed to by the qword at object + 0x08.
   The buffer pointer is loaded before the stores and is never
   null-checked; a null pointer would fault.
2. Store qword 0 at object + 0x30, and byte 0 at the buffer pointed
   to by the qword at object + 0x28, again with no null check.
3. Field + 0x20 is never written.

Block + 0x48..+ 0x7f: zeroed with two 16-byte stores (+ 0x48,
+ 0x68), two qword stores (+ 0x58, + 0x78) and one dword store
(+ 0x60). Bytes + 0x64..+ 0x67 are NOT written by any instruction.

First array (begin at object + 0x80, end at + 0x88, stride 0x28):
for each element, the string-dispose pattern — if the qword at
element + 0x08 differs from the element's own + 0x18 address, call
operator delete with (qword at + 0x08, qword at + 0x18 plus 1);
when equal, skip. Afterwards the end field at + 0x88 is set to the
begin pointer, so the array is empty but its backing store is kept.

Linked list (head at object + 0xa8): while the head is non-null,
call 0x5f53f50 with the qword at node + 0x18 (by contract only, see
Unknowns), then delete the node itself with size 0x30, advancing
via the qword at node + 0x10. Afterwards the header is reset:
qword at + 0xa8 is 0, qwords at + 0xb0 and + 0xb8 are the object's
own + 0xa0 address, and the qword at + 0xc0 is 0.

Second array (begin at object + 0xc8, end at + 0xd0, stride
0x130): for each element, four string-disposes in this exact
order — (+ 0x100, + 0x110), (+ 0xe0, + 0xf0), (+ 0x50, + 0x60),
(+ 0x30, + 0x40) — each with the same pattern (pointer compared
against the element's own second-field address; on mismatch,
delete with (pointer, second field plus 1)). Afterwards the end
field at + 0xd0 is set to the begin pointer.

Third array (begin at object + 0xe0, end at + 0xe8, stride 0x58):
for each element, two string-disposes in this order —
(+ 0x38, + 0x48), (+ 0x18, + 0x28) — with the same pattern.
Afterwards the end field at + 0xe8 is set to the begin pointer.

Tail scalars, in order:

1. If the qword at + 0xf8 differs from the qword at + 0x100,
   store the former into + 0x100 (same value when equal, so the
   net effect is + 0x100 := + 0xf8).
2. If the qword at + 0x110 differs from the qword at + 0x118,
   store the former into + 0x118 (net effect + 0x118 := + 0x110).
3. Store qword 0 at + 0x128, dword 0 at + 0x130, word 0 at
   + 0x134, qword 0 at + 0x140, and byte 0 at the buffer pointed
   to by the qword at + 0x138 (no null check).
4. Store byte 0 at + 0x158, dword 0 at + 0x15c, qword 0 at
   + 0x168, and byte 0 at the buffer pointed to by the qword at
   + 0x160 (no null check).

Callers (all real e8 calls, confirmed by the whole-file census;
caller internals were not read, so only call sites are claimed):

- 0x5f1337c inside element prepare 0x5f13310 (mapped by #2230:
  called once per element with element + 0xa98).
- 0x5f1442c, 0x5f160d5, 0x5f161fd, 0x5f5c1f6 in functions whose
  internals were not read.

## Unknowns (explicit)

- The internals of 0x5f53f50 are by contract only: the packet
  claims the call site, the argument (node + 0x18), the walk
  order, and the node delete (size 0x30). Its own body is a
  recursive + 0x18-chain walk with its own self-call; it is a
  separate function-map item, not modelled here.
- The operator-delete mechanism (PLT _ZdlPvm) is by contract:
  the packet claims the call sites, arguments and order, not the
  allocator's internals. A null buffer argument to delete is a
  no-op in the model, matching the allocator contract.
- The domain meanings of the fields (what the strings, arrays and
  list represent) are not claimed; only their literal offsets,
  order and values are recorded.

## What this does not claim

- No caller behavior beyond the call sites listed above.
- No behavior for the cold blocks beyond their jump-back role:
  each is the skip arm of one dispose (first array, second-array
  + 0x30 field, third-array + 0x18 field) and rejoins the loop
  check, which the model reproduces by disposing in order.
