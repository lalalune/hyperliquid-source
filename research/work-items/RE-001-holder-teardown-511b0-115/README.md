# RE-001: holder teardown routine 0x5d511b0 (node #115)

## Bounded question

What does the routine at `0x5d511b0` do to the holder it takes in
`rdi`, and where is that routine used?

## Answer (established semantics)

The routine `0x5d511b0` takes a holder pointer in `rdi` and returns
nothing. It is a complete behaviour end to end, not a lone-window
fragment: the whole 1022-byte routine is pinned (FDE
`0x5d511b0..0x5d515ae`), its four phases and its tail are all pinned,
and its 16 direct callers across 11 caller functions are censused.
It destroys a holder in this order: every record in the records
array, then two holder pointer lists, then a tail scalar.

### The shared list shape

Every pointer/item list in this routine follows one shape: an 8-slot
inline segment reached through a pointer field, a heap segment with
begin/end pointer fields, and an inline-count field. The loop runs
`heap_count + inline_count` times; element `i` comes from the inline
segment when `i <= 7` and from the heap segment at index `i - 8`
otherwise. The binary's element-selection threshold is the fixed
constant 8, so the model treats well-formed inputs as
`inline_count == 8`; that assumption is recorded explicitly, and the
tests use 8. The inline segment's pointer fields are not cleared by
this routine; only the count fields and heap-end fields listed below
are.

### Phase 1: records array

Records live in the array with begin field `H+0x130` and end field
`H+0x138`, stride `0x218`. The records array itself is not cleared.
Per record, in order:

1. **Notify.** Item count is `(heap_item_bytes / 0x30) +
   inline_count` where `inline_count` is the field at `record+0x68`
   (the byte count is divided by three 16-byte units, which is the
   `0xaaaaaaaaaaaaaaab` multiply in the binary). Items are 0x30
   bytes, inline segment pointer at `record+0x1f0`, heap begin at
   `record+0x1f8`, heap end at `record+0x200`, target pointer at
   `item+0x28`. For each item, the target's pair list (begin at
   `target+0x140`, end at `target+0x148`, pair stride 0x10, object
   pointer at `pair+0x00`) is walked; for each object the slot at
   `object_vtable+0x100` is read. When the slot equals `0x5d48450`
   it is skipped; otherwise the slot is called with
   `(object, item)`. Note that `0x5d48450` is a genuine instruction
   sequence in the target binary — `endbr64` followed by `ret` —
   not a placeholder, so skipping it changes nothing observable.
2. **Pop inline items.** The `record+0x68` count is decremented to
   zero, taking the item at the decremented index each time, so
   items are visited in reverse index order. When an item's pointer
   at `+0x00` differs from the item's own address plus `0x10`, the
   pointer is sized-deleted with size `item_field_at_0x10 + 1`;
   when it equals that address, no delete happens.
3. **Dispose heap items.** The heap range `record+0x1f8` to
   `record+0x200` is walked forward with the same delete rule as
   step 2. Afterwards `record+0x200` is set to `record+0x1f8`.
4. **Dispose the record's pointer array.** Count field at
   `record+0x00`, inline segment pointer at `record+0x48`, heap
   begin at `record+0x50`, heap end at `record+0x58`. Each non-null
   pointer is passed to `0x5d8d820` and then sized-deleted with
   size `0x290`; null pointers are skipped. Afterwards
   `record+0x00` is set to 0 when it was non-zero, and
   `record+0x58` is set to `record+0x50` when they differed.

### Phase 2: holder pointer list

Count field `H+0xc8`, inline segment pointer `H+0x110`, heap begin
`H+0x118`, heap end `H+0x120`. Each non-null pointer is passed to
`0x5f10d40` and then sized-deleted with size `0xd20`; null pointers
are skipped. Afterwards `H+0xc8` is set to 0 when it was non-zero,
and `H+0x120` is set to `H+0x118` when they differed.

### Phase 3: holder pointer list

Count field `H+0x148`, inline segment pointer `H+0x190`, heap begin
`H+0x198`, heap end `H+0x1a0`. Each non-null pointer is passed to
`0x5f04800` and then sized-deleted with size `0x58`; null pointers
are skipped. Afterwards `H+0x148` is set to 0 when it was non-zero
at phase entry, and `H+0x1a0` is set to `H+0x198` when they
differed.

### Tail

The field `H+0x1f0` is read and then set to 0. When the read value
was non-null it is passed to `0x5f3c850` and then sized-deleted
with size `0x10` as the routine's final action (a tail call to the
sized delete at `0x5d5159a`); when null the routine returns
directly at `0x5d515ad`.

### Returns and failure edges

The routine returns nothing. There is no stack canary and no
in-routine landing-pad fragment; exceptions from the virtual calls
or the destructors unwind through the FDE. The sized-delete tail
call is the only exit besides the direct return.

### Inferred readings (separate from the observations above)

- The `0x5d8d820` / `0x5f10d40` / `0x5f04800` / `0x5f3c850`
  calls read as per-element destructors, from their call shape and
  the sized delete that follows each; their internals are not
  pinned here.
- The virtual slot at `+0x100` reads as a per-object teardown /
  detach handler; only the skip rule for the `0x5d48450` stub is
  pinned, not any handler's internals.
- The holder's and the records' source-level names and owning
  classes are not pinned. The pair list's second qword is not
  pinned. The inline segments' allocation ownership is not pinned.

### Consumers

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): exactly 16 direct calls + 0 tail jumps across 11 caller
FDEs (see callers.tsv); 0 stored qwords, 0 RELATIVE relocations —
reached only by code, never by data.

### Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (from `provenance/artifacts.json`, verified against the local
  `work/hl-node-115.bin`).
- `main.txt`: whole-function verbatim objdump excerpt, produced by
  `objdump -d --start-address=0x5d511b0
  --stop-address=0x5d515ae work/hl-node-115.bin` with the header
  normalized to the bare binary name (the only modification).
- `records.json`: semantic records only; instruction-level detail
  lives only in the verbatim excerpt.
- `verify.py` + `export_excerpts.py` + `census.py` are committed in
  this packet; `verify.py` regenerates the excerpts byte-for-byte,
  checks every excerpt line against the raw binary, re-runs the
  census, and runs the model tests.
