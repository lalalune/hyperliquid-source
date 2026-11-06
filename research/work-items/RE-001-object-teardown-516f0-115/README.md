# RE-001: object teardown routine 0x5d516f0 (node #115)

## Bounded question

What does the routine at `0x5d516f0` destroy for an object, in what
order, and where is that routine used?

## Answer (established semantics)

The routine `0x5d516f0` is a member teardown, not a destructor of the
object itself: it takes an object pointer in `rdi`, frees the object's
heap members in a fixed order, returns nothing, and never frees the
object pointer or reads a vtable slot. It is a complete behaviour end
to end, not a lone-window fragment: the whole 725-byte routine is
pinned (FDE `0x5d516f0..0x5d519c5`), its ten phases, its three loops,
its linked-list walk and its 87 direct call sites across 65 caller
FDEs are all pinned. The disassembly excerpts in this packet are
verbatim objdump output: opcodes such as `endbr64` are genuine
instructions present in the target binary, not placeholders.

The packet was produced with:

```
objdump -d --start-address=0x5d516f0 --stop-address=0x5d519c5 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
readelf -r work/hl-node-115.bin
```

### Shared rules

A string at offset `S` holds its data pointer at `S+0x00` and its
capacity at `S+0x10`. When the data pointer equals the address
`S+0x10`, the string is short-form and nothing is freed; otherwise
the sized delete frees `(data pointer, capacity + 1)`.

A buffer at offset `B` holds its begin pointer at `B+0x00` and its
end pointer at `B+0x08`. When begin is null nothing is freed;
otherwise the sized delete frees `(begin, end - begin)`. The
capacity slot of a buffer is never read by this routine.

Every free in this routine goes through the sized-delete PLT at
`0x63f0d80` (`_ZdlPvm`), with `(pointer, size)` as above, except
the final heap-form string, which tail-jumps to the same PLT.

### Phases, in routine order

1. The string at `+0x160` (short-form address `+0x170`).
2. The string at `+0x138` (short-form address `+0x148`).
3. The buffer at `+0x110` (end at `+0x120`).
4. The buffer at `+0xf8` (end at `+0x108`).
5. The element loop at `+0xe0..+0xe8`, stride `0x58`: per element
   the string at `+0x38`, then the string at `+0x18`; then the
   loop buffer itself (`+0xe0`, end `+0xf0`).
6. The record loop at `+0xc8..+0xd0`, stride `0x130`: per record
   the strings at `+0x100`, `+0xe0`, `+0x50` and `+0x30`, in that
   order; then the loop buffer itself (`+0xc8`, end `+0xd8`).
7. The linked list at `+0xa8`: per node, in order, call the
   internal callee `0x5d4c8d0` with the value at `node+0x18`
   (call shape only), read the successor from `node+0x10`, and
   free the node with size `0x30`; the walk ends at a null
   successor.
8. The element loop at `+0x80..+0x88`, stride `0x28`: per element
   the string at `+0x08`; then the loop buffer itself (`+0x80`,
   end `+0x90`).
9. The string at `+0x28` (short-form address `+0x38`).
10. The string at `+0x08` (short-form address `+0x18`): short form
    returns directly; heap form pops the saved registers and
    tail-jumps to the sized-delete PLT.

The routine pushes only `r12`, `rbp` and `rbx`; it performs no
stack-canary check. Its two exits are the plain return when the
final string is short-form and the tail jump when it is heap-form.

### Consumers

Exactly 87 direct calls and 0 tail jumps across 65 caller FDEs (see
`callers.tsv`); 0 stored qwords and 0 RELATIVE relocations, so the
routine is reached only by code, never by data. Every call site was
confirmed to lie inside its caller FDE.

### Unknowns

- The source-level type name of the object and of its members.
- The semantics of the internal callee `0x5d4c8d0` beyond its call
  shape (its FDE is `0x5d4c8d0..0x5d4ca99`).
- Why the routine reads no vtable slot and frees no object pointer
  itself.
- The contents of the object fields this routine never reads
  (`+0x00..+0x07`, `+0x10..+0x27`, `+0x40..+0x7f`, `+0x98..+0xa7`,
  `+0xb0..+0xc7`, `+0x128..+0x137`, `+0x178` and above).
- Whether any caller relies on the routine's exact phase order
  rather than only on its final freed state.

### Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make verify`, `make test` and `make catalogue-check` were not run
in a tooled environment and no hosted CI result is claimed. The
packet's own checker (`verify.py`) and the model tests were run
directly against the materialized node #115 binary, whose SHA-256
matches `provenance/artifacts.json`.
