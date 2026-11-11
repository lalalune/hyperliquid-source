# RE-001: object teardown routine 0x5d50170 (node #115)

## Bounded question

What does the routine at `0x5d50170` destroy for an object, in what
order, and where is that routine used?

## Answer (established semantics)

The routine `0x5d50170` is a member teardown, not a destructor of the
object itself: it takes an object pointer in `rdi`, frees the object's
heap members in a fixed order, returns nothing, and never frees the
object pointer or reads a vtable slot. It is a complete behaviour end
to end, not a lone-window fragment: the whole 645-byte routine is
pinned (FDE `0x5d50170..0x5d503f5`), its two chain walks, its twelve
single-string disposals and its 36 direct call sites plus one tail
jump across 28 caller FDEs are all pinned. The disassembly excerpt in
this packet is verbatim objdump output: opcodes such as `endbr64`
are genuine instructions present in the target binary, not
placeholders.

The packet was produced with:

```
objdump -d --start-address=0x5d50170 --stop-address=0x5d503f5 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
readelf -r work/hl-node-115.bin
```

The routine pushes only `r12`, `rbp` and `rbx`, and performs no stack
canary check. Every free goes through the sized-delete PLT at
`0x63f0d80` (`_ZdlPvm`).

## Shared string rule

A string at offset `S` holds its data pointer at `S+0x00` and its
capacity at `S+0x10`. When the data pointer equals the address
`S+0x10`, the string is short-form and nothing is freed; otherwise
the sized delete frees `(data pointer, capacity + 1)`.

## Phases, in routine order

1. The chain at object `+0x288`. While the current node is non-null,
   in order: call the internal callee `0x5d4cfd0` with the value at
   `node+0x18` (call shape only); dispose the string at `node+0x40`
   (short-form address `node+0x50`); dispose the string at `node+0x20`
   (short-form address `node+0x30`); free the node itself with size
   `0x60`. The successor is read from `node+0x10` before the node is
   freed, and the walk ends at a null successor.
2. The chain at object `+0x258`, with exactly the same four steps
   per node.
3. Twelve single strings at object offsets, in descending order:
   `+0x228`, `+0x208`, `+0x1e8`, `+0x1c8`, `+0x1a8`, `+0x188`,
   `+0x168`, `+0x148`, `+0x128`, `+0x108`, `+0xe8`, `+0xc8`, each
   under the shared string rule with short-form address `offset +
   0x10`.

## Exits

The final string (`+0xc8`) decides the exit: short-form ends in a
plain return at `0x5d503f4`; heap-form ends in a tail jump to the
sized-delete PLT from `0x5d503eb`, after popping the saved
registers.

## Consumers

Executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's `census.py` and re-run
inside `verify.py`: exactly 36 direct calls plus 1 tail jump across
28 caller FDEs (see `callers.tsv`); 0 stored qwords, 0 RELATIVE
relocations — reached only by code, never by data. The tail-jump
caller is the 13-byte stub at `0x5dfbcd0`, which adds `0x10` to its
own argument before jumping, so the routine receives an object
pointer `0x10` past the caller's argument.

## Unknowns (kept separate from findings)

- What the callee at `0x5d4cfd0` computes for the value at
  `node+0x18`; pinned by call shape only.
- The source-level names of the object, the chain nodes and the
  string fields.
- Whether either chain can be cyclic in a well-formed object; the
  binary keeps no visited set, so a cyclic chain would loop forever
  in the binary as in the model.
