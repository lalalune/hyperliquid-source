# RE-001: shared-copy routine 0x5d50400 (node #115)

## Bounded question

What does the routine at `0x5d50400` copy, what decides which record
it copies, and what does it increment after the copy — and where is
that routine used?

## Answer (established semantics)

The routine `0x5d50400` is a whole 98-byte leaf routine (FDE
`0x5d50400..0x5d50462`), not a lone-window fragment: it takes a
destination pointer in `rdi` and a source pointer in `rsi`, copies
exactly 16 bytes into the destination, and then, when the copied
record's second qword is non-null, increments the dword at that
target's `+0x08` slot by one. It saves no registers, reads no vtable
slot, makes no calls, and writes nothing else. The disassembly
excerpt in this packet is verbatim objdump output: opcodes such as
`endbr64` are genuine instructions present in the target binary, not
placeholders.

The packet was produced with:

```
objdump -d --start-address=0x5d50400 --stop-address=0x5d50462 work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
readelf -r work/hl-node-115.bin
```

## Copy-source selection

1. Read the selector pointer at source `+0x10`.
2. If the selector is null, or the byte at selector `+0x68` is zero,
   copy the 16 bytes at source `+0x00` into the destination.
3. If the selector is non-null and the byte at selector `+0x68` is
   nonzero, copy the 16 bytes at source `+0x20` into the destination
   instead. No other source bytes are read, and the source record is
   never written.

## Increment after the copy

Read the destination's second qword (destination `+0x08`) after the
copy:

- Null: return with nothing further.
- Non-null: load the pointer held at `0x64ed290`, read the flag byte
  it points to, and add 1 to the dword at target `+0x08` — a plain
  add when the flag byte is nonzero, a locked add when it is zero.
  Both forms add exactly one, modulo 2^32. The returns are at
  `0x5d50436` (plain add), `0x5d50445` (locked add, and the default
  null-target path) and `0x5d50461` (alternate null-target path).

## Consumers

Executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's `census.py` and re-run
inside `verify.py`: exactly 27 direct calls and 0 tail jumps across
14 caller FDEs (see `callers.tsv`); 0 stored qwords, 0 RELATIVE
relocations — reached only by code, never by data.

## Unknowns (kept separate from findings)

- The source-level names of the source record, the selector object
  and the incremented target, and what the selector's `+0x68` byte
  means at source level.
- What the flag byte reached through the pointer at `0x64ed290`
  means at source level; only its zero/nonzero effect on the add
  form is pinned.
- Whether the incremented target is a shared-ownership control
  block; the routine's observable behaviour is the copy plus the
  single dword increment, and that reading is an inference, not a
  pinned claim.
