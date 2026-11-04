# RE-001: map node #115 default-gated predicate getter 0x5eeb7a0 with its default implementation 0x5d89610

## Bounded question

Next to the mapped getter run at 0x5eeb490..0x5eeb741, the binary
holds one more getter that reads the same member at outer + 0x788
but dispatches differently: what does getter 0x5eeb7a0 return, and
how does its default gate work? This packet pins the whole behavior
end to end, not lone-window fragments: the getter whole, its whole
7-byte default implementation, the .got gate slot the getter
compares against, and every census-confirmed reference to each
window.

## Windows

- Getter: 0x5eeb7a0..0x5eeb7ef (79 bytes), FDE at .eh_frame offset
  0x357124, length 0x1c, CIE 0 (no LSDA). Ends at the `ret` at
  0x5eeb7ee; the `int3` padding from 0x5eeb7ef is excluded. The
  `nopw` at 0x5eeb7d2 between the two arms is inside the function
  and is part of the window.
- Default implementation: 0x5d89610..0x5d89617 (7 bytes), FDE at
  .eh_frame offset 0x34b3e8, length 0x10, CIE 0 (no LSDA). Ends at
  the `ret` at 0x5d89616; the `int3` padding from 0x5d89617 is
  excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5eeb7a0 --stop-address=0x5eeb7ef work/hl-node-115.bin
objdump -d --start-address=0x5d89610 --stop-address=0x5d89617 work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. Both
windows start with `endbr64`; every mnemonic in the excerpts
is genuine objdump output from the target binary, not a placeholder,
and verify.py checks sampled instructions byte-for-byte against a
fresh objdump run and the raw binary. Instruction-level detail
lives only in the verbatim excerpts; records.json carries semantic
records, not a per-instruction list.

## Semantics (literal)

### Getter 0x5eeb7a0

Arguments (outer, out) in (rdi, rsi). The getter loads the member
at [outer + 0x788], loads the virtual object at [member + 0x950],
loads the virtual slot at [vtable + 0x28], and compares it against
the .got slot at 0x64ed2d0:

- Default arm (slot equal): *out = 0 (eax was zeroed before the
  compare), return 1. The default implementation is NOT called on
  this arm.
- Override arm (slot different): rsi = [member + 0x30] + 0x40,
  call the slot with (obj, rsi), then *out = movzbl(al) and
  return 1.

Both arms return 1 unconditionally. No null check anywhere.

### Default implementation 0x5d89610

`xor %eax,%eax; ret` -- returns 0 unconditionally, ignoring both
arguments. That is why the getter's default arm can store 0 without
calling it: calling it would produce the same 0.

### The gate slot

The static file holds 0 at 0x64ed2d0, but the slot carries a
R_X86_64_RELATIVE relocation with addend 0x5d89610, so at runtime
the comparison is against the default implementation's address.
A full objdump of .text grepped for `# 64ed2d0` returns exactly
one site -- this getter at 0x5eeb7bf -- so the getter is the sole
consumer of the default gate. A second RELATIVE slot at 0x64c9b50
also carries addend 0x5d89610; its consumers are not traced here
and are not claimed.

### Masking quirk

The override arm masks with `movzbl`, so only the low byte of the
override's return survives: an override returning 0x1ab yields
0xab, and one returning 0x100 yields 0. The raw override return
is never stored.

## What is left by contract

- The override body behind the +0x28 slot varies by class. Only
  its calling convention (obj, [member + 0x30] + 0x40) and the
  low-byte masking are pinned.
- The getter has no direct callers, tail jumps, qword hits or
  RELATIVE addends file-wide (virtual-getter shape, as in
  #2228/#2229/#2263/#2264/#2265/#2268/#2279), so its callers reach
  it through a vtable slot this packet does not identify.
- The consumers of the second default-carrying slot at 0x64c9b50
  are not traced in this packet.
