# RE-001: map node #115 plain field getters 0x5eeb250/0x5eeb270/0x5eeb2f0/0x5eeb320/0x5eeb350/0x5eeb380

## Bounded question

In the getter neighbourhood below the mapped run at 0x5eeb490..0x5eeb741,
several getters read the same member at outer + 0x788 but delegate or
dispatch instead of reading a field directly. Which getters in the
0x5eeb250..0x5eeb380 span are plain, direct field projections of that
member, and exactly which field does each one return? This packet pins
the whole family end to end, not lone-window fragments: all six getters
whole, with every census-confirmed reference to each window.

## Windows

- Getter A: 0x5eeb250..0x5eeb26f (31 bytes), FDE at .eh_frame
  offset 0x356de8, length 0x10, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5eeb26e; the `int3` padding from 0x5eeb26f is excluded.
- Getter B: 0x5eeb270..0x5eeb28f (31 bytes), FDE at .eh_frame
  offset 0x356dfc, length 0x10, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5eeb28e; the `int3` padding from 0x5eeb28f is excluded.
- Getter C: 0x5eeb2f0..0x5eeb312 (34 bytes), FDE at .eh_frame
  offset 0x356e60, length 0x10, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5eeb311; the `int3` padding from 0x5eeb312 is excluded.
- Getter D: 0x5eeb320..0x5eeb342 (34 bytes), FDE at .eh_frame
  offset 0x356e74, length 0x10, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5eeb341; the `int3` padding from 0x5eeb342 is excluded.
- Getter E: 0x5eeb350..0x5eeb372 (34 bytes), FDE at .eh_frame
  offset 0x356e88, length 0x10, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5eeb371; the `int3` padding from 0x5eeb372 is excluded.
- Getter F: 0x5eeb380..0x5eeb39b (27 bytes), FDE at .eh_frame
  offset 0x356e9c, length 0x10, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5eeb39a; the `int3` padding from 0x5eeb39b is excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5eeb250 --stop-address=0x5eeb26f work/hl-node-115.bin
objdump -d --start-address=0x5eeb270 --stop-address=0x5eeb28f work/hl-node-115.bin
objdump -d --start-address=0x5eeb2f0 --stop-address=0x5eeb312 work/hl-node-115.bin
objdump -d --start-address=0x5eeb320 --stop-address=0x5eeb342 work/hl-node-115.bin
objdump -d --start-address=0x5eeb350 --stop-address=0x5eeb372 work/hl-node-115.bin
objdump -d --start-address=0x5eeb380 --stop-address=0x5eeb39b work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. All six
windows start with `endbr64`; every mnemonic in the excerpts is genuine
objdump output from the target binary, not a placeholder, and verify.py
checks sampled instructions byte-for-byte against a fresh objdump run
and the raw binary. Instruction-level detail lives only in the verbatim
excerpts; records.json carries semantic records, not a per-instruction
list.

## Semantics (literal)

All six getters take (outer, out) in (rdi, rsi), return 1
unconditionally, and have no null check anywhere.

### Getter A 0x5eeb250

member = [outer + 0x788]; sub = [member + 0x30];
*out = sign_extend32([sub + 0xb30]) via `movslq`; return 1. The only
32-bit field in the family: a negative stored value sign-extends, so
*out is negative, unlike the 64-bit fields below.

### Getter B 0x5eeb270

member = [outer + 0x788]; sub = [member + 0x30];
*out = [sub + 0x1008] (64-bit); return 1. Same sub-object as getter A,
a different field of it.

### Getter C 0x5eeb2f0

member = [outer + 0x788]; sub = [member + 0x8e8];
*out = [sub + 0xcd0] (64-bit); return 1.

### Getter D 0x5eeb320

member = [outer + 0x788]; sub = [member + 0x8e8];
*out = [sub + 0xa70] (64-bit); return 1. Same sub-object as getter C,
a different field of it.

### Getter E 0x5eeb350

member = [outer + 0x788]; sub = [member + 0x8e8];
*out = [sub + 0xa78] (64-bit); return 1. Same sub-object as getters C
and D; note +0xa78 sits 8 bytes past +0xa70, so D and E read adjacent
qwords of the same sub-object.

### Getter F 0x5eeb380

member = [outer + 0x788]; *out = [member + 0x928] (64-bit); return 1.
No second sub-object: the only getter in the family that reads the
member itself directly.

### The family structure

Two getters share the +0x30 sub-object (A's signed 32-bit field at
+0xb30, B's 64-bit field at +0x1008); three share the +0x8e8
sub-object (C at +0xcd0, D at +0xa70, E at +0xa78); one reads the
member directly (F at +0x928). Together they are the plain
(non-delegating, non-virtual) projections of the outer + 0x788
member in this span.

## Census (summary; full scan in census.py output)

- All six getters: 0 direct calls, 0 tail jumps, 0 qword hits in
  .text, 0 whole-file qword hits, 0 RELATIVE addends
  (virtual-getter shape, as in #2228/#2229/#2263/#2264/#2265/
  #2268/#2279/#2293/#2295). They are reached through vtable slots,
  not by direct calls.

## Boundaries, stated openly

- The neighbouring getter at 0x5eeb3a0 calls stub 0x5d8c9c0, which
  tail-jumps to the large function at 0x5f90da0; it is a delegating
  getter, excluded by the plain-field selection criterion, and
  nothing is claimed about it here.
- The getter at 0x5eeb220 calls *0x478(%rax) where rax = [rdx], a
  virtual dispatch; it is likewise excluded by the criterion.
- The struct identities of the member and its +0x30 / +0x8e8
  sub-objects are not named: the packet pins only the field
  offsets and the widths (32-bit signed for A, 64-bit for the rest).
