# RE-001: map node #115 rdx-arg getters 0x5eeb6c0/0x5eeb6e0/0x5eeb700/0x5eeb720 with their leaves 0x5e4b550/0x5e4b560/0x5fc9610

## Bounded question

Immediately after the sibling getters mapped by #2228/#2229 and the
composite getter 0x5eeb570 (which reuses #2215's field sums), the
binary holds a run of small getters that all read their value from
the third argument (rdx) instead of the outer object. What does each
of the four getters in 0x5eeb6c0..0x5eeb741 return, through which
leaf, and who else calls those leaves? This packet pins the whole
family end to end, not lone-window fragments: all four getters whole
plus all three leaves whole, with every census-confirmed caller of
each leaf.

## Windows

- Getter C: 0x5eeb6c0..0x5eeb6da (26 bytes), FDE at .eh_frame offset
  0x357094, length 0x18, CIE 0 (no LSDA). Ends at the `ret` at
  0x5eeb6d9; the `int3` padding from 0x5eeb6da is excluded.
- Getter D: 0x5eeb6e0..0x5eeb6fa (26 bytes), FDE at .eh_frame offset
  0x3570b0, length 0x18, CIE 0 (no LSDA). Ends at the `ret` at
  0x5eeb6f9; padding from 0x5eeb6fa excluded.
- Getter E: 0x5eeb700..0x5eeb720 (32 bytes), FDE at .eh_frame offset
  0x3570cc, length 0x10, CIE 0 (no LSDA). Ends at the `ret` at
  0x5eeb71f; the next getter at 0x5eeb720 is a separate window.
- Getter F: 0x5eeb720..0x5eeb741 (33 bytes), FDE at .eh_frame offset
  0x3570e0, length 0x18, CIE 0 (no LSDA). Ends at the `ret` at
  0x5eeb740; padding from 0x5eeb741 excluded.
- Leaf 0x5e4b550: 0x5e4b550..0x5e4b560 (16 bytes), FDE at .eh_frame
  offset 0x352820, length 0x10, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5e4b55f; the next function at 0x5e4b560 is a separate window.
- Leaf 0x5e4b560: 0x5e4b560..0x5e4b599 (57 bytes), FDE at .eh_frame
  offset 0x352834, length 0x1c, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5e4b598; padding from 0x5e4b599 excluded.
- Leaf 0x5fc9610: 0x5fc9610..0x5fc961c (12 bytes), FDE at .eh_frame
  offset 0x3614a8, length 0x10, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5fc961b; padding from 0x5fc961c excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5eeb6c0 --stop-address=0x5eeb6da work/hl-node-115.bin
objdump -d --start-address=0x5eeb6e0 --stop-address=0x5eeb6fa work/hl-node-115.bin
objdump -d --start-address=0x5eeb700 --stop-address=0x5eeb720 work/hl-node-115.bin
objdump -d --start-address=0x5eeb720 --stop-address=0x5eeb741 work/hl-node-115.bin
objdump -d --start-address=0x5e4b550 --stop-address=0x5e4b560 work/hl-node-115.bin
objdump -d --start-address=0x5e4b560 --stop-address=0x5e4b599 work/hl-node-115.bin
objdump -d --start-address=0x5fc9610 --stop-address=0x5fc961c work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. All seven
windows start with `endbr64`; every mnemonic in the excerpts is
genuine objdump output from the target binary, not a placeholder, and
verify.py checks sampled instructions byte-for-byte against a fresh
objdump run and the raw binary. Instruction-level detail lives only in
the verbatim excerpts; records.json carries semantic records, not a
per-instruction list.

## Semantics (literal)

All four getters share one shape: arguments (outer, out, obj) in
(rdi, rsi, rdx); the outer object in rdi is IGNORED by every one of
them (never read); each stores one qword to *out and returns 1
unconditionally. The value differs per getter:

### Getter C 0x5eeb6c0 — via leaf 0x5e4b550

```
*out = leaf550(obj)   # rdx passed unchanged as the leaf's argument
return 1
```

### Getter D 0x5eeb6e0 — via leaf 0x5e4b560

```
*out = leaf560(obj)   # rdx passed unchanged as the leaf's argument
return 1
```

### Getter E 0x5eeb700 — inline, no callee

```
count = signed 32-bit [obj + 0x1104]
*out = [obj + 0x1128] if count > 0 else 0
return 1
```

### Getter F 0x5eeb720 — via leaf 0x5fc9610, masked

```
*out = movzbl(leaf610(obj + 0x1100))   # 1 iff signed 32-bit [obj + 0x1100] > 0, else 0
return 1
```

### Leaf 0x5e4b550

Argument: rdi = obj. Returns a qword. No null check anywhere: a null
obj or a null slot pointer would fault.

```
return [[obj + 0x68] + 0xe0]
```

### Leaf 0x5e4b560

Argument: rdi = obj. Returns a qword.

```
refresh(obj + 0x700)     # 0x60d5390, by contract; its return is ignored
head = obj + 0x1260
first = [head]
if first == head:
    return 0xffffffffffffffff   # signed -1, empty list
return [first + 0x10]
```

### Leaf 0x5fc9610 — read literally, including its quirk

Argument: rdi = pointer. It loads the signed 32-bit value at [arg],
tests it, and sets only the low byte of eax with `setg`:

```
x = signed 32-bit [arg]
raw = (x & 0xffffff00) | (1 if x > 0 else 0)   # upper 24 bits of eax keep x's bits
return raw
```

The leaf does NOT zero the upper bits: for a positive x the raw
return is x with its low byte forced to 1, not a clean 1. Only the
masking caller recovers a clean 0/1: getter F applies `movzbl` to
the low byte, so its stored value is exactly 1 iff x > 0, else 0.
Other callers of this leaf (listed below, internals not read) may
observe the unmasked raw value; this packet does not claim they mask
it.

## Consumers (census-confirmed)

The four getters themselves have no direct calls, tail jumps, qword
hits or RELATIVE addends anywhere in the file — the same virtual-
getter shape as the neighbouring getters mapped by #2228/#2229, so
they are reached through a table, not by direct call. The leaves'
direct callers (all real e8 calls; non-getter callers listed by site
and containing function only, internals not read):

- Leaf 0x5e4b550 (4 calls): 0x5dd1aff in 0x5dd0dd0..0x5dd3521,
  0x5e4ef75 in 0x5e4ee50..0x5e505b2, 0x5e697f0 in
  0x5e68fd0..0x5e6b82a, and 0x5eeb6cb in getter C.
- Leaf 0x5e4b560 (2 calls): 0x5e4eec1 in 0x5e4ee50..0x5e505b2 (the
  same function that also calls 0x5e4b550 at 0x5e4ef75), and
  0x5eeb6eb in getter D.
- Leaf 0x5fc9610 (12 calls): 0x5d8bf39 in 0x5d8bea0..0x5d8c97a,
  0x5dd5f7b in 0x5dd5f60..0x5dd5fc1, 0x5de0057 in
  0x5ddf430..0x5de0afe, 0x5de1baf in 0x5de1000..0x5de251d,
  0x5dfcec9 in 0x5dfcea0..0x5dfcfb6, 0x5dfdef0 in
  0x5dfdec0..0x5dfdf17, 0x5e872f5 and 0x5e8732b in
  0x5e87160..0x5e87935, 0x5e87aa1 in 0x5e87a70..0x5e87d5e,
  0x5e8e84d in 0x5e8e4a0..0x5e8ee70, 0x5ecc429 in
  0x5ecc400..0x5ecc45e, and 0x5eeb72f in getter F.

## Unknowns (stated, not filled in)

- Names/meanings of the outer object, the rdx object, and the fields
  at +0x68/+0xe0, +0x700/+0x1260/+0x10, and +0x1100/+0x1104/+0x1128.
- What the by-contract refresh 0x60d5390 does to obj + 0x700.
- Internals of the non-getter callers of the three leaves beyond
  their call sites.
- What the neighbouring getters 0x5eeb610/0x5eeb630/0x5eeb650/
  0x5eeb670/0x5eeb6a0 read (their callees were not mapped here).
