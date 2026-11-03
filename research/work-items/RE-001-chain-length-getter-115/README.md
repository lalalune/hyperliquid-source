# RE-001: map node #115 chain-length getter 0x5eeb610 with its stub and counter 0x5f70180

## Bounded question

Immediately before the group-sum getter mapped by #2264, the binary
holds a getter that reads a member at outer + 0x788 and reports a
chain length through it: what does getter 0x5eeb610 return, and how
does its counter 0x5f70180 count? This packet pins the whole
behavior end to end, not lone-window fragments: the getter whole,
its whole 13-byte forwarding stub, and the whole 44-byte counter,
with every census-confirmed caller of each window.

## Windows

- Getter: 0x5eeb610..0x5eeb62e (30 bytes), FDE at .eh_frame offset
  0x357008, length 0x18, CIE 0 (no LSDA). Ends at the `ret` at
  0x5eeb62d; the `int3` padding from 0x5eeb62e is excluded.
- Forwarding stub: 0x5d8c9a0..0x5d8c9ad (13 bytes), FDE at .eh_frame
  offset 0x34bbbc, length 0x10, CIE 0 (no LSDA). Ends at the tail
  jump at 0x5d8c9a8; the `int3` padding from 0x5d8c9ad is excluded.
- Chain-length counter: 0x5f70180..0x5f701ac (44 bytes), FDE at
  .eh_frame offset 0x35e2dc, length 0x10, CIE 0 (no LSDA). Ends at
  the `ret` at 0x5f701ab; the `int3` padding from 0x5f701ac is
  excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5eeb610 --stop-address=0x5eeb62e work/hl-node-115.bin
objdump -d --start-address=0x5d8c9a0 --stop-address=0x5d8c9ad work/hl-node-115.bin
objdump -d --start-address=0x5f70180 --stop-address=0x5f701ac work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. All
three windows start with `endbr64`; every mnemonic in the excerpts
is genuine objdump output from the target binary, not a placeholder,
and verify.py checks sampled instructions byte-for-byte against a
fresh objdump run and the raw binary. Instruction-level detail
lives only in the verbatim excerpts; records.json carries semantic
records, not a per-instruction list.

## Semantics (literal)

### Getter 0x5eeb610

Arguments (outer, out) in (rdi, rsi). The getter loads the member
at [outer + 0x788], saves out in rbx, and calls the stub with that
member; it stores the stub's return to *out and returns 1
unconditionally. There is no null check anywhere in this behavior:
a null outer, a null member, or a null chain head faults in the
binary (the model raises instead; see tools/chain_length_getter_115.py).

```
*out = chain_length([[outer + 0x788] + 0x28])
return 1
```

### Forwarding stub 0x5d8c9a0

Loads the chain head at [member + 0x28] and tail-jumps to the
counter, so the counter's return value passes through unchanged.
The stub has no `ret` of its own and no other behavior.

### Chain-length counter 0x5f70180

Argument head in rdi. The counter reads the next pointer at
[head + 0x1028] and walks the chain through the same +0x1028 field
until the walk returns to head, counting the steps:

```
count = 0
node = [head + 0x1028]
while node != head:
    node = [node + 0x1028]
    count += 1
return count
```

So the return is the number of non-head nodes in the cycle: 0 when
the head points at itself (an empty chain), 1 for a two-node cycle,
and so on. The binary has no guard for a chain that never returns
to head: such a chain loops forever (or faults on a null link).
The model adds a visited-set guard that raises ValueError instead;
that guard is model-only and is stated as such in the model.

## Census (whole-file scan; see census.py)

- Getter 0x5eeb610: no direct calls, no tail jumps, no qword hits,
  no RELATIVE addends anywhere in the file (virtual-getter shape,
  as in #2228/#2229/#2263/#2264).
- Stub 0x5d8c9a0: exactly 1 direct call, at 0x5eeb61f inside the
  getter; nothing else.
- Counter 0x5f70180: exactly 1 tail jump, at 0x5d8c9a8 inside the
  stub; no direct calls, no qword hits, no RELATIVE addends.

## What is NOT claimed

- The contents of the objects at outer + 0x788, member + 0x28, or
  node + 0x1028 beyond the fields read above are not modelled.
- The neighbouring getters 0x5eeb630 and 0x5eeb650, which share
  this getter's shape but delegate to different, larger targets
  (0x5f91010 and 0x5f6acb0), are NOT covered here; they need their
  own scope check.
- The counter's callers beyond the stub: there are none file-wide.

## Environment honesty

This VM has no cargo/rustc, no git-lfs, and no Ghidra/Java.
`make doctor` fails on missing providers (pre-existing), and
`make verify` / `make catalogue-check` fail on the LFS-pointer
artifact here (pre-existing); this packet binds instead to the
materialized work/hl-node-115.bin whose digest matches
provenance/artifacts.json. pytest is not installed, so the
pytest-style test file runs under plain python3 via its `__main__`
runner.
