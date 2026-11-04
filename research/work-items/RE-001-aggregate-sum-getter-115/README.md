# RE-001: map node #115 aggregate-sum getter 0x5eeb650 with its stub and aggregate 0x5f6acb0

## Bounded question

Immediately after the chain-length getter mapped by #2265, the binary
holds a getter that reads a member at outer + 0x788 and reports an
aggregate sum through it: what does getter 0x5eeb650 return, and how
does its aggregate 0x5f6acb0 sum? This packet pins the whole
behavior end to end, not lone-window fragments: the getter whole,
its whole 13-byte forwarding stub, and the whole 286-byte
aggregate, with every census-confirmed caller of each window.

## Windows

- Getter: 0x5eeb650..0x5eeb66e (30 bytes), FDE at .eh_frame offset
  0x357040, length 0x18, CIE 0 (no LSDA). Ends at the `ret` at
  0x5eeb66d; the `int3` padding from 0x5eeb66e is excluded.
- Forwarding stub: 0x5d8c9d0..0x5d8c9dd (13 bytes), FDE at .eh_frame
  offset 0x34bbf8, length 0x10, CIE 0 (no LSDA). Ends at the tail
  jump at 0x5d8c9d8; the `int3` padding from 0x5d8c9dd is excluded.
- Aggregate sum: 0x5f6acb0..0x5f6ad6e (286 bytes), FDE at .eh_frame
  offset 0x35dcd8, length 0x10, CIE 0 (no LSDA). Ends at the `ret` at
  0x5f6ad6d; the `int3` padding from 0x5f6ad6e is excluded.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5eeb650 --stop-address=0x5eeb66e work/hl-node-115.bin
objdump -d --start-address=0x5d8c9d0 --stop-address=0x5d8c9dd work/hl-node-115.bin
objdump -d --start-address=0x5f6acb0 --stop-address=0x5f6ad6e work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. All
three windows start with `endbr64`; every mnemonic in the excerpts
is genuine objdump output from the target binary, not a placeholder,
and verify.py checks sampled instructions byte-for-byte against a
fresh objdump run and the raw binary. Instruction-level detail
lives only in the verbatim excerpts; records.json carries semantic
records, not a per-instruction list.

## Semantics (literal)

### Getter 0x5eeb650

Arguments (outer, out) in (rdi, rsi). The getter loads the member
at [outer + 0x788], saves out in rbx, and calls the stub with that
member; it stores the stub's return to *out and returns 1
unconditionally. There is no null check anywhere in this behavior:
a null outer, a null member, or a null aggregate object faults in
the binary (the model raises instead; see tools/aggregate_sum_getter_115.py).

```
*out = aggregate_sum([[outer + 0x788] + 0x30])
return 1
```

### Forwarding stub 0x5d8c9d0

Loads the aggregate object at [member + 0x30] and tail-jumps to
the aggregate, so the aggregate's return value passes through
unchanged. The stub has no `ret` of its own and no other behavior.
Besides the getter, the stub has one further census-confirmed
direct caller, site 0x5e69df3 in 0x5e68fd0..0x5e6b82a, recorded
by site only; that function's internals were not read.

### Aggregate sum 0x5f6acb0

Argument obj in rdi. The count is the signed 32-bit value at
[obj + 0x50]; count <= 0 returns 0 at once. Otherwise the groups
are the first count 24-byte entries starting at the array base in
[obj + 0xad8]; each entry carries a begin pointer at +0 and an end
pointer at +8 (the third qword is never read). For every pointer
in a group's [begin, end) range, the aggregate adds the qword at
[pointer + 0x10] to a 64-bit wrapping total and returns it.

```
count = signed32([obj + 0x50])
if count <= 0: return 0
total = 0
for each of the first count groups at [obj + 0xad8]:
    for each pointer p in [group.begin, group.end):
        total += [p + 0x10]   (64-bit wrapping)
return total
```

The binary processes the pointers of a group in pairs with SIMD
`paddq` and handles a lone final element separately; the
observable total is the plain sum above, which the model computes
directly. An empty group (begin == end) contributes nothing, and
the count, not the array length, decides how many groups are read.

## Assumptions and unknowns

- The model represents each group's elements by their + 0x10
  values directly; pointer layout beyond begin/end is not modelled.
- Valid model inputs have as many groups as the count when the
  count is positive; the binary reads exactly count groups.
- The getter's argument setup for the stub's second caller
  (0x5e69df3) is not claimed.
- Neighbouring getter 0x5eeb630 and its target 0x5f91010 are not
  covered by this packet.
