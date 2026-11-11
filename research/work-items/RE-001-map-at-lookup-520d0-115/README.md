# RE-001: map-at lookup routine 0x5d520d0 (node #115)

## Bounded question

What does the routine at `0x5d520d0` compute for an out record and a
holder, and where is that routine used?

## Answer (established semantics)

The routine `0x5d520d0` takes an out record pointer in `rdi` and a
holder pointer in `rsi`, and returns the out pointer in every success
path. It is a complete behaviour end to end, not a lone-window
fragment: the whole 609-byte routine is pinned (FDE
`0x5d520d0..0x5d52331`), its three builder phases, its zero-record
failure path, its throw path and its two direct callers are all pinned.
The disassembly excerpts in this packet are verbatim objdump output:
opcodes such as `endbr64` are genuine instructions present in the
target binary, not placeholders.

### Layout

- `H` is the holder. The routine reads the head pointer at `H+0x1790`,
  the flag dword at `H+0x5d0`, the flag dword at `H+0x5d4`, the base
  pointer `H+0x1748` and the sentinel pointer `H+0x1788`.
- A graph node holds a kind byte at `+0x20`, a next pointer at `+0x10`,
  an alternate pointer at `+0x18` and a builder field at `+0x28`.
- The builder temp is a 16-byte record on the stack: dword at `+0x00`,
  word at `+0x04`, qword at `+0x08`. Its flag byte is at `+0x00`.
- The out record has the same 16-byte shape. Bytes `+0x06..+0x07` of
  the out record are written by no path in this routine.

### Phase A (flag0)

Phase A runs when the dword at `H+0x5d0` is nonzero, and is skipped
otherwise. It follows `+0x10` links from the head to the last
non-null node. If the head is null, the chain ends at the sentinel,
or the tail node's kind is not 0, the routine throws (see below).
Otherwise it builds a temp with `0x5f22020(temp, H+0x1748, 0,
node+0x28)`. If the temp flag byte is nonzero, the routine takes the
zero-record path below. If it is zero, the routine deletes the temp
qword at `+0x08` when non-null, reloads the head from `H+0x1790` and
continues at the flag1 test.

### Phase 1 (flag1)

Phase 1 runs when the dword at `H+0x5d4` is nonzero (re-read after a
successful phase A), and is skipped otherwise. It walks from the head:
kind-0 nodes step via `+0x18`, kind-nonzero nodes become the candidate
and descend via `+0x10`; the walk ends when the next pointer is null.
If the head is null, no candidate was found (the walk ends at the
sentinel), or the candidate kind is above 1, the routine throws. The
walk only records kind-nonzero nodes, so a passing candidate has kind
exactly 1. The routine then builds a temp with `0x5f22020(temp,
H+0x1748, 1, node+0x28)`. A nonzero temp flag byte takes the
zero-record path; a zero flag byte deletes the temp qword at `+0x08`
when non-null, reloads the head and continues to phase 2.

### Phase 2 (always)

Phase 2 always runs unless an earlier phase threw or took the
zero-record path. It walks from the head: kind-at-most-1 nodes step
via `+0x18`, kind-above-1 nodes become the candidate and descend via
`+0x10`; the walk ends when the next pointer is null. If the head is
null, no candidate was found, or the candidate kind is above 2, the
routine throws. The walk only records kind-above-1 nodes, so a passing
candidate has kind exactly 2. The routine then builds a temp with
`0x5f22f80(temp, H+0x1748, 2, node+0x28)` — a different builder from
phases A and 1 — and copies it into out: dword, word at `+0x04` and
qword at `+0x08`. The temp heap pointer moves into out; there is no
delete call on this path. The routine returns out.

### Tag/kind correspondence (observed, not builder internals)

Each builder call passes a tag equal to its phase's candidate kind:
0 in phase A, 1 in phase 1, 2 in phase 2. What the builders compute
inside the temp is not pinned here; they are recorded by address and
argument order only.

### Zero-record path

Reached from phase A or phase 1 when the builder temp flag byte is
nonzero. The routine zeroes the out record (dword, word at `+0x04`,
qword at `+0x08`), calls `0x5d49b10(out, temp)`, deletes the temp
qword at `+0x08` when non-null, and returns out through the shared
epilogue. The assign helper is recorded by address and argument order
only.

### Throw path

Any walk failure throws `std::out_of_range` with the literal `map::at`
at address `0x4408a7`, through the PLT at `0x63f1050`, after the stack
canary check. The walks carry no visited set, so a cyclic graph loops
forever in the binary as in the model.

### Return and stack

There is a single return site at `0x5d5226e`, returning the out
pointer. The frame carries a stack canary at `rsp+0x18`, checked in
both the success epilogue and the throw path; a canary mismatch calls
`__stack_chk_fail` instead of returning or throwing.

### Consumers

Exactly two direct calls, no tail jumps, no stored qwords, no RELATIVE
relocations — reached only by code, never by data:

- `0x5e63dc8` (call) in FDE `0x5e62c50..0x5e65462`;
- `0x5e7a228` (call) in FDE `0x5e79c30..0x5e7a4a4`.

The byte at `0x5d52331` between this FDE and the next FDE at
`0x5d52332` is padding, not part of this routine.

## What is not claimed

- What the builders `0x5f22020` and `0x5f22f80` compute inside the
  temp record, what the assign helper `0x5d49b10` computes from the
  temp, the source-level meaning of the holder, the node kinds and
  the tag values, and caller guarantees on graph shape.
- How a phase 1 or phase 2 walk behaves if it steps onto the sentinel
  node itself (the binary reads the sentinel's kind byte there, which
  is not pinned); the model stops the walk at the sentinel.
- The routine was verified against the materialized node #115 binary
  only. `make doctor` exits non-zero on this VM for the pre-existing
  missing Rust/Ghidra toolchains; `make verify`, `make test` and
  `make catalogue-check` were not run in a tooled environment and no
  hosted CI result is claimed.

## Reproduction

From the repository root:

```
python3 research/work-items/RE-001-map-at-lookup-520d0-115/export_excerpts.py
python3 research/work-items/RE-001-map-at-lookup-520d0-115/census.py
python3 research/work-items/RE-001-map-at-lookup-520d0-115/verify.py
```

`verify.py` checks the binary digest against
`provenance/artifacts.json`, the packet manifest, byte-for-byte
regeneration of the excerpts and frames, every excerpt line against
the raw binary, the caller census, the empty relocation census, the
semantic-only records file, model spot checks and the model tests.

## Verification command

The objdump command recorded for the excerpt is:

```
objdump -d --start-address=0x5d520d0 --stop-address=0x5d52331 work/hl-node-115.bin
```
