# RE-001: node #115 two-phase filtered accumulation 0x5f77330

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the 593-byte function
at 0x5f77330 do with the group table end to end — which elements it
accumulates, what the 136-byte leaf at 0x5f6b590 adds to the counters,
when the forward scan gives way to the reverse scan, and what stops the
reverse scan?

## Windows

* Scan 0x5f77330..0x5f77581 (593 bytes, FDE range as shown in
  frames.txt). The main window of this item.
* Leaf 0x5f6b590..0x5f6b618 (136 bytes, FDE range as shown in
  frames.txt). The accumulator the scan calls in both phases.

Both windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

## Semantics, stated literally

The scan takes only the object pointer and returns nothing. Count =
signed 32-bit value at obj + 0x50; groups are the first count 24-byte
entries at obj + 0xad8, each entry holding an 8-byte element-pointer
array in its first two qwords (begin, end); the third qword is never
read. Count <= 0 returns at once with no predicate call.

Phase 1 (forward): groups in order, element pointers in order. A
predicate-false element is skipped with no accumulator call and no
virtual-chain call. A match is accumulated into the block at
obj + 0x40 (the leaf's base), then the virtual chain runs. A result of
0x400000 (the sentinel) continues the scan; any other result increments
the special count, and the 20th such result breaks out of both loops
into phase 2 at once. Exhausting all groups falls through into phase 2
the same way.

Phase 2 (reverse): entered after phase 1 however it ended. It returns
at once when the accumulated base + 0xf98 counter (obj + 0xfd8) is
nonzero. Otherwise groups run from last to first, element pointers
from last to first; a match is accumulated, and after every element
step a nonzero base + 0xf98 counter ends phase 2 entirely. An empty
group contributes nothing.

The leaf (base, element), all wrapping 64-bit arithmetic, no calls,
no return value: base + 0xf88 += element + 0x10; base + 0xf90 +=
element + 0x90; base + 0xf98 += element + 0x98; base + 0xfa0 =
base + 0xfa0 + element + 0x80 - element + 0x88; base + 0xfa8 +=
element + 0x88; base + 0xfb0 = base + 0xfb0 + element + 0x80 -
element + 0x88; base + 0xfc0 += 1; base + 0xfb8 += element + 0x88.
In caller terms the counters land at obj + 0xfc8, +0xfd0, +0xfd8,
+0xfe0, +0xfe8, +0xff0, +0xff8 and +0x1000.

NOT claimed: the predicate 0x5f77190's matching rule; the virtual
chain's link walk, the global tag it compares against, and the virtual
method it calls; the pipeline wrapper 0x5f88550's own control flow
beyond its one call site; any meaning for the counters beyond the
eight updates the leaf performs. The model takes the group table and
the count as fixed inputs; an oracle mutating them mid-scan is out of
contract.

## Census

Whole-file scan, reproduced by census.py in this packet: the scan has
exactly 1 direct call (0x5f88588, inside the pipeline wrapper
0x5f88550, site-only), 0 tail jumps, 0 stored qwords, 0 RELATIVE
addends. The leaf has exactly 2 direct calls (0x5f773bd in phase 1,
0x5f77508 in phase 2), 0 tail jumps, 0 stored qwords, 0 RELATIVE
addends.

## Reproduction

From the repository root:

    objdump -d --start-address=0x5f77330 --stop-address=0x5f77581 work/hl-node-115.bin > research/work-items/RE-001-two-phase-filtered-accum-115/main.txt
    objdump -d --start-address=0x5f6b590 --stop-address=0x5f6b618 work/hl-node-115.bin > research/work-items/RE-001-two-phase-filtered-accum-115/leaf.txt
    python3 research/work-items/RE-001-two-phase-filtered-accum-115/export_excerpts.py
    python3 research/work-items/RE-001-two-phase-filtered-accum-115/census.py
    python3 research/work-items/RE-001-two-phase-filtered-accum-115/verify.py
    python3 tests/test_two_phase_filtered_accum_115.py

The excerpts are verbatim objdump output: instruction mnemonics such
as `endbr64` in them are genuine instructions present in the target
binary, not placeholders. The model tests exercise the behavior end
to end (inputs through the model to observable counter outputs), not
only pinned constants.

## Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify`, `make test` and `make catalogue-check` fail on the
LFS-pointer artifact here (pre-existing, not caused by this change);
the packet binds to the materialized work/hl-node-115.bin instead,
whose hash matches provenance. The packet checker (verify.py) and the
model tests run and pass here.
