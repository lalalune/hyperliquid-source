# RE-001: node #115 threshold store 0x5f6c270 with its minimum recompute 0x5f6bfe0

Bounded question: what does the small store at 0x5f6c270 maintain, and
what does the recompute it tail-jumps to rebuild when the stored value
rises past the current minimum?

## Windows (whole functions, from .eh_frame)

- Setter 0x5f6c270..0x5f6c28d (29 bytes, FDE at file offset 0x1004d88).
- Recompute 0x5f6bfe0..0x5f6c266 (646 bytes, FDE at file offset 0x1004d3c).

Both windows were extracted from the digest-verified node #115 binary
`work/hl-node-115.bin` (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
bound in `provenance/artifacts.json` as `artifacts/node/115/hl-node`).
Instruction-level detail lives only in the verbatim objdump excerpts
under `excerpts/`; the mnemonics there are genuine instructions from
the target binary, reproduced exactly as objdump emitted them, not
placeholders. Excerpts regenerate byte-for-byte with:

```
objdump -d --start-address=0x5f6c270 --stop-address=0x5f6c28d work/hl-node-115.bin
objdump -d --start-address=0x5f6bfe0 --stop-address=0x5f6c266 work/hl-node-115.bin
```

## Semantics, stated literally

Object fields: threshold at +0xf30, minimum at +0xf28, collection
size at +0xdd8, collection inline base at +0xe60, collection heap
begin/end/cap end at +0xe68/+0xe70/+0xe78, scan inline base at
+0xdb8, scan heap begin/end at +0xdc0/+0xdc8, scan extra count at
+0xd30. A scan record is 16 bytes: an ignored first qword and an
element pointer; the element's flag byte is at +0xb4 and its value
qword at +0x20.

Setter: store the new value at +0xf30 first. Then, when the old
minimum at +0xf28 is unsigned-less than the new value, tail-jump to
the recompute; otherwise return. The fast path does not rescan, so
after a decrease the collection and the minimum still reflect the
previous threshold until a later increase triggers a recompute.

Recompute:
1. If the collection size is nonzero, set it to 0; if the heap end
   differs from the heap begin, set the heap end to the heap begin
   (the heap capacity is retained).
2. Set the minimum to the sentinel 0x00ffffffffffffff.
3. Scan logical indices 0..total-1, where total = scan heap length +
   scan extra count. Index <= 7 reads the scan inline array; index >
   7 reads the scan heap array at index - 8.
4. Per record, skip it when the element flag byte is nonzero, and
   skip it when the element value is zero. When the value is
   unsigned-less than the threshold, append the whole 16-byte record
   to the collection; otherwise set the minimum to the unsigned
   minimum of the current minimum and the value.
5. Collection append: while the collection size is <= 7, store at the
   inline base + size * 16; past that, store at the heap end when it
   is below the heap cap end, otherwise grow the heap (new capacity 1
   when the heap is empty, else twice the heap size, capped at
   0x7ffffffffffffff elements; growing past that cap throws the
   native length error) and then store. The old heap buffer is freed
   on growth when it is non-null.

The recompute never reads its incoming second argument: it works from
the stored threshold field, which the setter writes before
tail-jumping. The native zero-new-capacity growth arm requires a
nonempty heap of size 0 and is unreachable for a well-formed heap; it
is recorded as an assumption, not modelled as reachable behavior.

## Census (whole-file scan, reproduced by census.py)

- Setter: exactly 1 direct call (site 0x5d67f16, site only), 0 tail
  jumps, 0 stored qwords, 0 RELATIVE addends.
- Recompute: exactly 1 direct call (site 0x5f7eba1, inside the
  0x5f7e420 function, site only), exactly 1 tail jump (the setter's
  site 0x5f6c288), 0 stored qwords, 0 RELATIVE addends.

## Model and tests

- `tools/threshold_store_115.py` implements the setter and the
  recompute literally, including the fast-path staleness, the heap
  growth rule, and the length-error guard.
- `tests/test_threshold_store_115.py` covers the fast path (below and
  equal to the minimum), the recompute path using the new threshold
  rather than the old one, the sentinel case, zero-value and
  flagged-element skips, the equal-to-threshold minimum case,
  clearing of a previous collection with capacity retained, the
  inline/heap scan mix, growth past the 8 inline slots (heap
  capacity 1, 2, 4 across 12 records), unsigned ordering, and guard
  errors for null elements and short scan arrays.

## Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs, and no Ghidra/Java, so the
Rust reconstruction surface is out of reach; this item stays in the
Python model layer. `make doctor` fails on missing providers and
`make verify` fails on the LFS-pointer artifact here (both
pre-existing); this packet binds to the materialized
`work/hl-node-115.bin` instead. pytest is not installed, so the
pytest-style test file runs under plain python3 via its `__main__`
runner; `verify.py` runs that same runner.
