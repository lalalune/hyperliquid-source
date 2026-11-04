# RE-001: map node #115 three-array string teardown 0x5d54fc0

Task: RE-001. Bounded question: what does the leaf routine at
0x5d54fc0 do to its holder, and which code calls it?

Target: node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound via `provenance/artifacts.json`), upstream main `8fd8db68`
at the time of this work.

## Answer in one paragraph

The routine tears down three vectors of 32-byte strings stored in one
holder, in the fixed order A, B, C. For each vector it first frees the
heap buffer of every element whose data pointer differs from the
element's own inline buffer (the libstdc++ short-string check), then
frees the vector's buffer itself with the sized delete, unless the
vector's begin pointer is null. It writes nothing back to the holder:
every begin/end/capacity field is left dangling, and it returns no
value. The third vector's buffer free is a tail jump to the sized
delete; the routine makes no other calls.

## Holder layout (rdi = holder pointer)

| Vector | begin | end | capacity end | element stride |
| ------ | ----- | --- | ------------ | -------------- |
| A | +0x50 | +0x58 | +0x60 | 0x20 |
| B | +0x38 | +0x40 | +0x48 | 0x20 |
| C | +0x08 | +0x10 | +0x18 | 0x20 |

Element layout (32 bytes): data pointer at +0x00, an 8-byte field at
+0x08 that the routine never reads, and the capacity-or-inline-buffer
slot at +0x10. The +0x08 field is the string length in the libstdc++
layout; the routine never consults it, so no length claim is made
here. The sized delete of a heap element passes capacity + 1, i.e.
the heap allocation size including the terminating NUL.

## Semantics, in order

1. Vector A: walk elements from +0x50 to +0x58 in 0x20 steps. For
   each element, if its +0x00 pointer equals the element's own +0x10
   address, skip it (short string, buffer inside the element). Else
   call the sized delete with (data, *(element + 0x10) + 1). Then, if
   A begin (+0x50) is non-null, call the sized delete with (begin,
   *(+0x60) - begin); a null begin skips the buffer free. An empty
   but non-null vector still frees its buffer with the
   capacity-minus-begin size.
2. Vector B: the same two steps with +0x38 / +0x40 / +0x48.
3. Vector C: the same two steps with +0x08 / +0x10 / +0x18, except
   the buffer free is a tail jump to the sized delete, so the routine
   never returns normally on the C-buffer path; when C begin is null
   it returns normally instead.
4. No holder field is written at any point. The routine is a leaf
   apart from the sized-delete PLT calls.

## Consumers (census)

Exactly 2 direct calls, 0 tail jumps, 1 distinct caller FDE. Both
sites sit in FDE 0x5d7d5a8..0x5d7d740, which is itself a landing-pad
region of a larger function (it opens with `__cxa_begin_catch` and
has no prologue): site 0x5d7d619 passes a stack holder at rsp+0x60
and site 0x5d7d6a8 passes a stack holder at rsp+0xd0. Both calls
occur on exception-cleanup paths (each is reached after a
`__cxa_end_catch` / delete sequence and the region resumes unwinding
via `_Unwind_Resume`). The surrounding function's body beyond these
cleanup blocks is not pinned here. The routine is reached only by
code: no stored qword and no RELATIVE relocation for 0x5d54fc0
exists in the binary (see `relocations.txt`, empty).

## Observations, inferences, unknowns (kept separate)

- Observation: the routine reads only the begin/end/capacity-end
  triples and, per element, the +0x00 data pointer and the +0x10
  slot. It never reads any element's +0x08 field and never writes
  to the holder.
- Inference: the elements are libstdc++ `std::string`s and the three
  triples are `std::vector<std::string>` members, from the 0x20
  stride, the data-vs-inline-buffer check, and the capacity + 1
  sized-delete size. The vector identity is inference; the pinned
  claim is only the byte-level behavior above.
- Inference: the two caller sites tear down two distinct stack
  holders of the same shape during exception cleanup. The caller's
  normal path is not pinned.
- Unknown: what the holder object is, what fills the three vectors,
  and what the +0x08 element field holds beyond the layout
  inference. The packet does not pin the owning type.
- Unknown: a holder whose begin is null but whose end is non-null
  would make the element walk read from address zero; such a holder
  cannot come from a well-formed vector, so the model requires begin
  null to imply an empty vector and does not pin the malformed case.

## Evidence

- `main.txt`: the whole-function disassembly excerpt, verbatim as
  objdump emitted it (only the header line's file path is normalized
  to the bare binary name, as `export_excerpts.py` does). The
  `endbr64` at 0x5d54fc0 is a genuine instruction present in the
  target binary, not a placeholder.
- `frames.txt`: the routine FDE (0x5d54fc0..0x5d55105) and the
  caller FDE (0x5d7d5a8..0x5d7d740).
- `callers.tsv`: both confirmed call sites.
- `relocations.txt`: empty; no relocation references 0x5d54fc0.
- `records.json`: semantic records only. No per-instruction list is
  included; instruction-level detail lives only in `main.txt`.
- `verify.py`: replays every check (digest, manifest, excerpt
  regeneration byte-for-byte from a fresh objdump run, all excerpt
  instruction bytes against the raw binary, both FDE ranges, the
  census with its exact site list, the empty relocation record, and
  model spot checks).
- `export_excerpts.py` / `census.py`: the scripts that produced
  `main.txt`, `frames.txt`, and `callers.tsv`.

Regeneration commands:

```
objdump -d --start-address=0x5d54fc0 --stop-address=0x5d55105 \
    work/hl-node-115.bin
readelf --debug-dump=frames-interp work/hl-node-115.bin
python3 research/work-items/RE-001-three-array-string-teardown-54fc0-115/verify.py
```

## Environment limits

This work was done without cargo/rustc, git-lfs, or Ghidra. All
claims rest on objdump/readelf output over the materialized
`work/hl-node-115.bin`, whose digest matches
`provenance/artifacts.json`. The Python model in
`tools/three_array_string_teardown_54fc0_115.py` and its tests in
`tests/test_three_array_string_teardown_54fc0_115.py` encode exactly
the behavior above.
