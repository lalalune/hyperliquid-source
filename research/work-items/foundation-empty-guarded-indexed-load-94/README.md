# RE-001: empty-guarded indexed load over node #94 (0x4fec800)

Task ID: RE-001. Bounded question: what does the 35-byte function at
0x4fec800 in node #94 return, and what guards its one memory read?
Answer: it takes `rdi` = a container and `rsi` = an index, reads a
begin/end pointer pair at `[rdi+0x988]`/`[rdi+0x990]`, returns 0 when
they are equal (an empty container), and otherwise returns the first
qword of the `rsi`-th 16-byte element, `qword[[rdi+0x988] + 16*rsi]`.
The index is never bounds-checked; the only guard is emptiness.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x4fec800..0x4fec823, 35 bytes, body SHA-256
  `b6da27453a165412264e0289a3548633511967910594dccc0faf563430c74c6b`,
  FDE at .eh_frame+0x28f04c (length 0x10), 13 int3 padding bytes to the
  next FDE at 0x4fec830.
- No stack canary, no callee-saved pushes: this is a leaf with no calls
  and no indirect branches (no `e8`/`ff` byte at any locked boundary).

## Observations (read from the bytes)

- `endbr64` (0x4fec800); `mov 0x988(%rdi),%rax` loads the begin pointer;
  `cmp 0x990(%rdi),%rax` compares it against the end pointer.
- `je 0x4fec820` (rel8 `74 0c`): when begin == end, fall through to
  `xor %eax,%eax` + `ret`, returning 0.
- Otherwise `shl $0x4,%rsi` scales the index by the 16-byte element
  stride, `mov (%rax,%rsi,1),%rax` loads the first qword of that element,
  and `ret` returns it.
- `nopl (%rax)` at 0x4fec81d is genuine alignment padding inside the
  function body, between the two return paths; it is part of the 35
  locked bytes, not trailing padding.
- Caller census (full .text scan for `e8` rel32 calls and `e9` rel32
  tail jumps to 0x4fec800): exactly one direct caller, 0x4fb2546, and no
  tail jumps. That caller (function head 0x4fb2530) forwards its 2nd and
  3rd arguments as `(rdi, rsi)`, then null-checks the result with
  `test %rax,%rax ; je` — i.e. it treats the empty-guard 0 as a "none".
- Relocation census: no `R_X86_64_RELATIVE` record in .rela.dyn names
  0x4fec800 as its addend; the window is reached only by that direct call.

## Inferences (labelled, not observations)

- The `[rdi+0x988]`/`[rdi+0x990]` pair is read as a begin/end pointer
  pair over 16-byte elements (a slice/vector-like region); no
  source-level type is claimed for the container or the element.
- The returned first qword is read as a pointer-or-value the caller then
  null-checks; its contract past the load is not claimed.

## Unknowns (not claimed)

- The source-level types of the container, the begin/end field pair, and
  the element are not claimed.
- Only emptiness is guarded. Whether callers always pass an in-range
  index (so the missing bound check is safe in practice) is not
  demonstrated from this function alone.
- A 0 return is ambiguous: it arises both from an empty container and
  from a non-empty element whose stored first qword is 0. The negative
  controls below pin this ambiguity rather than hide it.

## Overlap notes (checked before building)

- No work item, tool, test, or doc in the tree claims 0x4fec800, and no
  open upstream PR names it (checked against the open-PR list). The two
  stray in-tree substring hits for "4fec80" are an unrelated hex blob in
  fees-staking-link-94/vectors.tsv and a different address in the
  imported visor disassembly; neither touches this function.
- Neighbours are distinct: the preceding function ends before 0x4fec800,
  and the following FDE begins at 0x4fec830 (unexamined here).

## Evidence format

- evidence.json holds semantic records only (digest, carve range and SHA,
  field offsets, stride, caller/relocation censuses, the decoded rule and
  its edges). Instruction-level detail lives only in the raw objdump
  excerpts: window.objdump.txt (0x4fec800..0x4fec830, function plus
  padding) and caller.objdump.txt (0x4fb2530..0x4fb2557, the sole caller).
- frames.txt carries the CIE and the two FDE records, checked against the
  binary with GNU `--dwarf=frames`.
- tools/foundation_empty_guarded_indexed_load.py is the runnable checker;
  tests/test_foundation_empty_guarded_indexed_load.py registers the
  target-grounded controls, the decoded-rule edges and the corruption
  controls.

## Reproduction

```
objdump -d --start-address=0x4fec800 --stop-address=0x4fec830 artifacts/node/94/hl-node
python3 tools/foundation_empty_guarded_indexed_load.py --check \
    research/work-items/foundation-empty-guarded-indexed-load-94/evidence.json
python3 tests/test_foundation_empty_guarded_indexed_load.py
```

Environment limits, stated honestly: this VM has no cargo/rustc and no
pinned Rust toolchain, so Rust checks are not run; this packet is static
evidence plus Python verifiers only and claims no Rust reconstruction.
objdump here is GNU binutils 2.44.
