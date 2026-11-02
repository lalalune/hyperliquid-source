# RE-001: tagged count with saturating subtraction, capped by a field, over node #94 (0x22c3f10)

Task ID: RE-001. Bounded question: what does the 69-byte function at
0x22c3f10 in node #94 return, and how do its three paths combine a tag,
two fields and an upper bound?
Answer: it takes `rdi` = a struct pointer, reads a tag at `[rdi]`, and
returns a single unsigned qword that is always `umin(base, [rdi+0x28])`.
The tag selects `base`: when `[rdi]` is zero (full 64 bits) `base =
[rdi+0x18]`; when the tag's low 32 bits equal 1 `base` is the unsigned
saturating difference `[rdi+0x10] - [rdi+0x18]` (0 on underflow); for any
other tag `base = 0`. Every path then caps the result at `[rdi+0x28]`.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x22c3f10..0x22c3f55, 69 bytes, body SHA-256
  `1b7701b64e3f85801c9ee03ff1b4f5882c2cf90f520e99d0929fc010fd9304f3`,
  FDE at .eh_frame+0x62e80 (length 0x10, range 0x45 = 69), 11 int3
  padding bytes to the next FDE at 0x22c3f60.
- No stack canary, no callee-saved pushes: this is a leaf with no calls
  and no indirect branches. No `e8`, `e9` or `ff` byte appears anywhere in
  the locked 69-byte body; every one of the three arms ends in `ret`.

## Observations (read from the bytes)

- `mov (%rdi),%rax` (0x22c3f10) loads the full 64-bit tag; `test %rax,%rax`
  then `je 0x22c3f37` takes the tag-zero arm when the whole qword is 0.
- `cmp $0x1,%eax` then `jne 0x22c3f47` takes the default arm unless the
  tag's **low 32 bits** are exactly 1; the compare is 32-bit (`83 f8 01`),
  so high bits are ignored by this discriminant.
- Tag-one arm (0x22c3f1d): `mov 0x10(%rdi),%rcx`, `xor %eax,%eax`,
  `sub 0x18(%rdi),%rcx`, `cmovae %rcx,%rax`. The `sub` sets CF when
  `[rdi+0x10] < [rdi+0x18]` (unsigned borrow); `cmovae` keeps the
  difference only when there is no borrow, otherwise `rax` stays 0. This is
  an unsigned saturating subtraction.
- Cap step, present in all three arms: `mov 0x28(%rdi),%rcx`,
  `cmp %rax,%rcx`, `cmovb %rcx,%rax`. This replaces `rax` with `[rdi+0x28]`
  only when `[rdi+0x28] < rax`, i.e. `rax = umin(rax, [rdi+0x28])`.
- Tag-zero arm (0x22c3f37): `mov 0x18(%rdi),%rax` loads `[rdi+0x18]`
  directly (no subtraction, `[rdi+0x10]` is not read), then caps it.
- Default arm (0x22c3f47): `xor %eax,%eax` sets `rax = 0`, then the cap
  step runs; `cmovb` can never fire against 0 (nothing is unsigned-less
  than 0), so the arm returns 0 regardless of `[rdi+0x28]`.
- Caller census (full .text scan for `e8` rel32 calls and `e9` rel32 tail
  jumps to 0x22c3f10): exactly one direct caller, 0x227d52d, and no tail
  jumps. That caller forwards a pointer into `rdi` (`mov %rsi,%rdi` at
  0x227d527) and stores the returned count into a stack slot
  (`mov %rax,0x28(%rsp)` at 0x227d537) consumed by a later indirect call.
- Relocation census: no `R_X86_64_RELATIVE` record in .rela.dyn names
  0x22c3f10 as its addend; the window is reached only by that direct call.

## Inferences (labelled, not observations)

- The three fields `[rdi+0x10]`, `[rdi+0x18]`, `[rdi+0x28]` are read as
  unsigned qwords; the tag-one arm treats `[rdi+0x10]`/`[rdi+0x18]` as a
  high/low pair whose difference is a count, and `[rdi+0x28]` as a cap on
  the result. No source-level type is claimed for the struct, the tag, or
  the fields.
- The uniform `umin(base, [rdi+0x28])` cap and the saturating subtraction
  read as a bounded-count/remaining-capacity accessor, but the role is a
  label, not a claimed identity.

## Unknowns (not claimed)

- The source-level types of the struct, the tag enumeration, and the three
  fields are not claimed.
- Which concrete values the tag takes at runtime, and whether the default
  (0-returning) arm is reachable in practice, are not demonstrated from
  this function alone.
- A 0 return is ambiguous: it arises from the default arm, from a tag-one
  underflow, and from a tag-zero/tag-one path whose capped `base` is 0. The
  negative controls below pin this ambiguity rather than hide it.

## Overlap notes (checked before building)

- No work item, tool, test, or doc in the tree claims 0x22c3f10, and no
  open upstream PR names it (checked against .openprs.txt). The only
  in-tree substring hits for `22c3f4` are unrelated random hex blobs in
  RE-001-multiply-subtract-rust-94/fixtures/inputs.tsv; neither touches
  this function.
- Neighbours are distinct: the preceding FDE ends at 0x22c3f04 and the
  following FDE begins at 0x22c3f60 (a separate 5-byte stub, unexamined
  here).

## Evidence format

- evidence.json holds semantic records only (digest, carve range and SHA,
  tag and field offsets, the three-arm formula and its edges,
  caller/relocation censuses). Instruction-level detail lives only in the
  raw objdump excerpts: window.objdump.txt (0x22c3f10..0x22c3f60, function
  plus padding) and caller.objdump.txt (0x227d510..0x227d548, the sole
  caller's call site and result store).
- frames.txt carries the CIE and the two FDE records, checked against the
  binary with GNU `--dwarf=frames`.
- tools/tagged_count_min_cap.py is the runnable checker;
  tests/test_tagged_count_min_cap.py registers the target-grounded
  controls, the decoded-rule edges and the corruption controls.

## Reproduction

```
objdump -d --start-address=0x22c3f10 --stop-address=0x22c3f60 artifacts/node/94/hl-node
python3 tools/tagged_count_min_cap.py --check \
    research/work-items/tagged-count-min-cap-94/evidence.json
python3 tests/test_tagged_count_min_cap.py
```

Environment limits, stated honestly: this VM has no cargo/rustc and no
pinned Rust toolchain, so Rust checks are not run; this packet is static
evidence plus Python verifiers only and claims no Rust reconstruction.
objdump here is GNU binutils.
