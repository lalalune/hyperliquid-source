# Node #94 pointer selector and adjusting tail wrappers

Safe, dependency-free `no_std` reconstruction of three complete linked entries:
direct `[0x552cac0,0x552cade)`, inner `[0x552b280,0x552b28d)` and outer
`[0x54cbd40,0x54cbd50)`. Together they contain 59 bytes / 13 instructions in
node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`load(entry, image, base, object, selector)` returns full RAX (loaded qword),
RDI (selected base) and RSI (unchanged selector). `Entry::Offset24` adds
0x18 to the object; `Entry::Offset10672` adds 0x2998 then 0x18. The low32
selector equal to one chooses offset 0xe518; other values choose 0xec10.
The sole load reads selected-base+0x78. All address additions wrap as u64.

The stable numeric image must not cross 2^64, and only the final chosen qword
must fit. Object/selected-base metadata and the unused field need not be
mapped. None is a new safe refusal, not an original fault/return. Numeric
addresses never become host pointers; the input slice is never mutated. The
2,048-byte client image is not a public API limit. Hardware mappings, flags,
stack/control faults, MMIO, races and the original native ABI are outside scope.

The [proof](../../research/work-items/RE-004-pointer-select-rust-94/PROOF.md)
and [packet](../../research/work-items/RE-004-pointer-select-rust-94/README.md)
close all three bodies, both internal jumps and the six complete direct-caller
contexts. Source structs, library identity and original compiled-byte equality
remain unknown.

From the repository root, using the pinned rustc 1.94.1 host compiler:

```sh
python3 -O research/work-items/RE-004-pointer-select-rust-94/verify_static.py
python3 -O research/work-items/RE-004-pointer-select-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/pointer-select-replay
```

The verifier checks exact compiler/source hashes, builds and repeats opt0/opt3,
and runs actual wrong implementations against the independently frozen oracle.
No Cargo workspace, dependency lock or full node is invented. New source is
independently authored MIT code; captured evidence retains its original rights.
