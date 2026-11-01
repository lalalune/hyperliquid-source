# Node #94 conditional two-hop field read

Safe, dependency-free `no_std` reconstruction of the complete 40-byte leaf
`[0x5361710,0x5361738)` in node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`load(image, base, object)` interprets a stable numeric memory image. It loads
P at object+8 and Q at P+0x1e0, then reads P+0x178 if Q is zero or Q+8
otherwise. It returns full RAX=the selected qword and RDX=P. All field addresses
wrap modulo 2^64. Only reached qwords must fit completely in the nonwrapping
image; unused terminal fields need not be mapped. Numeric zero roots are
accepted when their reached fields are present.

None is a new safe refusal for missing reached bytes or an overflowing image,
not an original return/fault. The shared slice is never mutated. The original
normal-return relation assumes stable ordinary memory and valid control/stack
state; faults, timing, concurrent mutation, MMIO, flags and the native ABI are
not reproduced. The 512-byte client image is only fixture framing, not an API
capacity limit. Numeric fields never become host pointers.

The [proof](../../research/work-items/RE-004-two-hop-field-select-rust-94/PROOF.md)
and [evidence packet](../../research/work-items/RE-004-two-hop-field-select-rust-94/README.md)
bind the complete code/FDE, both caller contexts and independent expectations.
No source struct/library identity, original compiler or compiled-byte equality
is inferred.

From the repository root, using the pinned actual rustc 1.94.1 host compiler:

```sh
python3 -O research/work-items/RE-004-two-hop-field-select-rust-94/verify_static.py
python3 -O research/work-items/RE-004-two-hop-field-select-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/two-hop-field-select-replay
```

The verifier checks compiler/source hashes, builds opt0/opt3 and repeats both,
runs the input-only driver against frozen expectations, and compiles effective
wrong implementations. There is no Cargo workspace, invented dependency lock
or full-node build. New source is independently authored MIT code; binary
evidence retains the artifact's original rights.
