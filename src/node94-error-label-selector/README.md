# Node #94 byte selector

Safe, dependency-free `no_std` value projection of the complete 40-byte leaf
`[0x14b4e20,0x14b4e48)` from node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`select(tag, load_bias)` accepts all 256 byte values and all numeric `u64`
biases. It returns the full written RAX, RDX, RCX and RSI. The input byte is
the result of the original read through RDI; this is a value API, not that
pointer ABI or a fault model. Addresses use wrapping arithmetic and are never
dereferenced. RSI retains the second address even when RAX selects the first.

`captured_bytes(tag, &[u8;796])` separately projects the returned byte interval
from a supplied captured window. The original leaf does not read that window.
The adapter's host indices are independent of numeric addresses/load bias.
With the exact evidence window it exposes every returned byte; supplying other
data does not establish target-data identity. Tag 254 selects the largest
779-byte interval and reaches the exact end. Higher tags are not presumed to
be valid enum values or meaningful names.

The [proof](../../research/work-items/RE-004-error-label-selector-rust-94/PROOF.md)
and [packet](../../research/work-items/RE-004-error-label-selector-rust-94/README.md)
bind body, unwind records, entry relocation and the complete captured data.
The original compiler, caller, source identity, fault/stack/flags behavior and
compiled-byte equivalence remain outside this reconstruction.

From the repository root, use the actual pinned rustc 1.94.1 host compiler:

```sh
python3 -O research/work-items/RE-004-error-label-selector-rust-94/verify_static.py
python3 -O research/work-items/RE-004-error-label-selector-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/error-label-selector-replay
```

The verifier directly builds this real library and an input-only driver at
opt0/opt3, repeats both builds and compiles wrong implementations. The compiler
file hash, full version/host, linker and every command are checked/recorded.
No Cargo workspace, dependency lock or full node build is invented. The library
is independently authored MIT code; captured artifact bytes remain evidence
under their original rights and are supplied to the client as input.
