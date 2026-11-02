# node94 checked 256-bit subtraction

Independent, dependency-free `no_std` Rust for the complete node94 leaf `[0x2760a10,0x2760a67)`, target SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`subtract` takes one mutable byte image and abstract u64 addresses for the minuend, subtrahend and output. It preserves ordered operand dependencies under arbitrary byte overlap: later subtrahend reads can observe earlier minuend rewrites. The entire minuend is rewritten even when subtraction fails. Success snapshots/copies 32 result bytes to output+8; both paths store a full qword flag at output and return the exact 0/1 RAX value.

The image and used ranges must not wrap. Both operands require 32 bytes; output requires 8 bytes on failure, 40 on success. A 32-byte staging buffer models the ordered operand writes, allowing all required ranges to be checked before any actual mutation. Refusals leave the image unchanged. This is a final-state projection under valid ordinary memory and disjoint instruction/control storage. Native ABI, fault timing, MMIO, concurrency and wrapped operand/output ranges are excluded. No alignment or operand/output disjointness is assumed.

This differs from the existing 0x32d8310 wide-subtract leaf: this leaf mutates the minuend unconditionally and gates output copying on success. The predecessor's entry-value arithmetic covered disjoint operands only. See `research/work-items/RE-001-checked-subtract-rust-94/PROOF.md` for the whole-prefix alias theorem and complete native branch proof.

From repository root:

```sh
PATH=/opt/homebrew/opt/rustup/bin:$PATH cargo check --offline --manifest-path src/node94-checked-subtract/Cargo.toml
python3 -O research/work-items/RE-001-checked-subtract-rust-94/verify.py --out work/checked-subtract-review
```

The standalone stdin client accepts inputs only and reports the exact return/error status and every changed image byte. It cannot open or receive expected outputs. No captured code is executed or emulated, and no whole-node build or progress gate is claimed.
