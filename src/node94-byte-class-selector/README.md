# node94 byte-class selector

Independent dependency-free `no_std` reconstruction of complete ELF VA `[0x359be70,0x359bebe)` (78 bytes/26 instructions), target SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

`select(first:u32, second:u32)->u64` accepts every pair of u32 values. The first low byte chooses the first value, the second value, or one of three low-byte rewrites of the second value. First-derived results retain all first bits; rewritten results retain the second value's upper 24 bits. The u64 result represents complete native RAX, with bits32..63 zero. No original source identity or text-encoding meaning is inferred.

This is a register-value projection. Native high argument bits32..63 cannot affect RAX; scratch registers, flags, timing, control/stack behavior and instruction faults are excluded. The target has no input-memory accesses. No pointer, alignment, alias or allocation premise is needed.

The proof separates the finite low-byte behavior from arbitrary high fields. All 65,536 low-byte pairs are frozen before Rust alongside high-bit and full-u32 witnesses. The input-only client accepts ID/two hex u32 values and emits ID/complete hex RAX; it cannot read expected outputs. Only new Rust executes.

From repository root:

```sh
PATH=/opt/homebrew/opt/rustup/bin:$PATH cargo check --offline --manifest-path src/node94-byte-class-selector/Cargo.toml
python3 -O research/work-items/RE-001-byte-class-selector-rust-94/verify.py --out work/byte-class-selector-review
```

See the evidence packet's `PROOF.md`, `COMMANDS.md` and machine-readable native records. No root workspace, full-node build, compiled-target-byte equivalence or progress gate is claimed.
