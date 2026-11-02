# Node94 modulo-index byte lookup

Independent dependency-free `no_std` Rust for the complete wrapper at
`0x538c820` and its fixed-seed call to the closed helper at `0x5422e70`.
`hash_for_index` handles little-endian complete words and signed residual
bytes. `lookup` reduces that hash by an unsigned u16 divisor and adds the
zero-extended low32 caller index before reading the selected table byte.

The original pointer ABI is projected onto immutable slices and scalar loads.
The successful correspondence domain requires valid ordinary stable memory,
nonwrapping effective accesses and nonwrapping hash-loop lookahead. ZeroDivisor
and TableBounds are additional safe refusal policy, not native returns.
The full admitted-domain proof, target digest, exact bytes, build commands and
frozen independent native expectations are in the
[evidence packet](../../research/work-items/RE-004-modulo-index-rust-94/README.md).
The library has no external dependency, Cargo workspace or invented lockfile;
the packet builds it directly with pinned rustc as an rlib and a real client.
