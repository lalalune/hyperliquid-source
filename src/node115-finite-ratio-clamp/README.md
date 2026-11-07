# Node115 finite-ratio clamp

Independently authored MIT `no_std` logical projection of the 148-byte leaf at
`0x14ca350..0x14ca3e4` in Linux x86-64 node #115. The target digest, complete
instruction walk, constants, caller references, and static verifier are in
[`research/work-items/RE-001-node115-finite-ratio-clamp/README.md`](../../research/work-items/RE-001-node115-finite-ratio-clamp/README.md).

`project_ratio` accepts and returns raw binary64 bits. It preserves the
observed RAX result and XMM0 low-lane bits, including early-return inputs,
clamping, division overflow, and signed zero. The frozen test vectors are
copied from the packet's binary-grounded `records.json`; they are not
generated from this Rust implementation.

This crate assigns no source name, financial units, original ABI, or field
ownership. It is not integrated into clearinghouse or vault code: caller
production ranges, units, result consumers, and floating-point environment
must be traced before such an integration is justified. The source project has
no recovered root Cargo workspace. No captured binary is executed or emulated.

Run `cargo test --offline --locked` in this directory. The crate has no
external dependencies.
