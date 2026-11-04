# Node115 fee-rate MessagePack encoder

An independently authored, no_std, dependency-free encoder for four stored binary64 bit patterns. `encode_bits([u64;4])` returns 37 bytes: array4, then four float64 markers with big-endian words. It preserves all input bits; it assigns no fee units or field meaning.

The concrete caller, full selected helpers, frozen pre-Rust expectations and actual comparison results are in [the evidence packet](../../research/work-items/RE-005-node115-fee-rate-map-wire/README.md). This is not the captured serializer ABI or an integrated node. Decoder, allocation/unwind, helper behavior outside the concrete sufficient-capacity path and whole-ELF equivalence remain open.

Run `cargo test --locked --offline --manifest-path src/node115-fee-rate-map-codec/Cargo.toml` from the repository root. Native Windows tests use the already installed Rust 1.95.0 toolchain and explicit bundled ld.lld linker; the packet gives those flags. The verifier also builds a Linux rlib without executing captured code. No original machine bytes or unlicensed inferred Rust are used in this source.
