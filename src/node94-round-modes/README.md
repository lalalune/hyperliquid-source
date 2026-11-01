# node94 round helper with explicit target RC

Independent `no_std` Rust for the low returned binary64 bits of node #94
ELF VA `0x565f410..0x565f481`. `round_bits(bits, RoundingMode)` takes a new
explicit value parameter for target MXCSR.RC; it does not inspect host state.

The target adds a same-sign `(0.5 - 2^-54)` before truncating. Nearest-even
addition yields half-away integer rounding, but other modes can round exact
halves toward zero or increase already-integral large values. Signaling NaNs
are quieted while preserving sign/payload. The API assumes masked SIMD
exceptions and models no flags, traps or upper XMM lanes.

No third-party dependency, Cargo manifest, build hook or root workspace is
needed for this direct rustc component. Actual qualification uses rustc
1.94.1, edition 2024, native aarch64-apple-darwin, opt0/opt3, overflow checks,
one codegen unit, panic=abort and warnings denied. A standalone build is:

```sh
rustc +1.94.1 --edition=2024 --crate-name node94_round_modes --crate-type rlib \
  -D warnings -C codegen-units=1 -C panic=abort -C overflow-checks=yes \
  -C opt-level=3 src/node94-round-modes/lib.rs -o /tmp/libnode94_round_modes.rlib
```

See `research/work-items/RE-004-round-modes-rust-94/` for the complete static
proof, frozen exact-rational oracle, input-only client, raw native results,
negative controls and compiler/linker identities. No target machine-code or
whole-node equivalence is claimed.
