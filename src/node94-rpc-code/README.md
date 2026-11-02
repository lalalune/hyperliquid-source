# Raw RPC-context code classification

The 533-byte owner at ELF VA `[0x15bb930,0x15bbb45)` classifies the raw ESI word and stores its kind at output +0x30 and original raw code at +0x34. This module implements only those selected numeric results, using a newly chosen `Classification` interface.

The mapping is -32700→0, -32007→1, -32600→2, -32601→3, -32602→5, -32603→6, otherwise 7, interpreted as raw u32 two's-complement words. No kind 4 is emitted by this selected path. The original raw u32 is retained unchanged. No named enum or original output layout is assigned.

The captured wrapping addition by 32603 is a bijection on u32. Indexes 0..3 therefore have exactly four preimages, distinct from the two explicit singleton comparisons; all other words take the default. This finite partition argument is not exhaustive native execution. Upstream JSON number admission/narrowing, optional-data serialization, allocation, 24-byte copies and full error-constructor/caller closure remain excluded.

## Build and validate

This independently authored safe `no_std` module has no dependencies, build scripts, Cargo workspace or lockfile. It is built directly with research rustc 1.94.1, edition 2021, warnings denied and overflow checks on. The compiler pin is not a recovered full-node build recipe.

```sh
python3 -B research/work-items/RE-012-rpc-code-rust-94/verify.py --rustc /path/to/rustc-1.94.1 --output work/node94-rpc-code-new --controls
```

Use a new output directory. The runner authenticates node #94 and rechecks the [existing static evidence](../../research/work-items/RE-001-rpc-code-classifier-94/README.md), then compares 135,171 cases against three own Rust builds and detects 5 compiled semantic mutants. No original machine-code equivalence is claimed. See the [implementation packet](../../research/work-items/RE-012-rpc-code-rust-94/README.md) for evidence, actual results and limits.
