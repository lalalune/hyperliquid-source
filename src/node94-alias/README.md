# Node #94 alias contract

This is an independently authored, dependency-free Rust implementation of one
bounded observed contract. `AliasFeed` streams bytes and returns the observed
64-bit final hash. `alias10` returns the ten letters for the input, `ff`, and
the four-byte little-endian counters 0 through 9. It uses fixed-size state and
output, with explicit wrapping arithmetic and no unsafe code or allocation.

The source is derived from authenticated node #94 instructions, not the
unlicensed inferred reference. The exact target, full FDEs, equations, native
disassembly, byte controls and remaining gaps are in
[`RE-001-short-string-alias-94`](../../research/work-items/RE-001-short-string-alias-94/README.md).
No constructor, cache, allocator, lock, wire format, target Rust ABI or whole
node is implemented. Short inputs test the producer only: the constructor
routes inputs of at most 16 bytes through a different path.

## Check

From the repository root, with the existing Rust/Cargo toolchain and authenticated
LFS inputs, GNU binutils and LLVM disassembler available:

```sh
cargo test --locked --offline --manifest-path src/node94-alias/Cargo.toml
cargo test --release --locked --offline --manifest-path src/node94-alias/Cargo.toml
make alias-rust
```

The first two commands compare the committed observations with the actual Rust
code. `make alias-rust` first regenerates every expectation from the authenticated
instructions and refuses any changed fixture. It checks both build profiles,
two clean release builds and eight compiling Rust-source mutations that must
fail the comparisons. Cargo uses `--locked --offline`; there are no registry
dependencies or build scripts. Run normal repository checks as documented in
the evidence packet too.

`evidence/contract-vectors.txt` contains 78 aliases, 780 complete counter hashes,
and 264 split-feed sequences with all 1,056 intermediate states. Empty chunks
are `-`. State words use logical order `v0,v1,v2,v3`, not the target's memory
order. Only the explicit command below replaces this target-derived file:

```sh
python3 tools/short_string_alias_rust.py --write-vectors
```

These are finite static comparisons, not observed captured-program outputs.
The Rust library runs on the recorded host; node #94 is never launched. Two
equal Rust library builds do not establish target-code identity or close any
component gate. No speed improvement or cryptographic property is claimed.
