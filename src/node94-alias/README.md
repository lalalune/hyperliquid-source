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
The constructor's admitted inline route is exposed separately below. No full
constructor, cache, allocator, lock, wire format, target Rust ABI or whole node
is implemented. Short inputs to `alias10` still test the producer only; the
constructor selects the inline route for those lengths.

## Inline carrier

`inline_carrier(input: &[u8]) -> Option<u128>` implements only the native
constructor's length-at-most-16 route through packer `0x144a010..0x144a069`.
It places input byte i at bits `8*i..8*i+7`. The low 64 bits project RAX and
the high 64 bits project RDX; empty input returns zero. Embedded and trailing
zeros are preserved as bytes, while the integer carrier has no separate length:
`A` and `A\0` therefore produce the same carrier. This is not a string-identity,
UTF-8 validation, display or wire-format claim.

Inputs longer than 16 return `None` in this chosen API. The native constructor
takes its unimplemented long/cache route instead; this is not a native error
or alias-constructor implementation. The existing `alias10` hash API is unchanged.

The [inline-carrier evidence packet](../../research/work-items/RE-001-inline-carrier-rust-94/README.md)
credits the earlier native discovery, binds complete constructor/packer bodies,
the admitted guards and the unique recursive/tail-call slot. Its 156 native
rows, including every one-bit position, and two API-only refusal rows were
frozen before the new Rust source. No captured instruction evaluator runs in
this follow-on. Its input-only compiled comparison and source controls are
separate from the older feed/alias reconstruction runner below.

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
