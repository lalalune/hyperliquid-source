# Noop serializer prefix to bounded inner digest

Partial progress on [#3912](https://github.com/lalalune/hyperliquid-source/issues/3912).
This contribution resolves the writer-produced Noop prefix and follows the
complete short preimage into its selected absorb/finalize path. It adds owned
Rust producing both the bytes and the 32-byte inner digest. No component gate
or full signing/action-acceptance claim is changed.

## Target and method

Original Linux x86-64 node #115 ELF, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The verifier retains 17 selected windows, 2,367 instruction bytes and 593
instructions; 125 explicit field/call/branch/table/literal facts are checked.
Twenty semantic corruptions are rejected with whole-image/window hash checks
bypassed, so a changed semantic fact must detect each corruption. Capstone
5.0.7 decodes from the enclosing FDE boundaries. No captured instructions are
executed or emulated. The counts include credited prerequisites.

## Complete selected prefix

The outer owner is `0x36aa9a0..0x36aade6`. It initializes an empty byte writer,
passes configuration `0x01000400`, and invokes `0x36b1600`. The native action
discriminant `0x86` selects the signed table entry at `0x799f5c`, which resolves
to `0x36b162a`. This branch binds exact four-byte literals `type` and `noop`
and calls `0x471c040` through the shared continuation at `0x36b3a7b`.

The complete successful byte path is:

| Stage | Bound observation |
| --- | --- |
| Map header | `0x471c067` supplies count 1 to `0x3d4f6d0`; the selected fixed-map path and marker helper `0x3d52310` append `0x81`. |
| Pair writer | `0x471c093..09f` passes the two literal pointers and lengths to `0x41b1ac0`. Its sentinel path calls `0x41c6110` for the key, then the value. |
| String header and bytes | Length 4 selects marker `0xa0`; `0x3d52310` combines it with the low five length bits to produce `0xa4`. `0x41c643a` binds to imported `memcpy` and appends the four original literal bytes. |
| Finalization | The streaming sentinel makes `0x41aba50` return success without adding bytes. `0x36aaa05` accepts the resulting `0x8000000000000004` tag. |

Thus the new prefix is exactly `81a474797065a46e6f6f70`. `NoopAction` and the
diagnostic variant name are not emitted by this selected path. Reallocation
and ordinary byte-copy behavior remain successful-helper premises; their
allocation failure and unwind ABI are not reconstructed.

## Suffix and one-block digest

The previously mapped suffix appends the big-endian nonce, exact vault
presence tag and optional 20 bytes, then the optional zero marker and
big-endian expiry. The typed API admits only valid absent/present states.
The four total lengths are 20, 29, 40 and 49 bytes.

At `0x36aab2a..0x36aabeb`, the owner initializes zero lanes/cursor, rate 136,
domain byte 1, and an unsqueezed flag. The complete pointer and length go
through slot `0x64e0148` to `0x5cda910`. These short inputs take the path with
no permutation during absorption: the selected vector, word and byte loops
XOR exactly the input bytes into the state and publish its length at `+0xc8`.

The owner then calls `0x5cdad40` through `0x64e0150` with output length 32.
The unsqueezed path XORs domain byte 1 at the absorbed length, XORs `0x80` at
rate-minus-one (135), and invokes the relocation-bound permutation
`0x5cda380` exactly once. Since 32 is less than 136, it copies the first 32
state bytes without a further permutation. The new source converts byte
lanes explicitly as little endian and reuses the existing permutation.

This closes only the four short-input shapes produced here. Other action
serializers, streaming updates, rate changes, multiple-block squeezing and
the outer domain/signature chain remain outside scope.

## Prior work and overlap

`RE-005-node115-rmp-signable-layout`, including the correction in
[PR #2656](https://github.com/lalalune/hyperliquid-source/pull/2656), already
maps the suffix and exact optional-field guards. It leaves the initial writer
opaque. `RE-001-node115-signable-preimage-append` supplies related append
context. Those suffix findings are prerequisites, not new discoveries.

`RE-017-abci-result-digest-115` identifies the selected digest helpers and
rate/domain observations in a different caller. `RE-009-sponge-permutation-115`
provides the existing independent MIT permutation and its prior evidence.
This contribution reuses that source unchanged, SHA-256
`54d751f5d2366fdba907838d5980826b6fd48c3764adf338c55c13a950a6e0f8`.
Historic target evaluators are not rerun; the new checks are static and owned
Rust tests with a separate OpenSSL comparison.

Terra screened current main, the 396-open-PR title/body inventory, related
packets and targeted all-state searches for the Noop preimage and selected
writer addresses. No competing scoped implementation was found. Historical
metadata searches do not prove every unindexed closed patch was inspected.

## Reproduction and limits

```sh
python3 research/work-items/RE-001-node115-noop-preimage/verify.py
python3 research/work-items/RE-001-node115-noop-preimage/compare-openssl.py
cargo +1.95.0 test --offline --manifest-path src/node115-noop-preimage/Cargo.toml
cargo +1.95.0 test --offline --release --manifest-path src/node115-noop-preimage/Cargo.toml
cargo +1.95.0 clippy --offline --manifest-path src/node115-noop-preimage/Cargo.toml --all-targets -- -D warnings
```

The static verifier needs Capstone 5.0.7 and the audited repository ELF helper.
Four Rust tests and all 64 independent OpenSSL 4.1.0 `KECCAK-256` comparisons
pass. The vector inputs are synthetic; the digest reference uses no keys.
OpenSSL must expose that algorithm to rerun the optional independent check.
The Rust crate has only the unchanged local permutation dependency.

Valid native representations, ordinary successful allocation/copy and normal
helper returns are premises. This proves no wire decoder, live action,
authorization, nonce policy, signature, private key behavior, deployed network
identity or native runtime equivalence. Full `make test` is not run because
its unfiltered discovery includes captured-instruction emulation outside this
work's authorization. Issue #3912 remains open.
