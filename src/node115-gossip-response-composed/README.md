# Node 115 bounded Gossip response composition

This offline prefix API joins three existing MIT decoders under the original
response parent's observed raw outer tags. Tag 1 calls the address-vector
child; tag 0 reads a nested Result tag and routes tag 1 to ClientBlocksError;
tag 2 uses the existing option/record envelope. A nested success tag 0 yields
an explicit `ResultSuccessBoundary`, with its payload unconsumed. That boundary
is not a complete decoded response. The API reports logical active values,
remaining bytes and charge, not the native ABI or network behavior.

The old address-vector and ClientBlocksError packet READMEs used opposite
outer-tag labels. Their inner APIs start after those tags and remain unchanged;
see the correction notes in those packets and the new evidence packet. Existing
inner decoding remains credited to #2795, #2790 and #2784; the u32 reader is
reused from `src/node115-u32-varint`. No component-completion gate changes.

The vector crate and the response record's reader adapter each have a separate
path package named `node115-u64-reader-state` version 0.1.0, which Cargo cannot
place together in one lockfile. This crate uses the existing, unchanged MIT
vector source as a Rust module and links it against the response reader adapter.
The adapter source `research/imported/node115-reader-45e91f8499f1a78460407d235f580c1625f44d1a/lib.rs`
and the vector's original `src/node115-u64-reader-state/lib.rs` are byte-identical
at base 7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6 (SHA-256
`fd6afd281a93e28074d355f28306c340bb88c2f492ebc3501a879874d65c4cb2`).
This local composition does not change those historical manifests or source.

Run with an existing Rust 1.95 toolchain:

```sh
cargo +1.95.0 test --locked --offline --manifest-path src/node115-gossip-response-composed/Cargo.toml
```
