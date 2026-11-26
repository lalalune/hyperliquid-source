# Node 115 bounded Gossip response composition

This offline prefix API joins existing MIT decoders under the original response
parent's observed raw outer tags. Tag 1 calls the address-vector child; tag 0
reads a nested Result tag and routes tag 1 to ClientBlocksError; tag 2 uses the
existing option/record envelope. For nested success tag 0, unlimited mode now
decodes the structural ClientBlocks payload with the separately qualified
`node115-client-block-success` parser. Limited mode retains an explicit
`ResultSuccessBoundary`: charge behavior inside that payload is not yet closed.
The API reports logical active values, remaining bytes and the charge observed
at the return/boundary, not native ABI or network behavior.

The old address-vector and ClientBlocksError packet READMEs used opposite
outer-tag labels. Their inner APIs start after those tags and remain unchanged;
see the correction notes in those packets and the new evidence packet. Existing
inner decoding remains credited to #2795, #2790 and #2784; the u32 reader is
reused from `src/node115-u32-varint`. No component-completion gate changes.

The vector crate and response record reader adapter use separate path packages
with the same name/version; this crate uses the existing unchanged MIT vector
source as a module and links all decoders to the response reader adapter. The
success parser now uses that same reader adapter through its path dependency.
The adapter source and original vector source remain byte-identical at the
pinned base (SHA-256 `fd6afd281a93e28074d355f28306c340bb88c2f492ebc3501a879874d65c4cb2`).
No existing source or historical manifest is rewritten.

The nested success decoder is structural and unmetered. It establishes the
remaining slice for successful unlimited inputs; it does not establish the
limited-mode charge/error ordering within the full ClientBlocks graph. In that
mode, the composition stops at `ResultSuccessBoundary` after consuming the
outer and nested tags. Structural child errors are returned as projected Rust
errors, not claims of native error-ABI equivalence.

Run with an existing Rust 1.95 toolchain:

```sh
cargo +1.95.0 test --locked --offline --manifest-path src/node115-gossip-response-composed/Cargo.toml
```
