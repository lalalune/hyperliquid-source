# node115-lz4-decode

Dependency-free safe Rust reconstruction of the logical-byte contract of one
node #115 size-prefixed LZ4 adapter. It decodes terminal literals, variable
length extensions and overlapping history matches, preserves observed error
category ordering, and checks announced capacity against a u64 maximum.
The size prefix is little-endian and is a capacity, not an exact output length.

```rust
use node115_lz4_decode::decode;
assert_eq!(decode(&[8, 0, 0, 0, 0x13, b'A', 1, 0, 0], 8), Ok(vec![b'A'; 8]));
```

Build: `cargo +1.95.0 test --locked --offline --manifest-path src/node115-lz4-decode/Cargo.toml`.
Requires a64-bit host; Rust1.95.0 is pinned. No external crate is used.

See [the packet](../../research/work-items/RE-012-lz4-decode-115/README.md)
and its manual proof for the native FDEs, target SHA, frozen cases, mutation
controls, helper premises and limitations. This is independently authored
from static binary evidence; no lz4_flex or unlicensed inferred source was
copied. The target embeds lz4_flex dependency code: this packet does not claim
it is a newly recovered private algorithm or add first-party byte credit.

No socket, async reader or native Vec/Result ABI is implemented. Scalar exact
copies replace native SIMD/wide-copy scheduling. Native error payloads and
uninitialized spare capacity are not reproduced. `ExtensionOverflow` reports
a captured panic boundary; `Allocation` is local allocator failure. Callers
must choose an appropriate maximum for their resource budget; actual input
processing remains offline in this contribution.
