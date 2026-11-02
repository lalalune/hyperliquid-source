# node94 two-stream mixer

A dependency-free `no_std`, safe Rust slice/value reconstruction of node #94
ELF VA `0x16488e0..0x1648946`. The descriptive name does not identify a hash
algorithm. This is different from `node94-keyed-mix` at `0x399c600`.

```rust
use node94_two_stream_mixer::two_stream_mix;

let mut bytes = [0; 16];
bytes[..8].copy_from_slice(&1u64.to_le_bytes());
bytes[8..].copy_from_slice(&2u64.to_le_bytes());
assert_eq!(two_stream_mix(&bytes, 5, 3, 0), 6);
```

Arguments are `(input, seed_b, seed_a, key)`, preserving the observed RDX/RCX
seed order. All reads are little-endian. Short slices return the seed xor.
For length at least 16, each of `ceil(len/32)` rounds reads 16 bytes from the
front and 16 from the back; reads can overlap and are not rounded to aligned
chunks. Both halves of each unsigned 128-bit product contribute.

The relation to the native body assumes a valid nonwrapping mapped buffer.
The API accepts the slice's actual length; it has no raw length register,
native pointer ABI, bit-63 length variant or wrapped-address behavior. The
library has no allocation or dependencies; the separate input-only CLI uses
`std` for the offline verification protocol.

From the repository root, with Rust 1.94.1 on PATH:

```sh
cargo +1.94.1 build --offline --locked --manifest-path src/node94-two-stream-mixer/Cargo.toml
python3 research/work-items/RE-001-two-stream-mixer-rust-94/verify.py --out work/two-stream-verification
```

The verifier defaults to the observed macOS tool paths; use `--rustc`,
`GNU_OBJDUMP` and `LLVM_OBJDUMP` to select installed tools elsewhere. The output
directory must be fresh and under the repository. Only newly authored Rust
runs. [The evidence packet](../../research/work-items/RE-001-two-stream-mixer-rust-94/README.md)
contains the static proof, frozen oracle corpus, controls and limits.
