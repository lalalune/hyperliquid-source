# Node94 tag-dispatched store

This safe dependency-free `no_std` component reconstructs the complete
`[0x5057700,0x505773d)` leaf over a mutable numeric-address image.

```rust
pub fn store(
    image: &mut [u8], image_base: u64, load_bias: u64,
    destination: u64, source: u64, tag: u64,
) -> Result<u64, AccessError>;
```

The low 32 tag bits choose an eight-byte linked-address value (0), an
eight-byte raw source value (1), a sixteen-byte source snapshot (2),
or no memory access (other values). Every successful path returns full
RAX=0. The load bias is independent of the image base; linked-address
contents are never read. Arbitrary partial copy overlap is supported.
New checked refusals preserve the entire image.

The [proof](../../research/work-items/RE-004-tag-store-rust-94/PROOF.md)
states the complete image/ABI domain, read gates, address metadata,
snapshot argument and limitations. Qualification uses pinned actual
aarch64-apple-darwin rustc 1.94.1:

```sh
python3 -B research/work-items/RE-004-tag-store-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/tag-store-rust/replay
```

Use a fresh output directory. Direct opt0/opt3 builds enable overflow
checks and deny warnings. No Cargo workspace or dependency resolution
is required; only newly authored host programs execute.

The separate input-only client consumes 106-byte little-endian records:
five u64 values `(image_base,load_bias,destination,source,tag)`, a u16
admitted length 0..64 and 64 backing bytes. Output is 73 bytes: status,
u64 RAX and all 64 final backing bytes. Error tags 1/2/3 denote ImageRange,
Source and Destination, with a zero RAX placeholder. Malformed records are
rejected before output. Native raw streams are checkpointed losslessly
in a gzip archive at compression level 1, mtime 0.
