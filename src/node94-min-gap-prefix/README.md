# node94 min-gap prefix equality

This independent, safe `no_std` component reconstructs the complete
`[0x5430db0,0x5430e07)` helper using actual bytes from a readonly image.
It returns full numeric RAX (0 or 1). The original call is bound through
its real `memcmp` PLT/GOT/symbol/version records; correspondence assumes
a standard ABI-conforming, readonly, normally returning memcmp. No
fabricated helper result is accepted by the API.

```rust
pub fn compare(
    image: &[u8], image_base: u64, a: u64, b: u64,
) -> Result<u64, AccessError>;
```

Each object stores a pointer at offset 0 and a u64 length at offset 8.
Lengths are read first. A zero minimum skips both pointer fields;
otherwise the complete minimum-length byte spans must be admitted,
even if the final length ordering rejects. All readonly aliases are
supported within one nonwrapping image. Error variants describe new
checked admission, not original faults. The library allocates nothing,
forbids unsafe code and imposes no arbitrary count cap.

The [proof](../../research/work-items/RE-004-min-gap-prefix-rust-94/PROOF.md)
derives full-u64 behavior, all read gates, the signed-gap reduction,
external premise and ABI limits. Exact build and qualification use the
actual pinned aarch64-apple-darwin rustc 1.94.1 executable:

```sh
python3 -B research/work-items/RE-004-min-gap-prefix-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/min-gap-prefix-rust/replay
```

Use a fresh output directory. The recipe builds opt0 and opt3 directly,
with overflow checks enabled and warnings denied. No Cargo workspace,
dependency resolution or captured execution is needed. The separate
input-only std client consumes 282-byte little-endian records: three
u64 values `(image_base,a,b)`, a u16 admitted length 0..256, and 256 backing
bytes. It emits a status byte and u64 result. Error tags 1/2/3/4 denote
ImageRange/Lengths/Pointers/Bytes and use zero as a placeholder.
Malformed records are rejected before output. Raw command streams are
checkpointed losslessly in one compressed archive, avoiding duplicate
per-command binary files on disk.
