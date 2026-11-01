# node94 deep comparison

Independent MIT `no_std` value reconstruction of complete node94
`[0x51c0c00,0x51c0c18)`. It preserves the full RAX/RDX pair after
four ordered reads: SETB changes only AL, leaving the first deep
value's upper 56 bits intact, while RDX keeps the second loaded hop.
The readonly image allows arbitrary aliases and wrapped field-address
formation, with explicit range refusals. See the [proof](../../research/work-items/RE-004-deep-compare-rust-94/PROOF.md).

This dependency-free component builds directly with pinned rustc,
without an invented root workspace or lockfile. From repository root:

```sh
python3 -O -B research/work-items/RE-004-deep-compare-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/deep-compare-review
```

Use a fresh output directory and the recorded macOS aarch64 toolchain
for exact qualification. The input-only client reads 282-byte rows:
u64 `(image_base,first_object,second_object)`, u16 valid image length
0..256, then 256 backing bytes. It emits 17-byte rows `(status:u8,
RAX:u64,RDX:u64)`. Integers are little-endian. Error tags 1..5 follow
the public enum and use zero register placeholders. Incomplete rows
or oversized lengths are rejected before output; expectations never
enter the client. Only new Rust executes.
