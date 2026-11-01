# node94 endpoint gate

Independent MIT Rust value reconstruction of the complete node94 leaf
`[0x3cd2460,0x3cd2490)`. `gate` returns full numeric RAX/RDX and preserves
the span even when the byte/limit gate returns zero RAX. It reads only
reached endpoint bytes and admits wrapped effective addresses through a
checked, nonwrapping readonly image. See the [proof](../../research/work-items/RE-004-endpoint-gate-rust-94/PROOF.md)
for the exact domain, all paths and new safe refusals.

This dependency-free `no_std` library is built directly with pinned rustc;
there is no invented root Cargo workspace or dependency lock. From the
repository root, the complete reproducible build and qualification is:

```sh
python3 -O -B research/work-items/RE-004-endpoint-gate-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/endpoint-gate-review
```

Use a fresh output directory and the recorded aarch64 macOS toolchain for
the exact compiler/linker qualification. Other host compilation is not
claimed here. `input_only_driver.rs` takes fixed 49-byte little-endian
rows: five u64 values `(image_base,base,start,end,limit)`, one length byte
0..8, and eight backing bytes. It emits one tag byte and two u64 values
`(RAX,RDX)`; tags 1/2/3 mean ImageRange/Start/End and use zero placeholders.
It never receives expected outputs. Incomplete rows or oversized lengths
are refused before any output. The target is never executed.
