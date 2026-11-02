# node94 tagged copy

Independent MIT, dependency-free `no_std` image reconstruction of the
complete node94 `[0x22155a0,0x22155c0)` leaf. It snapshots all 32 input
bytes before writing a tagged 40-byte result and returns the original
numeric output address. Every admitted bytewise input/output overlap
is supported. The [proof](../../research/work-items/RE-004-tagged-copy-rust-94/PROOF.md)
derives the full relation and distinguishes safe errors from native faults.

The component uses direct pinned rustc builds, without a fabricated
workspace or dependency lock. From the repository root:

```sh
python3 -O -B research/work-items/RE-004-tagged-copy-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/tagged-copy-review
```

Use a fresh output directory and the recorded macOS aarch64 compiler
and linker for exact qualification. The input-only client reads 154-byte
rows: three u64 `(image_base,source,destination)`, a u16 image length
0..128, then 128 backing bytes. Integers are little-endian. It emits 137
bytes: a status byte, raw RAX u64, then the complete 128-byte final image.
Tags 1/2/3 mean ImageRange/Input/Output and use zero RAX placeholders.
Malformed rows or oversized lengths are refused before any output.
The client never receives expected values; only newly authored code runs.
