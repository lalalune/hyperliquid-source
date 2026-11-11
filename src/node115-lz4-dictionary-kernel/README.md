# node115 LZ4 dictionary probe kernel

Independently authored MIT `no_std` Rust for one selected candidate probe in
Linux x86-64 node #115 (`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Evidence and repeatable qualification are in
`research/work-items/RE-012-lz4-dictionary-kernel-115/`.

`small_probe` accepts the caller's actual `[u16; 4096]`; `large_probe` accepts
`[u32; 4096]`. Both require an input position in the native outer loop's
`position <= source.len() - 12` domain. The safe adapter rejects any other
position before touching the table. No table initialization is invented.
The `origin` label describes the saved raw value added to the current source
position and subtracted from the old candidate; its original source type and
caller initialization remain unclosed.

The returned `Probe` exposes the selected bucket, previous cell, truncated
stored value, and a logical verdict. The table update occurs before candidate
rejection, including the native subtraction-failure boundary. Native opaque
failure-helper calls become explicit enums, not reconstructed panic objects.
`AbsoluteOverflow` occurs before hashing or mutation. A zero-distance candidate
can pass this local probe; no claim about subsequent compression follows.

The large arm hashes an eight-byte load but compares four candidate bytes.
The hash uses only the low five input bytes algebraically. This crate does
not implement initialization, skip stepping, match extension, offsets, token
emission, a full compressor, wire negotiation, or the native register/stack ABI.
It does not execute or emulate captured code. All full-scope gates remain false.

```
cargo +1.95.0 build --offline --locked --manifest-path src/node115-lz4-dictionary-kernel/Cargo.toml
python3 -B research/work-items/RE-012-lz4-dictionary-kernel-115/qualify.py
```
