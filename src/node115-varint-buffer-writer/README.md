# node115 unsigned64 byte-vector writer

Independent MIT `no_std` + `alloc` Rust for the complete writer at ELF VA
`0x5822910..0x5822b90` in node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Evidence: `research/work-items/RE-005-varint-buffer-writer-115/`.

`write_u64(&mut Vec<u8>, value)` writes the minimal 1/3/5/9-byte representation:
0..250 inline, otherwise marker251+LE16, marker252+LE32, or marker253+LE64.
This appends actual bytes to a real `alloc::Vec`, not the existing size counter.

A marker is committed before the payload-capacity check. A refused payload
allocation leaves that marker and the caller's existing bytes present. The
implementation uses actual `Vec::try_reserve`; it does not preflight the entire
encoding or fake a vector. The native path calls its allocation-failure handler;
this safe API exposes `PrefixGrowth`/`PayloadGrowth` as boundary snapshots, not
a claim that the original returns errors or can resume after its fatal path.
Native pointer/Result/allocator ABI and higher-level serialization are open.

The host probe wraps the real System allocator, forwarding normal requests and
refusing only a selected alloc/realloc during the new Rust call. It verifies
actual vector bytes, length/capacity and request count, including partial-marker
snapshots. This controlled fault injection is not captured-node execution,
instruction emulation, a simulated Vec, or a claim of real resource exhaustion.

```
cargo +1.95.0 build --offline --locked --manifest-path src/node115-varint-buffer-writer/Cargo.toml
python3 -B research/work-items/RE-005-varint-buffer-writer-115/qualify.py
```
