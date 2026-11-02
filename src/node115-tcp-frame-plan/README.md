# node115 TCP frame plan

A dependency-free, safe `no_std` projection of one captured TCP reader's
complete-header policy: five-byte header, big-endian u32 length, inclusive u64
limit, flag exactly one selecting the post-read LZ4 route, and read intervals
capped at 4,000,000 bytes. It does not perform I/O, allocate payloads or decode LZ4.

Build and test with the installed pinned compiler:

```sh
cargo +1.95.0 test --locked --offline --manifest-path src/node115-tcp-frame-plan/Cargo.toml
```

The new Rust types are a scalar API, not the original future, Result, Vec or
native ABI. Inputs are a supplied complete header, current raw limit and
completed counter. Private read/allocator/codec effects, async states, logging,
timeouts, ownership, concurrent mutation and unwind remain unclosed. A zero
payload with flag one still selects the transform route; success is not implied.

Target-bound evidence and reproduction:
`research/work-items/RE-012-tcp-frame-plan-115/README.md`.
