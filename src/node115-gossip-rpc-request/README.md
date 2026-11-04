# Node115 GossipRpcRequest logical prefix decoder

Task RE-005 / serialization, with RE-012 gossip context. This independently
written `no_std` decoder models one established request-prefix relation. It is
not a whole-node codec or the original Rust ABI. See the evidence packet at
`research/work-items/RE-005-node115-gossip-rpc-request/README.md`.

The scalar u64 reader is byte-identical MIT source at commit
`45e91f8499f1a78460407d235f580c1625f44d1a`, with its original manifest and
LICENSE under `research/imported/node115-reader-<commit>/`. `reader/Cargo.toml`
is only a local build adapter; it adds no implementation. No reader-primitive
reconstruction credit is claimed by this change.

```
cargo build --offline --locked --manifest-path src/node115-gossip-rpc-request/Cargo.toml --all-targets
cargo test --offline --locked --manifest-path src/node115-gossip-rpc-request/Cargo.toml --lib
python3 tools/gossip_rpc_request.py
python3 tools/gossip_rpc_request_rust.py --rustc /absolute/path/to/rustc --output work/gossip-request-check
```

Rust1.95.0 is pinned for the recorded build. On Windows gnullvm pass
`--linker /absolute/path/to/rust-lld.exe` to the Python comparator; for Cargo,
set the linker plus `-Clinker-flavor=ld.lld -Clink-self-contained=yes` in
`RUSTFLAGS`. Keep caches/target directories in operator-owned storage. The
comparator requires installed Linux target libraries for its Linux rlib checks;
it never downloads them. Captured binaries are only read and authenticated.

Probe input is four TSV columns: mode(0unlimited/1limited), charged u64, limit
u64, hexadecimal bytes (`-` for empty). Expected outputs are never sent to the
probe. Output is value/error label, consumed byte count, resulting charge.
`decode_prefix` returns the actual remaining slice, including on errors. The
fixed cases cover all256 first-byte classes, short/fast thresholds, marked
truncations, nonminimal encodings, both payload positions, invalid variants,
limit stores and u64 count overflow. Field names/units beyond `first/second`
are unknown. Unit variants and successful two-value requests retain suffixes.
