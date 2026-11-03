# Node115 gossip response scalar record

RE-005 serialization with RE-012 caller context: a whole four-u64 record followed
by a one-byte optional marker and an optional fifth u64. The actual call comes
from the outer-present path of GossipRpcResponse variant2. This does not recover
the complete response, its other variants or network framing.

Unlike the existing precharged `Reader::read_four`, this record charges each
read separately, then1for the optional marker, then8for a present value. Failed
reads retain partial cursor/charge. Unknown optional markers consume their byte
before returning the projected native tag5/index. No trailing EOF check is added.
The diagnostic string names `Option<l1::node_types::round::Round>`; the safe API
uses an optional scalar without claiming the original Round ABI or field units.

The dependency is byte-identical MIT source at commit
`45e91f8499f1a78460407d235f580c1625f44d1a`, retained with LICENSE/original
manifest under research/imported/. `reader/Cargo.toml` is a local build adapter,
not a recovered original workspace. No registry dependency is introduced.

```
cargo fmt --manifest-path src/node115-gossip-response-record/Cargo.toml --all -- --check
cargo build --offline --locked --manifest-path src/node115-gossip-response-record/Cargo.toml --all-targets
cargo test --offline --locked --manifest-path src/node115-gossip-response-record/Cargo.toml --lib
cargo test --offline --locked --manifest-path src/node115-gossip-response-record/Cargo.toml --release --lib
cargo clippy --offline --locked --manifest-path src/node115-gossip-response-record/Cargo.toml --all-targets -- -D warnings
python3 tools/gossip_response_record.py
python3 tools/gossip_response_record_rust.py --rustc /absolute/path/to/rustc --output work/response-record-check
```

Recorded compiler: Rust1.95.0. Windows gnullvm comparator builds require
`--linker /absolute/path/to/rust-lld.exe`; Cargo requires that linker plus
`-Clinker-flavor=ld.lld -Clink-self-contained=yes` in RUSTFLAGS. The comparator
also builds Linux x86_64 rlibs using already installed target libraries; it never
downloads a target. Use operator-owned Cargo cache/target and output directories.

Probe input is four TSV columns: mode0unlimited/1limited, initial charged u64,
limit u64, hexadecimal bytes (`-` for empty). Expected results are not sent to
it. Output is record/error label, consumed bytes and resulting charge. On a
successful None field the final value label is `-`. The API returns the actual
remaining slice on every exit. See the task packet for identities, the pre-Rust
freeze commit, full native closure, negative controls and limitations.
