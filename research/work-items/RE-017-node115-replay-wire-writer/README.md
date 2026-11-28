# RE-017: Encode node #115 replay payload prefixes

The offline replay codec could read a Block or Tx prefix. The companion Rust encoder now writes the
same envelope from the existing decoded types. A Block emits its signature,
header and optional commit proof, then an independent attachment option. A
present empty vector emits both its presence byte and an explicit zero count.
A Tx emits a length-prefixed opaque byte slice.

The native target is Linux x86-64 node #115. The verifier authenticates the
digest, checks the writer FDE at `0x4fb5ce0`, the three Block child calls and
the two raw attachment option writes, and re-runs the established decoder
witness. The count and write paths are described in the [native writer analysis](https://github.com/lalalune/hyperliquid-source/pull/7274). The implementation uses the already qualified compact u64
writer. It reconstructs the Unix timestamp from the decoder's packed date
and validates that the decoded clock words survive a full admission round
trip before writing ZigZag seconds and unsigned nanoseconds.

Tests compare writer output with pre-existing fixed wire fixtures for
absent, empty, and populated attachments. A separate nested fixture
exercises timeout/QC children, commit proof and attachment bytes. A blob
length of 251 exercises a widened compact prefix. Invalid packed timestamp
flags are rejected. No captured instructions run.

Only the selected wire prefix is modeled. This change does not encode
transport headers or compression, infer a live record's source, verify
signatures or compare state roots.

```sh
python3 -B research/work-items/RE-017-node115-replay-wire-writer/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-wire-encoder/Cargo.toml
cargo clippy --locked --offline --all-targets --manifest-path src/node115-replay-wire-encoder/Cargo.toml -- -D warnings
```

[Real offline output](offline-log.txt)
