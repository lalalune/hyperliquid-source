# RE-017: Receive-round classification for completed replay Blocks

This composes the [decoded certificate layout](../RE-017-node115-replay-parent-projection/README.md)
with the [native receive comparison](https://github.com/lalalune/hyperliquid-source/pull/7266)
and its [initial baseline](https://github.com/lalalune/hyperliquid-source/pull/7270).
It gives the offline fixture a way to distinguish older, equal, and gap
cases after a completed Block passes identity checks.

| Parent | Incoming successor basis | Parent comparison round |
| --- | --- | --- |
| Direct QC | QC third scalar | QC third scalar |
| Timeout, no optional QC | Leading Timeout scalar | Embedded QC third scalar |
| Timeout, optional QC | Leading Timeout scalar | Optional QC third scalar |

The incoming and buffered-tail successor increments saturate. An empty
receive buffer uses the caller's restored round. A nonempty one uses the
newest buffered Block's own successor. The comparison is unsigned; the
incoming successor is a separate diagnostic value. The typed Rust
interface does not model invalid native owners, attachment normalization,
gap fetching, signatures or actual block execution.

Target Linux x86-64 node #115, SHA-256 printed by the independent ELF
verifier. Fixed test cases deliberately set the timeout, optional and
embedded QC scalars to different values. Tail and startup inputs differ
in the saturation case. No captured instructions are executed.

```sh
python3 -B research/work-items/RE-017-node115-replay-receive-order-projection/verify.py
cargo test --offline --locked --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

[Raw offline run](offline-log.txt)
