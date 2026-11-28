# RE-017 · Select the archived #115 response variant for an offline fixture

The [post-block result fingerprint](../RE-017-abci-result-digest-115/README.md) establishes the periodic hash path and leaves the Full override lane open. The [archive response writer](../RE-017-node115-replica-response-source/README.md) emits the distinct `null`, `Hash`, and `Full` cases. This contribution binds the selected worker's final choice of those cases to the returned block height and callback mode, and exposes it in the existing Rust response writer.

The worker reads the returned height from the same slot it passes to the replica sink. Its selected periodic predicate is unsigned `height % 11 == 0`. At those heights it prepares the result fingerprint under tag 1. The other height path prepares tag 2. On the selected final sink continuation, the callback byte at `+0x6b8` equal to 1 instead forces tag 0 and copies the returned Full vector. Its 24-byte descriptor reaches the response field at the source consumed by the Full JSON writer. Other mode values keep the prepared tag, choosing `Hash` at the periodic heights and `null` elsewhere. The selected worker can prepare periodic data before the final override.

`select_response` selects the response from the independently supplied Full rows or matching result fingerprint. It reports a missing periodic fingerprint when the fixture needs one. The tests pass the selected values to the actual Rust JSON emitter. They verify one periodic height and both neighbors, the Full override at periodic and ordinary heights, and the distinction between a missing digest and `null`. The mode argument is the observed callback byte. The fixture makes no claim about CLI-to-callback configuration, sink enablement, root hashes, or output scheduling.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replica-response-policy/verify.py
cargo test --locked --offline --manifest-path src/node115-replica-response-json/Cargo.toml
```

The [raw offline log](offline-log.txt) records static path verification and fixture tests.
