# RE-017 · Carry both #115 replay rounds into the first converted block

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

A first replay record can match the restored identity while the converter skips its ordinary output. The native worker initializes the expected record identity and conversion cutoff with the same restored consensus round. On a matching record it advances the expected identity before conversion. A prepared second-owner input count of zero takes the empty-record check. A successor strictly below the saturated cutoff plus 10 takes the skip path and retains the earlier cutoff. Equality converts. On the selected successful continuation, the converted successor is the next cutoff. The cutoff supplied to that conversion is the converted block's `parent_round`.

The previous [identity](../RE-017-node115-replay-record-identity/README.md), [empty record](../RE-017-node115-replay-empty-record-age/README.md) and [worker cutoff state](../RE-017-node115-replay-cutoff-state/README.md) packets establish these individual branches. This contribution adds the executable cursor and an offline wire integration test. The test supplies ten decoded quorum-parent replay records with present empty attachments and no hashes. It checks nine skips before the record at the exact threshold yields an archive parent round of 100 and a successor of 110. Additional fixtures cover a nonempty input, an unsigned saturation boundary, a mismatching identity, and a separate successor. The caller supplies the prepared owner's input count before row filtering. The selected continuation assumed by the model ends at the next cutoff. The integration uses synthetic rounds and stops before state application.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replay-conversion-cursor/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

The [raw offline log](offline-log.txt) records the pinned-byte verifier and crate tests.
