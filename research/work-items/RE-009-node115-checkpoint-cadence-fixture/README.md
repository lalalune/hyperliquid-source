# RE-009: Initialize offline replay root eligibility from checkpoint cadence

The bounded checkpoint-to-replay fixture already accepts a materialized
root divisor. A caller with the raw checkpoint field needs the selected
decoder's default before using it. The
[MessagePack reader](../RE-009-node115-checkpoint-root-cadence/README.md)
and [JSON reader](../RE-009-node115-json-root-cadence/README.md)
establish that a missing or zero `aci` in the selected ExchangeMisc
visitor supplies 1,000, while a nonzero input reaches the live divisor
unchanged.

`ReplayEngineFixture::from_checkpoint_cadence` applies that normalization
before calling the existing materialized-state constructor. It assumes
the required containing ExchangeMisc object has already been found.
The existing constructor remains usable for fixture inputs that are
already materialized.

The test starts from a synthetic completed checkpoint at 999 and supplies
the same first replay Block at 1,000 to four cases. Missing, explicit zero
and explicit eight reach the existing local raw history path. Seven does
not. Since 1,000 is not divisible by 10,000, the independent built-in
trigger does not explain the result. The digest itself is supplied by
the test. This validates cadence integration, without computing a real
checkpoint or replay digest.

```sh
python3 -B research/work-items/RE-009-node115-checkpoint-cadence-fixture/verify.py
cargo test --locked --offline --manifest-path src/node115-abci-checkpoint-replay-fixture/Cargo.toml
```

[Raw offline output](offline-log.txt)
