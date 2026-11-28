# RE-017 · Check adjacent #115 retained replay links against offline references

Use `retained_batch::check_continuity` when a fixture has independently acquired Block-link references for consecutive retained replay records. Each row supplies its selected incoming identity and successor. For rows after the first one, the check also requires the incoming predecessor observation and the preceding row's same-kind 32-byte Block fingerprint. The API reports the first failed comparison or missing observation, with zero-based row coordinates. The last row's own fingerprint can be absent when only the supplied batch needs checking.

The prior [retained batch trace](https://github.com/lalalune/hyperliquid-source/pull/7306) anchors the first identity at replay future `+0x110` and the first descriptor's absent predecessor. For later rows, the selected successor of the previous accepted owner becomes the expected identity. The following descriptor has a predecessor present flag and a 32-byte output copied from the previous owner path. The validator checks identity first, then compares both halves of the predecessor when present. The selected successor basis can differ from the incoming identity on timeout parents.

The [decoded parent projection](https://github.com/lalalune/hyperliquid-source/pull/7424) supplies the incoming identity and raw predecessor bytes for an ordinary decoded fixture. The model takes the corresponding previous fingerprints as explicit input. Source or archive SHA-256, state roots, and attachment digests have separate meanings. The fixture checker has no digest generation or native block acceptance stage. Tests use synthetic offline observations and check nonconsecutive identity values, unresolved predecessor data, and independent mismatches in each half of a link.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-retained-batch-fixture/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

The [raw offline log](offline-log.txt) records the pinned verifier and tests.
