# RE-017 · Check decoded #115 replay attachment fixtures

The wire decoder exposes a Block's header digest vector and its optional attachment rows. Use the new `DecodedPrefix::check_attachment_fixture` before treating a decoded Block as having the necessary prepared inputs for offline replay. It checks the Keccak-256 digest of each attachment byte span against the digest carried by that row, then checks the row count and the position of every digest in the Block vector. It returns the prepared attachment count when those checks pass. The implementation reuses the existing pure-Rust Keccak-256 function.

A present owner retains its rows. When the owner is absent and the Block vector is empty, the selected native handoff supplies an empty owner. If the Block names digests and the owner is absent, the fixture needs the reconstructed owner before it can run these checks. The test decodes a two-row fixture with independently pinned content digests for `abc` and the empty input. Other fixtures distinguish the empty handoff from missing data and check content, count and position diagnostics.

The selected [owner handoff](https://github.com/lalalune/hyperliquid-source/pull/7273) and [ordered native attachment comparison](https://github.com/lalalune/hyperliquid-source/pull/7307) supply the previously traced native facts. This result joins those facts to the decoded fixture. The fixture check stops before native block processing and only hashes attachment contents.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replay-attachment-fixture/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

The [raw offline log](offline-log.txt) contains the verified target windows, content vectors and crate tests.
