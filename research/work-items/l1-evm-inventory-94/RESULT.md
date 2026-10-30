# Result: node #94 l1/evm execution census

Target SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Under the documented relocated Location layout and direct `l1/src/evm/*.rs` path rule, there are **10 records**, **18 reviewed LEA sites**, and **11 distinct containing FDE ranges**. They are not a function coverage denominator.

| Path basename | Location records |
| --- | ---: |
| evm_db.rs | 3 |
| evm_state.rs | 1 |
| hash.rs | 1 |
| hyper_evm.rs | 4 |
| transactor.rs | 1 |

The [JSON](l1-evm-inventory.json) and [raw excerpts](excerpts.txt) enumerate every Location, line, column, referencing instruction and containing FDE. Separate records with identical hyper_evm line and column are retained. At VA `0x32fc267`, bytes `e8 54 d7 f6 ff` decode as a direct rel32 call from the `evm_db.rs` Location-associated FDE `[0x32fc190,0x32fc55d)` to the start of the `hash.rs` Location-associated FDE `[0x32699c0,0x3269ad1)`. This is a static edge; labels describe co-located Locations rather than recovered function names or demonstrated runtime execution.

The can1357 reference suggests `RAW_HASH_BYTES=2048`, `DIGEST_BYTES=32`, `RECENT_SNAPSHOT_RETENTION=256`, `SECONDS_PER_YEAR=31557600`, and `MAX_ANNUALIZED_STEP=1.01`. **All five remain unresolved**: no scoped instruction or clear diagnostic has yet uniquely tied these values to the proposed semantics. No hex/digest diagnostic is claimed. The reference's `invalid RawHash.hash hex` is classified unanchored in the retained literal analysis and is not binary proof. State transition inputs and reth/revm private fork boundaries remain open; no full RE-011 completion or progress gate is claimed.

Packet authored against hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985` with pinned LFS inputs.

## Command outcomes (contribution tree)

Packet authored against hyperliquid-source `1f8c67c63ca4794c9689235471c60297f8a5c985` with pinned LFS inputs.

- `python3 tools/l1_evm_inventory.py --out research/work-items/l1-evm-inventory-94/`: exit 0
- `python3 -m unittest tests.test_l1_evm_inventory -v`: 10 tests, OK
- `python3 research/work-items/l1-evm-inventory-94/verify.py`: PASS (manifest, target digest, census, regenerated evidence)
- `make verify`: exit 0
- `make catalogue-check`: exit 0
- `make test`: exit 0
