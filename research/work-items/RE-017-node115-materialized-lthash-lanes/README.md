# RE-017 #115 materialized LtHash lane comparison

The [sidecar projection](https://github.com/lalalune/hyperliquid-source/pull/7337) obtains three cache-record digests from a pinned `lt_hashes.json`. To check whether a compact offline restore fixture retained those records, this packet follows the selected cache-hit route into the materialized state and compares the complete records at their native offsets.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

[The native cache packet](../RE-011-evm-db-checkpoint-hashes-115/README.md) identifies the ordered account, contract and storage records and the option tags. In its cache-success continuation at `0x38c27af`, the loader copies three `0x810`-byte records from consecutive offsets in the read result into three present options. It calls their respective constructors at `0x38c2867`, `0x38c2899` and `0x38c28c8`. Each selected tag-1 path copies the payload from option `+8` to constructor output `+0xf8`. The loader then copies the three `0x908`-byte outputs into one stack aggregate and returns its full `0x1b20`-byte block on the ordinary path.

The [composer](../RE-016-state-compose-434b9f0-115/README.md) preserves that block as its first `0x1b20` bytes. The [materializer](../RE-016-state-materialize-3c2e860-115/README.md) inserts the composer result at state `+0x1108`. Together the selected copies yield:

| Record | Compact offset | Compared size |
| --- | ---: | ---: |
| `accounts_hash` | `0x1200` | `0x810` |
| `contracts_hash` | `0x1b08` | `0x810` |
| `storage_hash` | `0x2410` | `0x810` |

The verifier pins the constructor calls, copy offsets and enclosing FDEs and recomputes the offsets used by the comparison tool. The composition assumes the documented normal returns and ordinary copy binding. It excludes rebuilt-cache paths and descriptor bytes. The report hashes each complete record including both counters, leaves surrounding object bytes outside the lane comparison, and checks the fixture image's own SHA-256 and the u64 height at state `+0x28`.

## Reproduce offline

```sh
python3 -B research/work-items/RE-017-node115-materialized-lthash-lanes/verify.py
python3 -B research/work-items/RE-017-node115-materialized-lthash-lanes/test_lanes.py
python3 -B research/work-items/RE-017-node115-materialized-lthash-lanes/compare_lanes.py \
    compact-state.bin --state-sha256 STATE_DIGEST --height H \
    --accounts-sha256 ACCOUNTS_DIGEST --contracts-sha256 CONTRACTS_DIGEST \
    --storage-sha256 STORAGE_DIGEST
```

Supply the three `layout_sha256` values from the sidecar report. A valid comparison returns JSON and exits 1 when a lane differs. Invalid fixture inputs are diagnosed separately. The [offline log](offline-log.txt) and [native windows](instructions.tsv) retain the actual checks. The tests cover a genuine local file through the CLI, mismatched image identity, height and size, an altered counter and data outside the three records.

This requires an already produced, pinned compact fixture image. It does not generate one, perform an actual DB restore, or compare raw ABCI roots.
