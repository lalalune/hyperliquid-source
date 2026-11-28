# RE-009 · Compare #115 named gas-auction checkpoint fields with raw ABCI slots

The offline comparator binds `register_token_gas_auction`, `perp_deploy_gas_auction`, and `spot_pair_deploy_gas_auction` to ordered raw exchange slots 28, 29, and 30. It requires both input SHA-256 pins, matches the checkpoint Context height with the export height, and recomputes the export's full raw ABCI digest before checking those branches.

Each named nil corresponds to an ordered branch containing child 1 alone with the little-endian qword 0 preimage. A present auction has ordered children 0 and 1, with qword 1 at child 1 and six selected u64 values under child 0. The comparator localizes differences per auction and field. It leaves the `end_gas_wei` Option subtree and the unqueried phantom leaves inside quantity wrappers outside its scope.

| Checkpoint field | Writer source relative to auction | Relative raw branch leaf path |
| --- | --- | --- |
| `bucket_guard.last_bucket` | `+0x18` | `[0,0,0]` |
| `bucket_guard.bucket_millis` | `+0x10` | `[0,0,1]` |
| `start_gas_wei` | `+0x28` | `[0,1,0]` |
| `token` | `+0x30` | `[0,3]` |
| `initial_gas_to_last_auction_gas_ratio` | `+0x20` | `[0,4]` |
| `min_gas` | `+0x38` | `[0,5,0]` |

Node #115 ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- Exchange writer key calls at `0x548120c`, `0x5481237` and `0x5481262` pass offsets `+0x3a00`, `+0x3a40` and `+0x3a80` to `0x5673520`. That writer emits MessagePack nil for native tag 2 at `0x567357a` and otherwise tail-calls the named payload writer `0x5a015b0`.
- `0x5a01657` sends the bucket guard at `+0x10` to `0x5617020`. The latter writes the guard's `+0x08` and `+0x00` qwords as `last_bucket` and `bucket_millis`, respectively. Raw visitor `0x46f4560` visits precisely those two offsets in that order through scalar leaf writers `0x14199b0` and `0x141b3c0).
- The other selected values are loaded at `0x5a01690`, `0x5a0177b`, `0x5a017b8` and `0x5a017d4`. Each goes through unsigned MessagePack integer writer `0x57d00b0`, with `min_gas` using forwarding helper `0x5aae2c0`. At raw entries 1 and 5 the `0x43c6a50` wrapper visits its source qword in child 0. Entries 3 and 4 dispatch directly to qword appenders.
- [#7327](https://github.com/lalalune/hyperliquid-source/pull/7327) establishes the common raw wrapper, six nested source offsets and qword tags. This packet ties the named payload's writer and field paths to that raw layout.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the local pinned ELF. Stage the exact `project.py` from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the exact `isolate.py` and `hash_tree.rs` from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories below the same helper directory. The tools check their source hashes.

```sh
python3 -B research/work-items/RE-009-node115-rmp-auction-root-scalars/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

Use the built #7404 `hash_tree` executable with `compare_auctions.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The JSON reports `selected_checks_pass` and each auction slot. The [measured offline run](offline-log.txt) covers two present auctions and one nil auction, a slot-30 token difference, a missing key, an out-of-domain scalar and a stale digest. It uses synthetic fixtures. A genuine checkpoint and matching raw export are required to establish parity at an actual height.
