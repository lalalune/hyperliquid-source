# RE-009 · Compare three #115 Exchange quantity subtrees against a raw root

The offline checker compares named checkpoint amounts and the two quantities in `pvs` against complete raw order-sensitive ABCI subtrees. It verifies the checkpoint and export hashes, checks both heights and recomputes the declared raw reference digest before comparing slots.

| Checkpoint field | Exchange field | Raw slot | Raw structure |
| --- | --- | --- | --- |
| `hlp_start_of_day_account_value` | `+0x10f8` | 26 | Optional quantity |
| `pvs.mptc` and `pvs.ptc` | `+0x4240` and `+0x4248` | 27 | Two ordered quantity children |
| `initial_usdc_evm_system_balance` | `+0x4268` | 47 | Quantity |

Each quantity has child 0 holding BLAKE3 of an eight-byte little-endian u64 and child 1 holding BLAKE3 of zero input bytes. A nil optional amount has child 1 alone with the hash of an eight-byte qword 0. A present amount has the quantity under child 0 and the hash of qword 1 in child 1, including a present numeric zero. `pvs` emits the `mptc` subtree before `ptc` regardless of key order in the input map. The checker compares raw values with no unit conversion.

## Native evidence

Target ELF SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Native evidence base `2da45cb0a761cff6b478e40421699857d87a94df`.

- The HLP writer receives the tag and qword at `0x54811ae..0x54811c2`. `0x56774c0` writes nil or dispatches the value to the unsigned integer writer `0x57d00b0`. Raw visitor `0x4d3f3a0` visits the quantity via `0x5106a90` only when tag 1 is selected. The final raw option leaf comes from qword constants 0 and 1 and appender `0x14199b0`. The quantity visitor allocates then calls `0x4d3f7f0` for its child 1. This visitor checks the leaf type and returns without writing.
- The `pvs` writer routes through `0x5673f30` to `0x5b065e0`, which writes `mptc` from `+0` and `ptc` from `+8`. Raw slot visitor `0x35c31a0` supplies both words in this order to descriptor `0x6465368`. Its visitor `0x46f5490` uses the u64 descriptor `0x64828c8` and zero-input leaf descriptor `0x6484b28`.
- The initial USDC EVM balance is written as a u64 through `0x56745d0`. In raw slot 47, `0x43c6a50` uses the same two-child layout with its own zero-input leaf descriptor `0x6487b30`.
- The three empty-leaf paths deliver the same zero-byte input despite their different visitor addresses. They use the leaf allocator at `0x141a020` with initial count zero. The leaf finalizer at `0x141a2bf` skips the BLAKE3 update when the count is zero. [#7517](https://github.com/lalalune/hyperliquid-source/pull/7517) established an equivalent quantity shape inside the auction fields. [#6095](https://github.com/lalalune/hyperliquid-source/pull/6095) supplies the names for these three separate slots.

## Reproduce offline

Use Python with `msgpack==1.1.2`, a compatible Rust compiler and the pinned local ELF. Stage the exact named parser from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445) and the ordered raw reader and BLAKE3 driver from [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) in their published work-item directories under one helper folder. The script verifies its dependency source hashes.

```sh
python3 -B research/work-items/RE-009-node115-rmp-exchange-quantity-subtrees/verify.py \
  --helpers /path/to/staged/helpers --rustc "$(command -v rustc)"
```

With the built #7404 `hash_tree` driver, use `compare_quantities.py HELPERS HASH_TREE HEIGHT CHECKPOINT_RMP CHECKPOINT_SHA256 RAW_EXPORT RAW_EXPORT_SHA256`. The [offline output](offline-log.txt) records synthetic matches and isolated discrepancies for nil versus zero, `pvs` child order, and substitution of a qword-zero digest for an empty digest. Matching a real chain height still requires a sourced checkpoint and same-height export.
