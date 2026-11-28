# RE-009 · Offline comparison of the complete node #115 Context subtree

Compare all 13 ordered Context children under raw ABCI tree path `[0,0]`. The command takes one normalized restored or replayed Context and one native `abci_hashes` record. Both inputs must match the requested height and their supplied SHA-256 digests. The output names mismatched fields and reports a sibling-order mismatch separately.

| Context entries | Successful leaf preimage |
| --- | --- |
| `hardfork_height`, `height`, `round`, `next_oid`, `next_lid`, `next_twap_id`, `system_nonce`, `mac` | One little-endian qword each |
| `hardfork` | Separate qwords for version and its round under indexes 0 and 1 |
| `tx_index` | Index at child 0 when present and qword 1 at child 1. Absence leaves child 0 out and hashes qword 0 at child 1. |
| `time`, `prev_time` | Signed Unix seconds as a little-endian qword followed by the original four-byte fractional nanosecond value |
| `use_system_nonce` | One canonical boolean byte |

The native Context callback `0x43037c0` checks a 13-entry destination and visits its ordered children. Its ordinary clock inputs at state `+0x60` and `+0x6c` share descriptor `0x6482708`. The visitor thunk `0x3d5e950` resolves to `0x141b1e0`; the selected path decodes the packed date and seconds, appends eight derived seconds bytes, and appends the four subsecond bytes. The Context byte visit at `0x1419d40` appends one byte. The scalar and nested pair visitors use the [native leaf reducer](../RE-008-abci-hash-tree-115/README.md), whose selected unkeyed BLAKE3 operation the existing Rust crate supplies offline.

[#7344](https://github.com/lalalune/hyperliquid-source/pull/7344) maps grouped Locus and Context descriptors, [#7347](https://github.com/lalalune/hyperliquid-source/pull/7347) checks two Context branches, and [#7342](https://github.com/lalalune/hyperliquid-source/pull/7342) models clock rotation. The [packed timestamp writer packet](../RE-009-node115-root-packed12-captures/README.md) establishes the calendar conversion for valid positive-year timestamps on a separate caller. This tool combines all 13 fields into one ordered Context comparison and anchors the clock/boolean methods at this caller.

Provide normalized Context data in the following shape. This is a synthetic input example.

```json
{
  "hardfork_height": 17,
  "hardfork": {"version": 42, "round": 12},
  "height": 30,
  "tx_index": null,
  "round": 500,
  "time": {"unix_seconds": 3, "subsec_nanos": 17},
  "prev_time": {"unix_seconds": -1, "subsec_nanos": 999999999},
  "next_oid": 26,
  "next_lid": 256,
  "next_twap_id": 66052,
  "system_nonce": 77,
  "use_system_nonce": false,
  "mac": 79
}
```

This interface accepts ordinary UTC seconds with year 1 through 9999 and an ordinary subsecond range. Checkpoint extraction, historical provenance, leap-second captured representation, other root branches, and full raw-root equality remain outside this comparison. No actual H/H+1 captures were available.

### Reproduce

Use Rust 1.95 and Python from the repository root.

```sh
python3 -B research/work-items/RE-009-node115-context-subtree-compare/verify.py
```

To compare supplied local files:

```sh
packet=research/work-items/RE-009-node115-context-subtree-compare
build_dir=$(mktemp -d)
rustc --edition=2024 --crate-name node115_abci_blake3 --crate-type rlib \
  src/node115-abci-blake3/src/lib.rs -o "$build_dir/libnode115_abci_blake3.rlib"
rustc --edition=2024 "$packet/hash_leaves.rs" \
  --extern "node115_abci_blake3=$build_dir/libnode115_abci_blake3.rlib" -o "$build_dir/hash_leaves"
python3 -B "$packet/compare.py" "$build_dir/hash_leaves" HEIGHT \
  CONTEXT.json CONTEXT_SHA256 EXPORT.jsonl EXPORT_SHA256
```

The [offline log](offline-log.txt) records the pinned target, a standard BLAKE3 vector, raw clock bytes, input pinning and a synthetic mutation for each child. Target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.
