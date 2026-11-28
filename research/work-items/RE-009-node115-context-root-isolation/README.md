# RE-009 · Isolate Context contributions to paired node #115 raw digests

Given two SHA-256-pinned `abci_hashes` records at the same height, this command measures whether their root differences are confined to Context. Both input trees must reproduce their recorded raw digest before the comparison runs.

1. Read the native ordered `exchange_abci_hash` tree in each record and rebuild its MessagePack root preimage.
2. Substitute the observed Context at path `[0,0]` into the reference tree and recompute the full raw digest.
3. Report whether the substituted tree equals the observed tree in ordered structure and whether the computed digest equals the observed raw digest.

If both checks pass and Context differs, the observed root change is fully accounted for by Context in those two captured trees. Changed Locus siblings, changes elsewhere under the top-level root, and reorderings outside Context remain visible. The substituted digest is a diagnostic and does not identify a third measured state.

The [native writer](../RE-017-node115-exchange-abci-hash-tree-json/README.md) preserves indexed child order. Its output is encoded for hashing by the [native reduction-tree preimage format](../RE-008-abci-hash-tree-encoding-115/README.md). [#7344](https://github.com/lalalune/hyperliquid-source/pull/7344) maps `[0,0]` to the selected Context. [#7290](https://github.com/lalalune/hyperliquid-source/pull/7290) verifies one exported tree against its raw digest. [#7333](https://github.com/lalalune/hyperliquid-source/pull/7333) identifies the first divergent node in a pair. This check uses complete trees and both raw values to isolate the contribution of one whole subtree.

Use two complete, same-height raw export rows with retained Context trees. This packet loads both records and encodes the root preimages in memory. It does not identify either capture's producer or establish real H/H+1 replay. The offline controls use synthetic input trees.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From the repository root with the pinned artifact and Rust 1.95 available:

```sh
packet=research/work-items/RE-009-node115-context-root-isolation
python3 -B "$packet/verify.py"

build_dir=$(mktemp -d)
rustc --edition=2024 --crate-name node115_abci_blake3 --crate-type rlib \
  src/node115-abci-blake3/src/lib.rs -o "$build_dir/libnode115_abci_blake3.rlib"
rustc --edition=2024 "$packet/hash_tree.rs" \
  --extern "node115_abci_blake3=$build_dir/libnode115_abci_blake3.rlib" -o "$build_dir/hash_tree"
python3 -B "$packet/isolate.py" "$build_dir/hash_tree" HEIGHT \
  REFERENCE.jsonl REFERENCE_SHA256 OBSERVED.jsonl OBSERVED_SHA256
```

Exit 0 means a Context-only or unchanged pair. Exit 1 means the valid records disagree beyond Context. Exit 2 means an input failed its identity, height, shape, or raw-digest checks. The [measured offline log](offline-log.txt) includes authentic static writer checks, a standard BLAKE3 vector, and synthetic controls for the paired outcomes.
