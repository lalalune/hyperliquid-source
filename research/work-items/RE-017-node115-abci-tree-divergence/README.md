# RE-017 · Locate the first difference in paired node #115 ABCI trees

An `abci_digest` comparison can report a mismatch at H or H+1. If both sides retained the native `exchange_abci_hash` trees, this offline command locates where they first disagree in their stored traversal order. It reports the raw digest comparison separately. For example, a first difference at `[28,0,2]` points to child 2 of child 0 in top-level slot 28. A sibling-order mismatch reports the common path, position and both child indexes.

Each input is one previously selected, same-height `abci_hashes` line, pinned by its supplied SHA-256. The native writers emit three fields, `height`, `abci_digest`, and `exchange_abci_hash`. The last field is a single 32-byte digest or an ordered array of index–child pairs. Checks reject ambiguous or unsupported rows, including wrong height, repeated child indexes and malformed digest widths.

| Difference | Output |
| --- | --- |
| Leaf bytes | Leaf index path |
| Leaf versus child array | Path to the change in shape |
| Reordered siblings | Parent path, first differing ordinal, both indexes |
| Different sibling indexes | Parent path, ordinal, both indexes |
| Additional trailing children | Parent path and both lengths |

The [native row writer](../RE-008-abci-hashes-log-115/README.md) pins the field names and source. The [native tree writer](../RE-017-node115-exchange-abci-hash-tree-json/README.md) pins the recursive pair shape and stored order. [#7290](https://github.com/lalalune/hyperliquid-source/pull/7290) verifies a single export row's digest against its tree, and [#7318](https://github.com/lalalune/hyperliquid-source/pull/7318) compares raw digest values by height. This tool takes retained tree pairs and reports the first path difference. Identical trees with a raw digest mismatch direct attention back to the individual records and their digest calculation. Artifact and height checks alone do not establish independent origin or trusted root values.

## Reproduce

From the repository root with the pinned node #115 artifact available, run:

```sh
python3 -B research/work-items/RE-017-node115-abci-tree-divergence/verify.py
```

For already extracted rows:

```sh
python3 -B research/work-items/RE-017-node115-abci-tree-divergence/compare.py \
  HEIGHT REFERENCE.jsonl REF_SHA256 OBSERVATION.jsonl OBS_SHA256
```

An exact match exits 0, a recognized difference exits 1, and an invalid input exits 2. The [measured offline log](offline-log.txt) includes writer verification and synthetic detection controls only. H and H+1 captures were unavailable. Target SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.
