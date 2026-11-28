# RE-017 · Locate two adjacent native #115 replica rows across a shard roll

The [native replica schema](../RE-017-node115-replica-json-schema/README.md) puts the sequential `height` outside the Block's consensus `round` and `parent_round`. The [rotation trace](https://github.com/lalalune/hyperliquid-source/pull/7293) shows that a rotated shard uses the bucket `floor(max(height - 1, 0) / 10000) * 10000` as its filename stem. Consequently the rows at 10000 and 10001 can sit in different files, and the absolute height can differ from the decimal filename. A caller can establish the fixture pair from the explicit JSON coordinates, even when the source files are supplied in reverse order or have gaps.

`select_pair.py` scans the caller's manifest of decompressed native JSONL sources. It requires the SHA-256 of each full supplied file and reports exactly one row each at H and H+1. The result carries the file name, one-based line number, zero-based byte offset, whole-file SHA-256, and SHA-256 and unchanged UTF-8 text of the selected row including its newline. A repeated target height is ambiguous. An absent height, an incomplete row, or a failed file pin returns an error. This scope uses native explicit-height files. The [single explicit-row reader](https://github.com/lalalune/hyperliquid-source/pull/7285) handles a single metadata lookup, while the [provider-specific implicit selector](https://github.com/lalalune/hyperliquid-source/pull/7319) uses a separate archive indexing convention.

The two checked fixture shards are synthetic. H=10000 is the second row in `archive/20261030/0`. H+1 is the first row in `archive/20261031/10000`. The manifest lists the latter first. Verification authenticates the native bucket and selected field and newline writes, then checks both complete row bindings and missing, ambiguous, and wrong-file-digest cases. A trustworthy source must provide the real manifest pins. This packet does not establish #115 production captures or compare restored and replayed state roots.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
packet=research/work-items/RE-017-node115-replica-adjacent-shards
python3 -B "$packet/verify.py"
python3 -B "$packet/select_pair.py" "$packet/manifest.json" 10000
```

The [raw offline log](offline-log.txt) contains the native checks and the complete selector output.
