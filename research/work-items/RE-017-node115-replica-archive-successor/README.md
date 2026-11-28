# RE-017: select a checkpoint successor from a pinned archive shard

The [Dwellir replica catalogue](https://www.dwellir.com/docs/hyperliquid/data-catalog/node-feeds/blocks#file-layout)
documents shard heights as the chunk stem plus the zero-based line index plus
one. Its field census from 1,423 rows of
`replica_cmds/20261021/1191310000.lz4` lists the block and consensus rounds
without an outer height. The existing [explicit-height selector](https://github.com/lalalune/hyperliquid-source/pull/7285)
requires that field and therefore cannot use this documented layout. A
consensus round can skip and does not identify the sequential block.

This script accepts a single decompressed shard with its documented chunk
coordinate and an externally provided SHA-256. A supplied checkpoint height
H selects row H+1. If any row carries its own height, that height must agree
with the archive coordinate. Missing and conflicting coordinates, duplicate
JSON keys, malformed lines, and a wrong complete shard SHA-256 are errors.
The selected row is returned unchanged, including the trailing newline.

Base: `2da45cb0a761cff6b478e40421699857d87a94df`. Target: Linux x86-64
node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The verifier authenticates the [native rotation stem](https://github.com/lalalune/hyperliquid-source/pull/7293)
and native record newline with static ELF witnesses. Those instructions do
not prove the archive provider preserves every row, that every native file
uses this archive naming rule, or that the observed shard was produced by
#115. The documented provider rule is a separate input, never inferred from
a local file name, consensus round, checkpoint filename or block hash.

Run from a checkout containing the pinned #115 binary.

```sh
python3 -B research/work-items/RE-017-node115-replica-archive-successor/verify.py
python3 -B research/work-items/RE-017-node115-replica-archive-successor/extract.py \
  /path/to/decompressed-shard.jsonl --chunk-start "$chunk_start" \
  --checkpoint-height "$checkpoint_height" --sha256 "$decompressed_shard_sha256"
```

The native shard bytes, checkpoint and reference roots were unavailable for
this check. The offline log records the ELF byte checks and synthetic
selector controls using consensus rounds deliberately different from the
sequential block heights. It establishes exact record intake for a pinned
external shard and does not claim a successful replay.
