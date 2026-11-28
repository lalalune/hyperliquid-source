# RE-017: Carry a heightless #115 archive row into adjacent Context verification

Some provider replica shards declare the chunk start and position each record by line. The row itself can omit the explicit height required by the wire-to-Context runner. This bridge verifies the complete decompressed shard, selects source line H+1 by the documented addressing rule, verifies the independently supplied selected-row digest, and emits the byte offset and length of the unchanged row. It then stages a separately identified temporary projection with explicit height and only the three archive fields used by the runner. The final report keeps the source shard, source row, and adapter header digests distinct. [Provider format and source selector](https://github.com/lalalune/hyperliquid-source/pull/7319) · [Wire and adjacent Context runner](https://github.com/lalalune/hyperliquid-source/pull/7611)

The synthetic shard has 44 rows without an explicit height. For checkpoint height 42, physical line 43 supplies consensus round 41 and parent round 40. Its original JSON line includes leading spaces and a terminal newline, both covered by the original row digest. The bridge verifies these bytes, binds the normalized header to the pinned wire payload, and passes all selected H/H+1 Context comparisons with independent synthetic expected field values. Changing the chunk offset selects a different row and fails the row pin. Changing an unselected suffix fails the whole-shard pin. An explicit top-level height that conflicts with the calculated position fails even if the fixture hashes are updated.

The bridge reads the captured x86-64 #115 Linux ELF as data during native checks. It reuses the exact selector and Context runner snapshots and uses their existing compiled Rust libraries offline. Target SHA-256 is `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Real data still requires trustworthy shard and row digests, evidence for the coordinate convention and producer, and matching raw root exports.

## Reproduce

From the repository root, set `packet` to this directory and use Python 3.9 or later with msgpack 1.1.2 and Rust 1.95 or later. The exact linked Git objects and the pinned artifacts must be available locally.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

Use the [wire fixture manifest](https://github.com/lalalune/hyperliquid-source/pull/7611) with `archive_shard` in place of `archive`. Its four keys are `path`, `sha256` for the entire decompressed shard, `chunk_start`, and `row_sha256` for the exact selected line including its newline. Other artifact roles and their independent pins follow the existing runner. The final JSON output includes provenance for the selected archive row and the selected root comparison. A valid selected mismatch exits with status 1. See the [raw offline run](offline-log.txt).
