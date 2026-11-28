# RE-017: Preserve native #115 H/H+1 reference rows from export shards

The original raw ABCI reference selector returns the 32-byte digest at an explicit height. The adjacent Context comparator also needs the expected ordered tree from the same source row. This selector verifies each complete supplied native export shard, finds one row at H and one at H+1 by the explicit height fields, and writes unchanged original line bytes to separate files. Each output records the original shard hash, line number, offset, byte length, row SHA-256 and declared native digest. [Scalar reference selector](https://github.com/lalalune/hyperliquid-source/pull/7287) · [Adjacent Context comparator](https://github.com/lalalune/hyperliquid-source/pull/7465)

The synthetic H=42 row sits second in one shard and the H+1 row sits first in another. The source list supplies the shards in reverse order, with distinct leading whitespace on the selected lines. The selector preserves the exact original bytes, and the existing comparator verifies the recomputed native digest and all selected Context fields from those files. The controls reject duplicate target height across sources, a modified unrelated suffix, a digest-only row and a missing successor. Shard coordinate and pin checks identify locally supplied bytes. Independent production and root provenance remain required.

The verifier checks the native writer and tree encoder against the Linux x86-64 #115 ELF with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. It executes only offline Python and reconstructed Rust.

## Reproduce

From the repository root, set `packet` to this directory. The verification uses Python with msgpack 1.1.2 and Rust 1.95 and the exact Context dependency snapshots listed in the reused verifier.

```sh
python3 -B -u "$packet/verify.py"
python3 -B "$packet/select_exports.py" MANIFEST.json MANIFEST_SHA256 NEW_OUTPUT_DIRECTORY
```

The input manifest contains unsigned `height` and a nonempty `shards` list. Each shard specifies a relative `path` and complete-file `sha256`. The files are newline-terminated native `abci_hashes` rows. The output directory must be new. The resulting file pins can be used directly as `reference_h` and `reference_h_plus_one` in the Context case. See the [raw offline run](offline-log.txt).
