# RE-017 check complete #115 collector coverage before comparing a response Hash

An archive can carry one digest for the entire ordered result vector. The earlier collector audit compares partial observations against an archived Full vector. The earlier Hash comparator encodes a complete supplied vector. This fixture checks which bundles and actions the collector supplied before attempting the Hash comparison. [Collector audit](https://github.com/lalalune/hyperliquid-source/pull/7586) · [Archived order-result Hash](https://github.com/lalalune/hyperliquid-source/pull/7803)

The manifest pins the original archive line and a separate collector observation by SHA-256. Both must declare the same explicit H+1 relative to the supplied checkpoint height. The verifier uses the archived bundle keys and action counts to check coverage. It preserves the collector's row order and source ordinals in the report and hashes the unchanged ordered Full vector when every expected group is present. Missing groups produce a list of keys and no digest comparison. A present group with no actions counts as observed. An unexpected key, incorrect action count, or inconsistent ordinal metadata is an error.

The synthetic fixture uses H=43 and H+1=44. The collector produces two groups in a different order from the archive's bundle list. Its complete result matches the independent Rust Keccak digest of a manually assembled named preimage. Changing collector order yields a digest mismatch despite complete coverage. Empty and partial prefixes with an explicit stop remain inconclusive. A changed action count is rejected before hashing.

The verifier reads the pinned Linux x86-64 #115 capture as data, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. It runs the earlier static writer checks and reconstructed offline Python and Rust. Both transported observations and their provenance are supplied by the caller. This checks the ordered response fingerprint. Full production state-root parity remains separate.

## Reproduce

Use Python 3.9 or newer with msgpack 1.1.2, Rust 1.95 and the exact dependency commits recorded in `verify.py`. From the repository root set `packet` to this directory.

```sh
python3 -B -u "$packet/verify.py"
python3 -B -u "$packet/verify.py" --case CASE.json --case-sha CASE_SHA256
```

The case declares `checkpoint_height`, `archive` and `observation`. Each artifact entry carries `path` and `sha256`. The archive is one complete JSONL line with `resps.Hash`. The observation contains `height`, ordered `ordinals`, `stop_position` and `resps.Full`. The comparison returns status 0 for a match, 1 for a mismatch, and 2 for incomplete coverage. [Raw offline output](offline-log.txt)
