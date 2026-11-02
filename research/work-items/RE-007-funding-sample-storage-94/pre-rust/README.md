# Pre-source review gate: returned-record state projection

This separate phase proposes a dependency-free real Rust library for the active
sample/fallback values established by the frozen static packet. It does not
change the original static freeze, manifest, proof or evidence files.

Review [CONTRACT.md](CONTRACT.md), [SOURCE-PLAN.md](SOURCE-PLAN.md),
[PROTOCOL.md](PROTOCOL.md), and the 20 explicit states in
[corpus/hand-witnesses.json](corpus/hand-witnesses.json). Coordinator approval is
required before creating any Rust/Cargo source or driver for this component.

The independently authored mathematical oracle uses a first-full-tag2 prefix,
per-key even-payload concatenation, and last-odd selection only for exact dex
byte3. It imports no candidate, target, prior model or instruction evaluator.
The proposed production implementation is a sequential loop over supplied
records, using explicit `BTreeMap<u64, Vec<u64>>` and `BTreeMap<u64, u64>` state.

The frozen corpus contains **8,144 cases / 85,263 input records**, with at most
1,539 records in one case:

| Family | Cases |
| --- | ---: |
| Explicit hand expectations | 20 |
| All 256 dex bytes, with absent/existing state | 512 |
| Wide tags, unsigned key boundaries and raw payloads | 6,120 |
| Ordered tag pairs with repeated/distinct keys | 512 |
| Every single bit of key/tag/payload fields and complements | 384 |
| Long distinct-key and repeated-key streams | 48 |
| Sentinel at beginning/middle/end | 36 |
| Deterministic synthetic streams | 512 |

Normal Python and `-O` generation with distinct hash seeds/timezones produced
identical inputs, expectations, metadata and hand witnesses. Full raw/gzip
hashes are in [corpus/corpus.json](corpus/corpus.json). The evidence archive
retains exact bytes in gzip; it does not need duplicate uncompressed copies.
The packet's existing `.gitattributes` applies to these nested gzip files.

Reproduce into a nonexistent directory:

```sh
python3 research/work-items/RE-007-funding-sample-storage-94/pre-rust/oracle.py --out /tmp/funding-pre-rust-corpus
```

These are frozen value expectations, not native execution observations. The
native correspondence retains the valid-tree/vector, allocator/copy/frame,
ordinary-return and `0x222b480` endpoint premises. Rust allocation/panic/rollback
behavior, native data layout/ABI, scheduler completeness, outer min pairing and
economic semantics remain excluded. The future input-only driver and compiled
mutation checks are planned, not completed.
