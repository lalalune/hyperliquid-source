# Validation scope

- Main base `e5c9b6436876b2a4a39daef813171f9879317699`; capture node94 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- `make doctor verify catalogue-check reproduce`: pass. Artifact/source identities and inventories reproduce; analysis readiness true. Full-node exact rebuild readiness remains false.
- Existing focused methods: 6 for this component, 65 across this batch, all pass without skips.
- Three independently compiled 196,608-row Rust comparisons: zero mismatches. 6 compiled semantic mutants detected, own unit test and rustfmt pass, optimized library rebuild hashes agree.
- Complete shared baseline inventory: **971/971 files pass**, zero failed files, 15,468 reported cases, 72 skip records, 1101.220 seconds. `validation-results.json` retains per-file exits/counts/log digests. Six workers run the same fresh-process discovery commands as `make test`; only scheduling differs. No file or assertion is omitted.

`validation-inputs.json` fingerprints shared unchanged tracked tools/tests/provenance/config/registry inputs. The five new modules are compiled and compared separately. The shared baseline inventory is not five independent full runs on five PR heads. Every full-scope progress gate remains false.
