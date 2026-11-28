# Node #115 offline same-block wire and archive header audit

Compare two independently supplied artifacts for the first block after an explicit checkpoint height. The manifest pins the decoded replay input and the native replica archive row by whole-file SHA-256. The typed decoder observation names the replay file digest. The audit checks the archive's top-level `height == H + 1` before comparing the six nested `abci_block` fields `time`, `proposer`, `round`, `parent_round`, `hardfork.version`, and `hardfork.round`. It prints individual differences and exits nonzero when the fields disagree. Archive height is supplied independently of either consensus round.

The synthetic fixture uses `H=42`, archive height 43, block round 42, and cutoff-adjusted parent round 40 (direct QC round 41). The ordinary reconstructed decoder consumes the whole plain replay payload. The fixture pins separate wire and archive files and preserves the exact archived clock spelling `1970-01-01T00:00:00.120`. The comparator reports the parent-round disagreement if supplied the unadjusted 41.

An immutable node #115 capture is the static source of the native archive field spellings and conversion layout. The verifier rechecks those ELF spans and formatter separator by reading bytes from the captured image. The archived Rust snapshots [header projection e86354c](https://github.com/lalalune/hyperliquid-source/pull/7370) and [clock rendering 7dbf442](https://github.com/lalalune/hyperliquid-source/pull/7552) are compiled separately from exact commit objects for the integration reproduction. Each probe consumes the same pinned synthetic wire file, and the two results must match the checked-in observations. The basic verifier uses the stored observations and the static image. Neither mode executes the captured node binary.

From the repository root, setting `packet` to this directory and using Python 3.9 or later:

```bash
python3 -B "$packet/audit.py" "$packet/fixture.json" "$packet/observed.json"
python3 -B "$packet/verify.py"
python3 -B "$packet/verify.py" --compile-probes
```

The optional third command needs Cargo with the Rust 2024 edition and those two exact commit objects in the local Git object database. Cargo resolves only archived local path crates and runs offline. The audit is a header comparison of independently supplied operands. Production archive provenance, execution outcomes, and checkpoint and post-replay state roots remain external prerequisites for complete production replay verification.
