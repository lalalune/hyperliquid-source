# RE-007: compose node 115 flat margin selection and arithmetic

This is partial work for #3916. It joins the existing flat margin range
implementation (#3261) to the existing selected-row arithmetic (#2834), using
the native caller relation mapped in #2223. It does not claim complete margin
policy, units, liquidation behavior or an accepted component gate.

Target Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Prior #3261 owns the
flat range operation; #2834 owns the selected-row arithmetic. Open #4170
implements position modes while explicitly leaving margin-table paths opaque.
This packet closes the selected valid-flat producer-to-arithmetic join, not
those existing claims or the broader position policy.

## Selected native relation

Both FDEs `0x38b54b0..0x38b55f3` and `0x38b5300..0x38b54a9` construct a
range query whose lower bound tag is 2, upper bound tag is 0 and upper value
is the incoming amount. Both call `0x3cd80d0`. On the flat result tag 1 they
use the end of the second span when nonempty, otherwise the end of the first
span. The selected end minus 0x10 supplies the u64 offset and end minus 8
supplies the divisor byte. With 40-byte rows this is the last included row's
+24 and +32 fields, respectively. Empty spans enter existing diagnostics;
the tree representation has a different path and is outside this composition.

The new safe API reuses the prior crates and returns a local refusal for
invalid views, no selected row or zero divisor. It preserves the existing
arithmetic observation at opaque diagnostic boundaries and does not claim a
native returned error, a callback return or rollback. Valid stable flat storage,
proper original memory and normally returning helpers are correspondence
premises; original ABI, financial units, tree behavior and actual liquidation
or acceptance mutations remain unproven.

## Evidence and reproduction

`records.json` retains both complete FDE instruction partitions (748 bytes,
187 instructions). The verifier checks 37 selected facts and rejects 11
semantic byte corruptions with global digest/window checks bypassed for each
control, including query bound, span choice, field offset and arithmetic
changes. It also pins the unchanged reused range and row source hashes. This
is static evidence and independently authored source; no captured instructions
were executed or emulated.

```sh
python3 research/work-items/RE-007-node115-flat-margin-composition/verify.py
cargo +1.95.0 test --locked --offline --manifest-path src/node115-margin-flat-compose/Cargo.toml
```

The verifier requires the hydrated target and existing Capstone 5.0.7; Rust
uses only local paths and an already installed 1.95 toolchain. The new tests
cover wrap-seam duplicates, empty and invalid views, selected diagnostic
boundaries and 800 small valid-ring/mode combinations against direct formulas.
No live financial state, signing or network access is used.
