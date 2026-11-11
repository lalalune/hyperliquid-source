# Fee-trial owned source evidence

Issue #3913, bounded fee action only. Original node115 SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Static decoding only; the captured executable is never executed or emulated. Prior #2231 is the static predecessor; #286 is node94.

`records.json` binds 24 complete FDEs, 7,835 bytes, 1,928 instructions and 1,966 checked facts. Thirty corruption controls alter fields, statuses, time increments, native helper targets, constants and parser branches. The verifier authenticates the original ELF first, then requires every control to fail a semantic fact check with digest/window guards deliberately bypassed.

| Native range/helper | Owned interpretation |
| --- | --- |
| `3c18390..3c18a7e` | Actual user lookup, special-key baseline, raw disabled byte and active-trial gate, template and secondary-tier admission, cooldown, discounts, minimum/benefit, ordered affiliate/caller writes |
| `36a5540..36a58c8` | Four input strings in `+18,+00,+48,+30` order; length cap and parser dispatch |
| `43099f0`, `421e4e0` | Parsed decimal conversion; broader floating fallback remains excluded |
| `5c44210`, `5c42950`, `5c43b40`, `5c42c40` | Selected short unsigned/positive/negative digit folds |
| `5c424f0`, `5c424a0`, `5c42870`, `5c42540` | Fraction digit folds, scale and signed-zero normalization |
| `5c44b40`, `63f0080`, `63efe40`, `63f0160`, `63f00d0` | Decimal quotient/remainder and binary64 scaling/rounding on the bounded coefficient domain |
| `1506a00`, `16290d0` | Calendar add90/add14, with overflow represented explicitly |
| `4716f00`, `4717440`, `3ee6280`, `4717720`, `4717c50` | Actual keyed user lookup, equality and missing-entry initialization |

At `3c186bb` cooldown is 90 days; `3c186d4` computes end date 14 days before testing benefit. The user `+c0` last-trial date is read but not written. `3c188bf..3c18911` and `3c189ef..3c18a41` write custom trial data to affiliates and caller respectively. The native first four template lanes are compared in `[0,2,1,3]` order, and secondary rows cannot waive the primary-pair requirement. The native discount list stops at the first threshold greater than the retained volume. Positive requested lanes alone receive the factor `1-discount`. Native min/NaN and signed-zero selection is retained in the source; fixture claims are limited to their recorded finite cases.

The Python generator uses Decimal to derive coefficients and integer arithmetic for decimal decomposition, and a separate state reference. Decimal fixture SHA-256 `7f28103777d50c510034d1b3efd9033e2037d40e20963223bf29f28172f62fea`; state fixture SHA-256 `08a813bff77e9f8b6d0ca896cd01a923a65c4043470c1bae328d008f009f1e8a`. Six debug/release tests pass; 16,000 decimal and 4,500 state cases include calendar extremes and aliasing. These owned/reference checks do not execute native instructions and are not runtime differential tests.

Boundaries: accepted decimal syntax <=17 bytes only, valid native collections and successful allocation; physical hash maps, unobserved user fields, error payloads, long decimal/floating fallback and outer policy excluded. Full fee coverage and issue-closing gates remain false.
