# Actual author qualification

The exact frozen build completed with exit 0 on 2026-11-02. The public
`receipts/commands.json` retains all 196 completed child commands: 169 exit 0
and 27 intended exit 2 refusals (26 malformed batches and one extra argument).
Empty input returned exit 0 with no output. No timeouts, launch errors, Rust
compilation failures or incomplete value streams occurred in this author run.

Each profile passed all 13 integration tests (the standalone library has no
unit tests). The baseline, same-path clean repeat and separate-directory build
each emitted all 912 complete frames: 853 conditional native-domain cases and
59 safe-policy cases. All six correct streams exactly match the pre-Rust
expected bytes. Twenty-two independently compiled mutants emitted another
44 complete streams. A compile failure could not qualify as a detected mutant.
The 11 comparator controls rejected malformed or semantically altered complete
outputs. Inputs given to the executable contain no expected values or labels.

The table reports different complete frames per profile; debug and release
counts agree exactly. Nineteen native controls change native-domain cases;
three policy-only controls preserve every native frame.

| Mutation | Declared domain | Native differences | Policy differences |
| --- | --- | ---: | ---: |
| input-order | native_corresponding | 266 | 0 |
| final-only-clamp | native_corresponding | 113 | 0 |
| signed-maximum | native_corresponding | 207 | 0 |
| last-on-tie | native_corresponding | 180 | 0 |
| ignore-zero-magnitude | native_corresponding | 26 | 0 |
| one-byte-sentinel | native_corresponding | 209 | 0 |
| wrong-sentinel-offset | native_corresponding | 291 | 0 |
| stop-all-rows | native_corresponding | 270 | 0 |
| all-isolated | native_corresponding | 573 | 0 |
| opposite-debit | native_corresponding | 716 | 0 |
| wrapping-debit | native_corresponding | 187 | 0 |
| remove-aru | native_corresponding | 716 | 0 |
| equal-size-identity | native_corresponding | 74 | 0 |
| skip-zero-size-entry | native_corresponding | 25 | 0 |
| reverse-auxiliary | native_corresponding | 143 | 0 |
| increment-count | native_corresponding | 716 | 0 |
| increment-leverage | native_corresponding | 716 | 0 |
| eager-selected-validation | native_corresponding | 86 | 0 |
| accept-duplicates | safe_policy_only | 0 | 2 |
| summary-count-off-by-one | safe_policy_only | 0 | 4 |
| record-count-off-by-one | safe_policy_only | 0 | 4 |
| wrong-selected-asset | native_corresponding | 802 | 6 |

The archive independently rehashed 392 raw stdout/stderr references across
104 unique streams and all 100 compiled artifact references. Public raw
streams are unmodified, with no personal home path present. Compiled rlibs and
clients are retained privately before any directory deletion: their public
identities and private logical references are recorded, but executable bytes
are not distributed because they can contain private build/home paths.
Metadata uses documented logical path tokens; no binary masks or normalization
were used to claim equality.

Within the author run, all four baseline/repeat rlib/client identities match
at the same physical path. Across separate directories, both rlibs and the
release client match; the debug client differs. The independent root comparison
records 50 exact corresponding value streams and 75/100 corresponding compiled
artifacts equal across runs; 25 debug clients differ. No cause is asserted.
This is actual host qualification of the authored source and harness, not
execution of captured node94, universal native equivalence, a full repository
suite, a hermetic OS build, or a completed live-node gate.

The unchanged static pre-code verifier also ran inside the build, passing
110 controls and two regeneration trees. Its retained output is
`receipts/static-replay/validation.json`. The original 89-file pre-code package,
five source files, nine harness inputs and SOURCE-FREEZE bytes remain unchanged.
The separate first root attempt failed before compilation: the sparse checkout
lacked the pinned capture. All ten child commands and original traceback remain
retained privately. FIRST-ROOT-ATTEMPT.json gives the exact error identity and
hydration correction; source/harness/corpus were not amended or retried in place.

The frozen rust-validation/README.md documents the reproduction command and
recorded-host prerequisites. It is a chronological pre-build plan; this file
records completed execution without rewriting that frozen plan. A fresh output
and private-map path, exact toolchain, and hydrated captured file are required.
