# Independent integration review

The root reviewer read the complete six-body native proof, both decoder exports,
the safe Rust component, six handwritten tests, independent pre-code oracle and
the entire build/input-client harness. A separate peer independently checked the
native constant mapping and every compiled mutant's retained raw comparisons.
No actionable finding remains within the stated conditional value scope.

Before production source existed, the root independently regenerated all five
pre-code corpus products and verified the eight-entry freeze. The original
static, pre-code, source and author implementation freezes remain byte-for-byte
unchanged. `IMPLEMENTATION.md` is the combined contribution entry point;
`PUBLIC-MANIFEST.json` adds integration evidence without rewriting those records.

The root separately reran the static checker: all 169 controls passed and both
fresh collections reproduced the retained evidence. The complete native review
covered six full FDEs, 4,067 bytes / 1,007 instruction rows, plus the stated 137
context bytes; exact image/FDE/CIE, 92 instruction anchors and 14 RELA slots were
independently checked. These are static bindings, not target execution.

The root then ran the unchanged frozen `rust-validation/build.py` against a fresh
directory using Rust 1.94.1 and the actual dependency-free Cargo graph. All 139
commands succeeded. Debug and release each matched all 44,679 operand pairs and
211 length cases, passed six tests, and detected all 14 compiled mutants.
The twelve byte-value mutants cause 3,591 / 17,982 / 641 / 2,645 / 13,894 /
6,969 / 4,828 / 25,928 / 43,952 / 44,038 / 7 / 788 mismatches respectively;
the two new length-domain policy mutants cause 20 / 29 integer-case mismatches.
Those last two are safe-API policy checks, not original-machine observations.

`ROOT-COMPARISON.json` retains exact comparison results. All 278 root raw stream
references were rehashed. `rust-validation/root-receipts/commands.json.gz` retains
the root command records and references exact shared author streams where equal;
33 distinct new raw streams preserve the differing build/test/metadata logs.
Only stream-reference metadata was changed for deduplication; original references
and the original commands file identity remain recorded. Input-client result
streams and every mutant mismatch count agree between author and root.

Fresh rebuilds in each run have byte-identical library/client files. This does
**not** establish reproducibility across different build directories: author
and root rlibs and debug clients differ, and the rlibs retain their different
canonical `/private/tmp` source paths beyond the lexical `/tmp` remap. Release
clients agree. All original hashes are retained; there is no masking or target
compiled-byte claim. Before the root build, canonical `/private` and
`/private/tmp` Cargo config locations were also checked absent, supplementing
the frozen driver's lexical-ancestor audit without changing it.

Live overlap review through PR #1476 checked new PR bodies and full file lists.
The separate Visor preparation-policy #1437 and selected-parent-slice #1469
packets concern path/preflight preparation; node-94 shell-route #1464 uses a
different artifact. None supplies this move-value component. Their scope is not
claimed here and this PR does not depend on their unmerged branches.

The API requires canonical UTF-8 and external admission of the opaque preflight.
It reproduces argument byte values and raw option 1, not filesystem effects,
native allocation/layout, shell safety, quiet wrapping or full Visor equivalence.
Captured binaries, instruction evaluators, target networking and chain actions
were not run. The broad repository test dispatcher includes excluded captured
evaluators and was not run. Component completion and hosted CI are unclaimed.
