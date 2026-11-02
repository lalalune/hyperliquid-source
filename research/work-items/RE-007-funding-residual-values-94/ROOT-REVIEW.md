# Independent review and actual qualification

This contribution adds the dependency-free `node94-funding-residual-values`
package and its target-bound evidence packet for RE-007. Its input is a supplied
post-worker summary relation and represented existing user/position state. The
complete bounded operation sorts unique 20-byte keys, performs ordered signed
saturated accumulation and unsigned first-on-tie maximum selection, truncates
each inner sequence at its first zero u32 marker (bytes 60..64 of the 72-byte
record), and applies the selected
debit and auxiliary-entry updates. In particular, subtracting then adding the
same absolute size through two saturations is not always the identity.

`CONTRACT.md`, `PROOF.md`, `TREE-PROOF.md` and the pre-Rust corpus are historical
pre-code snapshots. The original pre-code base is 56c0ec6; source and this PR
use main 966865f. `IMPLEMENTATION.md`, `rust-validation/VALIDATION.md` and this
review record the subsequent implementation and observed results. Later review
files do not rewrite the earlier admission freezes.

The digest-bound native closure contains 29 complete FDEs, 25,803 code bytes
and 5,832 decoded rows, with GNU/LLVM exports, raw instructions, relocations,
CIE/FDE/LSDA records and call/data obligations. Parent and peer reviews covered
the native relation, helper frames, scalar arithmetic, tree induction, source,
transport and build graph before Rust compilation. Native correspondence is
conditional on the supplied post-worker state, unique summary keys, valid
spans, existing selected user/position, non-MIN position size on the active
path, ordinary helper returns and the explicit allocation/memory premises.
The safe API rejects invalid inputs before mutation; that is not a claim of
native panic rollback or missing native-constructor behavior.

The source freeze binds five package files and nine harness inputs. The real
graph has one local package, no dependency, build script or proc macro. Both
root and author actually ran the frozen qualification, independently producing:

- 196 child commands each: 169 exit 0 and 27 expected exit 2 refusals.
- Thirteen integration tests per profile, with zero library unit tests.
- Six correct complete streams and 44 compiled-mutant streams, each with all
  912 frames: 853 conditional-native cases and 59 safe-policy cases.
- Twenty-two compiled mutants in both profiles. Nineteen require a native-case
  difference; three policy-only controls must preserve all native cases.
- Eleven comparator controls, 26 malformed batches, an extra-argument refusal,
  and empty-input acceptance, counted separately from semantic examples.
- An unchanged static replay with 110 rejection controls and two fresh
  regeneration trees.

Input transport contains opaque `Cdddddd` case identifiers. The author's phrase
"no expected values or labels" means no expected results or semantic/outcome
labels, not an absence of those identifiers. The independent complete-output
parser checks IDs, order, lengths, canonical state shape and all frame bytes.

`ROOT-COMPARISON.json` records the parent's actual rehash of 784 raw stdout/stderr
references, 200 private compiled-artifact references and 50 source/client copy
observations. All 50 corresponding root/author value streams match exactly.
Same-path repeated compiled artifacts match. Across separate directories, both
rlibs and release clients match, while debug clients differ; 75/100 cross-run
compiled observations match. No masks, output normalization or cause of the
inequality is asserted. The peer reviewed the comparison logic and did not
claim a second execution of that entire parent comparison.

The first root build attempt stopped before compilation: a sparse checkout
lacked the captured input required by the unchanged static replay. It retained
ten command records (nine exit 0, one exit 1). The original traceback stays
private because it contains a personal home path; its exact size and SHA-256
are published. The authenticated 91,774,280-byte capture was materialized as
read-only data, then fresh output roots were used. No source, harness or corpus
changed. Separately, the author's first archive-census script rejected its own
hash-string/object comparison before publication writes; its corrected archive
checker did not amend either successful build.

The public archives retain exact safe raw streams. Review metadata projections
are explicitly marked and retain original identities; omitted private raw
streams retain identities and omission reasons. Compiled clients/rlibs, captured
executables, private maps and runtime caches are not distributed in this packet.
`PUBLIC-MANIFEST.json` covers every contribution file except itself, including
the five production-package files, original freezes and additive root evidence.

Current-main static repository checks and focused tooling tests are separately
recorded under `root-validation/baseline/`. The full repository suite was not
run because its captured-instruction evaluators are outside this task's static
authorization. Authored component debug/release tests and qualification did
run. No captured execution, emulation, captured linking, live node/funding
operation, deployment or component-gate completion is claimed. Review and build
agreement share the same project/native lineage and are not an independent
economic or live-target oracle.
