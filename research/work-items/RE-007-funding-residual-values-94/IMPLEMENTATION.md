# Supplied-summary residual values: implementation and actual qualification

The dependency-free MIT package `src/node94-funding-residual-values` implements
the complete bounded value/state operation described in CONTRACT.md. It consumes
supplied summary results and an existing selected user-position state. It
preserves unsigned maximum/tie choice, per-step saturated accumulation, ordered
cross/isolated debit, auxiliary entry creation and subtract-then-add arithmetic,
including the nonidentity case at signed MIN. It does not implement worker
provenance, absent native constructors, native allocation/tree layouts or their
failure behavior. Span/count and invalid-domain refusals are separate safe
policies. See rust-validation/SOURCE-PROOF.md and BRIDGE.md for the exact relation.

The original pre-code proof and 912-case oracle were frozen before Rust source
existed. Source was authored against current main966865f, with historical native
pre-code base56c0 explicitly preserved. The real single-package graph has no
external dependency, build.rs, proc macro or build hook. Source/harness freeze
b47558a08ad43ac3bfd6a747143c14a2face30f8133e0ecf1522348d1ca68499 was independently
reviewed before compilation; it has not been amended.

Author and root each actually completed the exact frozen harness: 196 commands,
13 integration tests per profile, six correct and 44 compiled-mutant full-state
streams of 912 cases. All 22 mutants were compiled in debug and release. The
19 native controls distinguish native cases; three safe-policy-only controls
leave native cases unchanged. All 50 corresponding value streams match across
the two independent host runs. Native correspondence remains conditional on
the stated stable post-worker state, valid spans, framed successful allocation,
copy/compare and ordinary-return premises; two same-project reviewers/builders
do not create an independent target lineage.

Public author evidence starts at rust-validation/VALIDATION.md and
rust-validation/receipts/results.json. AUTHOR-ARCHIVE-AUDIT.json rehashes the
392 raw stream references and 100 privately retained compiled artifacts.
Same-path clean artifact identity passes. Separate-directory debug client
bytes differ, including across root/author runs; both-profile rlibs and release
clients match. No masks, normalization or explanation of inequality is asserted.
Compiled bytes stay private; raw command stdout/stderr are published unchanged.

The first root attempt stopped before Rust compilation because captured data
was missing from the sparse checkout; its raw traceback was not rewritten.
FIRST-ROOT-ATTEMPT.json records that failure and exact capture hydration. The
successful runs use fresh output roots. There was no captured execution,
emulation, captured linking, live network/funding operation, full repository
suite, merge or deployment performed by this implementation qualification.

Use the frozen reproduction instructions in rust-validation/README.md with
actual pinned toolchain/SDK/provider prerequisites and a fresh output path.
IMPLEMENTATION-MANIFEST.sha256 and FINAL-AUTHOR-FREEZE.json bind the additive
public author distribution; root review/publication receipts may be added later
without changing its entries or any earlier freeze.
