# Node #115 open-PR integration validation

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The active PR review was blocked by malformed manifest separators and
historical root-document references resolving to newer or packet-local files.
`metadata-repairs.json` records the minimal metadata repairs. Original submitted
manifests and every affected historical root document are retained byte-for-byte.
The uncommitted CPython cache row is excluded from the active manifest; its
original declaration remains in the retained submitted manifest.

No raw binary evidence is rewritten, no instruction execution is claimed, and
no component reconstruction gate is advanced. The reviewed publication batch contains 1,147 PR heads; 41 out-of-scope PRs were closed, 57 await separate differential-execution approval; the prior-corpus blockers are now repaired. See `reviewed-pr-heads.json`, `held-pr-heads.json` and `validation.json`.

The compaction-dump model now wraps packed integer lanes at their observed
widths. Boundary controls and the host-libc test corrections are recorded in
`review-corrections.json`; all 71 focused tests pass. These are bounded
research-model checks, not a reconstructed-node execution or identity claim.

## Final review validation

All 970 authorized test files pass. The 23 remaining pre-existing test files
require instruction/native execution and were not run. All 616 selected static
packet verifiers pass, including the explicitly qualified renderer and
provider-version cases. The final changed-export audit byte-checks 550,472
recorded instruction rows with zero mismatches; it is not function coverage
or whole-node equivalence. All 38 top-level Cargo components tested pass;
two additional retained flat Rust libraries pass. Five nested helpers cannot
be tested standalone under `--locked` because they have no own lockfile, and
are covered by their passing parent builds.

`make doctor catalogue verify catalogue-check reproduce` passes with
Python 3.13 and the recorded GNU/LLVM analysis tools. Original raw exports,
negative results and comparison logs remain retained. No reconstruction gate
is changed. Captured binaries and original-instruction interpreters were not
executed. The publication commit skips automatic hosted CI because the existing
workflow runs unrestricted `make test`; this does not assert hosted CI success.

The review corrects packed-lane overflow, keeps both colliding RE-005/RE-006
modules, removes author-private temporary-directory dependence, makes a
citation-aware overlap check, and makes the profiling overlap mutant fail
for overlap independently of manifest integrity. Every correction and the
original affected manifest is retained in this packet.

PR #2721 was subsequently reconciled against the pinned, already merged
PR #2647 record. D is retained as reused context and earns no additional
coverage credit. Its 14 focused tests pass. The original submission README
and manifest remain under `submitted-pr2721/`.

## Public prior-corpus repair

The 73 remaining static comparison PRs now use a frozen manifest of 1,211
public record files. The earlier large private-worktree counts are preserved
as historical reports; they are not treated as reproduced evidence or as
coverage metrics. The record manifest, helper and original submitted
manifests are retained here. All 73 focused test files and all 73 direct
static checkers pass; eight helper tests exercise integrity, missing-input,
path, candidate-overlay and reference-identity controls.

The scan also handles valid annotated ranges, numeric coordinates, and
address-plus-size entries exposed by the larger reference set. Stale
next-work suggestions may now be documented by a later pinned packet; that
adds no new coverage credit and does not relax the current-window overlap
check. Committed packets are validated by exact reference identity and
recorded base ancestry. No target instructions were executed. Full receipts
are in `prior-repair-validation.json`.
