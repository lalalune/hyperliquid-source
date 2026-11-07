# Node #115 open-PR review on 2026-11-07

This review integrates 400 exact PR heads into the original main
revision `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. The target is Linux x86-64
node #115 with SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
`reviewed-pr-heads.json` identifies every PR and reviewed head.
`review-results.json` preserves individual findings and validation.

## Scope and observations

The submitted changes resolve bounded reverse-engineering questions, add
independently authored reconstructions, and retain target-bound evidence.
The review checked actual changes, target identities, available manifests,
negative controls, scope claims and relevant build or reproduction paths.

The integration preserves PR heads as merge parents. Follow-up commits
repair findings before publication. `integration-corrections.json` records those
commits and original failed or deferred test attempts.

Findings included private-worktree assumptions in prior-evidence readers,
incorrect iterator and ring-overflow behavior, stale evidence references,
binutils display differences, a census search range mistaken for function
ownership, overbroad logger interpretations, and parser models that erased callee errors or guessed helper output. Corrections preserve original
target exports and authenticate historical inputs. Four fixture mutators now
read their existing byte buffers directly, avoiding repeated whole-image copies
while preserving selected values and mutations.

The StatisticsImpl suite contains 130 top-level checks. Its prior dispatch to
unittest reported zero tests under Python 3.14. The runner now recognizes that
explicit check form. Sixteen runner regressions pass. Comparing dispatch for
all 1,127 files present at that point changed only the StatisticsImpl route.

## Validation

All 1130 current flat test modules have passing source-hash-bound receipts
in `test-results.json`. Baseline modules ran through repository per-file commands
in clean isolated worktrees, one child process per file. Changed modules and new
suites ran separately against final source. Original nonzero results remain
recorded alongside corrected-source passes. Configured opt-in execution skips
remain in force.

Four new numeric generators independently reproduced all 55 retained output
files byte-for-byte. `generator-results.json` records their results. Bounded
arithmetic checks, relevant Rust builds, and late-arriving static verifiers are
recorded in per-PR reviews. Captured node and visor executables were not run.
Bounded Python instruction interpreters and independently authored compiled code
were exercised.

Final repository checks are recorded in `validation.json`. Reproduction uses
authenticated repository artifacts, Python 3.14.8, Rust 1.95.0, Capstone 5.0.7 and
pyelftools 0.33. Legacy packet verifiers retain their explicitly pinned Capstone
5.0.6 and pyelftools 0.32 environment. Raw test logs remain in local ignored work
storage, with SHA-256 receipts retained here.

## Completion and remaining work

Completion gates remain 0 of 92, or 0.00%. Selected aligned comparisons cover
5,313,802 of 83,719,936 target text bytes, or 6.34712%. Raw-equal bytes total
4,964,007, or 5.92930%. These bounded submissions earn no additional full-scope
gate or compiled-code window credit. Generated documentation is rebuilt from
owning progress and catalogue inputs.

The next review question is whether a component's complete mapped scope has the
implementation, adversarial behavior checks, and code/data/helper closure needed
to satisfy its existing acceptance gates. Individual bounded results and passing
local tests leave that component-wide work open.
