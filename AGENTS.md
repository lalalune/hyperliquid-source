# Agent instructions

## Primary objective: complete the node reverse engineering

**100% of active reconstruction work targets Linux x86-64 node #115**, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
This is the sole node implementation and acceptance target. Do not open new
#94-only tasks, implementations or PRs. Work on older material is justified
only when it directly advances #115 and is validated against that target.
Review incoming PRs against this same target: migrate reusable code only with
#115 validation, and close obsolete #94-only changes. A release-label edit is
not migration evidence. The focus is exclusive; reconstruction remains incomplete.

All agent work, PRs and submissions must focus on reverse engineering the node's
code. Hillclimb completion by choosing bounded work that resolves binary-backed
unknowns, reconstructs established semantics or validates the reconstruction
against the target. Report concrete evidence of progress; retain the full-scope
acceptance gates below and do not inflate completion for partial work.

Modify tooling, infrastructure, workflows or surrounding architecture **only
when an active reverse-engineering task is blocked**. Record the task, evidence
of the blocker and why existing tools cannot support it. Make the smallest fix,
verify that the blocked work can proceed, and immediately resume reverse
engineering. Convenience, speculative improvements and architectural preferences
are not blockers. This restriction applies even to tasks listed in the queue.

**Window dressing, cosmetic cleanup and inconsequential PRs or submissions will
be closed.** Do not spend agent work on standalone tooling polish, refactors,
documentation churn or surrounding architecture changes without a demonstrated
blocker. Preserve useful documentation of new binary findings in evidence packets.

## Read first and preserve scope

Read CONTRIBUTING.md, docs/SCOPE.md, docs/PROGRESS.md, docs/TASKS.md and docs/REA.md.
Node #115 is the sole Linux x86-64 node implementation target. Older material
is migration input, not a maintained target or a prerequisite to finish.
Validate reused code, addresses, layouts and behavior against #115 before
crediting them. Retired code that cannot be validated belongs in Git history,
not a parallel active implementation. Visor work is justified only when needed
to deliver #115 and retains its own artifact identity. Use
provenance/artifacts.json for full SHA-256 values; bind every result to one.

This is an independent Rust reconstruction project. No full node build or
binary-equivalence claim exists yet. New implementation must be independently
authored or reused from licensed public source. Do not copy unlicensed inferred
code, fabricate Cargo graphs, or treat a successful local build as equivalence.
Every active component needs a documented #115 scope and real dependencies.

## Workflow and ownership

1. Pick a task/component and bounded question. Inspect current work before
   overlapping it; note the task ID and intended files in the change.
2. Run `make doctor`, `make verify`, and inspect the relevant catalogue/seed
   records. Query focused addresses and xrefs before broad decompilation.
3. Keep observations, inferred names/types and unknowns separate. Comment seeds
   and executable-section membership do not establish function boundaries.
4. Save reusable evidence under research/work-items/<id>/ using the template.
   Put transient output and Ghidra projects under ignored work/.
5. Implement only established semantics; record assumptions explicitly. Test
   against target-grounded expectations with boundary and corruption controls.
6. Update progress only for a reviewed full-scope gate. Report partial results
   honestly and leave unfinished gates false.

Do not launch parallel agents by default. Delegate only when the user asks or
an applicable task instruction explicitly requires it. If delegated, assign
non-overlapping files/components, one target digest and a defined evidence
return format; a worker's status message is not validation.

## Evidence, data and tool rules

- Do not modify imported evidence or advance submodule commits implicitly.
  Preserve hashes, signatures, licenses and original negative results.
- `make index` parses unwind start tables only. It does not establish all
  functions, exact body sizes or component ownership. Use actual FDE/CFG/data
  analysis before publishing a matched-window denominator.
- Use the connected REA server directly when available; pin CLI work through
  `python3 tools/rea.py` (6.8.0). `make rea-doctor` checks the selected native
  provider; `make rea-install` restores its lockfile. Do not rerun user-level
  registration setup when a working connection already exists.
- Prefer installed native tools; `make doctor` reports their availability.
  Ghidra/IDA/REA are analysis providers, not evidence by themselves. Preserve
  options, tool versions, completeness, input digest and exported records.
- Keep raw comparison output. State normalization masks and track helper,
  call-target, relocation, vtable/data and whole-ELF gaps separately.
- Avoid whole-node rewrites from prose or artificial byte transplantation.
  Matching source text and passing self-derived tests are not target equivalence.
- Captured node/visor execution, private keys, chain actions, public networking
  and paid dataset sync require explicit authorization. Static parsing,
  disassembly and digest-specific Ghidra analysis are in scope.
- No secrets, personal runtime state or unsanitized user fixtures in commits.
  New code is MIT; upstream material keeps its own terms.

## Validation and reporting

Run `make verify test catalogue-check` for repository/tooling changes.
Run `make reproduce` when changing inventory/literal analysis or interpreting
those inputs. Regenerate with `make catalogue`; never hand-edit generated
PROGRESS.md, COMPONENTS.md or research/catalogue files. Check only relevant
builds/tests beyond these; do not claim hosted CI or container success without
its actual result.

Report changes, verification scope, failures and remaining gaps. A complete
task must satisfy its original acceptance criteria, not just pass a narrower
check. docs/PROGRESS.md is milestone completion; it is not proof of correctness,
function coverage or remaining engineering effort.
