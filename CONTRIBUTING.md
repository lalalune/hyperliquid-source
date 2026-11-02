# Contributing

Start with [scope](docs/SCOPE.md), [current progress](docs/PROGRESS.md),
[component map](docs/COMPONENTS.md), and [ready tasks](docs/TASKS.md).
For REA CLI/MCP configuration and supported Node versions, see [REA.md](docs/REA.md).
**We are 100% focused on reconstructing Linux x86-64 node #115**, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
It is the sole node implementation and acceptance target. This describes our
focus, not completion: the integrated node is still being reconstructed.

All research, implementations, tests and PRs must advance #115. New #94-only
work is out of scope. Older code may be reused only with #115-specific evidence;
unvalidated retired implementations belong in Git history, not a second active
target. Supervisor work is in scope only when required to deliver #115.

## Acceptance priority: complete the node reverse engineering

Every PR and submission must focus on reverse engineering the node's code and
hillclimb toward completion: resolve a concrete unknown with binary evidence,
recover established semantics in independently authored Rust, or validate the
reconstruction against the target. State the task/component, the gap addressed,
and the evidence of progress. Bounded partial results are welcome when they
advance that work; they do not justify marking an unfinished gate complete.

Changes to tooling, infrastructure, workflows or surrounding architecture are
allowed **only when an active reverse-engineering task is blocked**. Identify
the blocked task, provide evidence of the blocker, explain why existing tools
cannot support the work, and make the smallest change needed to unblock it.
Include validation that the blocked work can proceed, then return to reverse
engineering. General convenience, speculative future needs and architectural
preferences do not qualify as blockers.

**PRs and submissions consisting of window dressing, cosmetic cleanup or other
inconsequential changes will be closed.** Standalone tooling polish, refactors,
documentation churn and surrounding architecture changes without a demonstrated
reverse-engineering blocker will also be closed. Documentation of new binary
findings and evidence belongs with the corresponding research contribution.

## Set up and choose work

```sh
git clone --recurse-submodules https://github.com/lalalune/hyperliquid-source.git
cd hyperliquid-source
./scripts/setup.sh
make doctor
make verify test catalogue-check
make index
```

Choose a small question and component ID, note its task ID in an issue/PR,
and work on a descriptive branch. Keep shared reference submodules pinned
and untouched. Generated analysis and disassembler databases belong in work/.
Commit durable, compact evidence under research/work-items/<task-id>/.
The [packet template](research/templates/EVIDENCE.md) specifies required fields.

## Contribution types

- Static research: exact target, validated addresses/ranges, xrefs, instructions,
  source/data attribution, inferences and unresolved questions.
- Implementation: independently authored Rust, target ABI/layout, pinned
  component build and lockfile, helper closure and evidence-backed tests.
- Tooling or surrounding architecture: only the minimal fix for a demonstrated
  reverse-engineering blocker under the policy above. Require deterministic
  offline outputs, explicit input hashes, malformed-input checks where
  appropriate, and no implicit execution of captured binaries.
- Review: reproduce the claimed build/checks and attack the comparator with
  corruption controls. Missing evidence remains a gap even if code looks right.

There is intentionally no root Cargo workspace yet. Add a real component
manifest only when its dependencies and build behavior are established. Do not
turn the inferred reference tree into an apparently recovered workspace using
arbitrary dependency versions or placeholder implementations.

## Required evidence packet

Include the target SHA-256/release, component and bounded question; source and
reference revisions; original addresses plus their coordinate system; tool
versions and analysis options; exact commands; observations with supporting
files; clearly separated inferences; before/after build/comparison results;
negative controls; limitations and a next step. Cite the relevant binary bytes,
not only the can1357 narrative. An address in its comments is an unverified seed.
Never publish private keys, tokens, home-directory state or live user datasets.

Rust reconstruction is required for implementation claims. Hand-patched or
transplanted original machine code is not reconstruction. Preserve raw results
and state every normalized operand. Matching functions still need their calls,
data, relocations, vtables and layout checked; passing a test of your own newly
invented behavior does not validate the target.

## Validation and progress updates

Run the checks that cover your change:

```sh
make verify                 # authentic inputs and unchanged imports/pins
make test                   # offline tooling controls
make catalogue-check        # generated scope/progress consistency
make reproduce              # if literals, inventories or evidence interpretation change
```

Run `make catalogue` after an approved edit to research/components.json or
research/progress.json and commit generated tables/catalogues with it, including
the README progress block. `make catalogue-check` also detects README progress
drift; text outside its generated markers is preserved. Do not edit generated
tables directly. Completion is four reviewed component gates;
only mark a gate true with a packet covering its entire scope and an evidence
path in the progress record. The consistency check verifies paths and structure;
it is not a semantic proof or a substitute for review. Partial results keep
component gates false and are recorded in their work item.

Once measured function windows exist, report raw-equal, normalized-only and
unmatched counts over an explicit denominator. Do not substitute source-file,
line-count, unwind-index or string coverage for these counts.

Register selected compiled-code comparisons in `research/byte-windows.json`,
including target and source hashes, reviewed bounds, original evidence and any
actual relocation records. `make catalogue` rechecks the bytes and generates
`research/catalogue/byte-coverage.json` and the tables. Count overlapping or
alternative candidates once per target. These selected-window percentages do
not supply a whole-module denominator or advance any acceptance gate.

When complete source and target extents differ, register
`comparison_mode: "extent-mismatch"` and the full `source.length`. Keep both
body hashes and the comparison evidence; do not truncate or pad a candidate to
fit. The catalogue lists these unmatched candidates separately, without an
aligned-byte comparison or credit in aligned-window totals. Shared relocation
masks and aligned-byte metric fields are not accepted for this mode.

Tag shared upstream windows with their `dependency` identity. The `component`
field then records the research allocation only: aligned dependency windows
count in target totals and the dependency table, never as reconstructed
first-party component bytes. Unequal-extent candidates remain separate.
Zero registered comparisons is a count, not a claim of zero
correct code. Keep unmeasured whole-component denominators explicit.

## Licensing, execution and review

New code/docs use MIT. Imported sources and binaries retain upstream rights;
can1357's unlicensed source is a research reference, not a grant to copy code
into the MIT implementation. Attribute evidence and preserve upstream notices.

The default workflow is static. Running captured binaries, networked services,
chain actions or signing requires explicit authorization and an isolated
harness with declared effects. Static Ghidra imports are allowed; they can be
large, so reuse a digest-specific project. Scope/release changes belong in the
PR description. Include checks run, exact outcomes, known gaps and any progress
change. Never merge an implementation claim based only on green tooling CI.
