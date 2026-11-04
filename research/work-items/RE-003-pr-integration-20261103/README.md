# RE-003: node #115 PR integration, 2026-11-03

- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: which of the 609 open PRs advance this target, and can their admitted
  evidence and independent components pass combined validation?
- Decision: 521 reviewed heads included; 88 PRs closed under the current scope
  policy (85 unsupported standalone tooling changes and three #94-only packets).
  Exact heads and individual dispositions are recorded beside this file.
- Scope: bounded evidence and independent implementations. All 92 full-component
  gates stay false. No captured execution or integrated node acceptance claimed.

## Review and concrete progress

The mixed-release FDE-gap PR is migrated to #115 rather than relabeled. Two fresh
native regenerations agree, 33 focused/shared tests pass, and nine raw island
exports match 63,546 target bytes. Its 16 entries do not establish complete
function ownership. Historical #94 outputs and CLI support are removed.

All 25 independent implementation PRs pass their 50 debug/release test jobs.
The review also runs full frozen/formula corpora and negative controls where
ordinary Rust test counts are zero. Exact commands, source hashes, native
bindings and scope are in `implementation-review.json`; this does not prove
machine-code identity or complete caller integration.

The native audits authenticate every declared complete FDE they admit, decode
it completely and check retained byte records. The result is bounded by the
declared ranges. Own-built source addresses, encoded LSDA tuples, constructed
store values, counted strings and negative controls use different coordinates;
their explicit qualifications are retained rather than treated as target code.
Eleven packet-only validators and the additional ELF/literal census checks pass.

The dependency census authenticates 7,882 source/target slices, their real
relocation fields and provenance. The standard-library census reproduces from
the locally installed pinned Rust 1.95.0 artifacts. Vendor builds are not
repeated here. Catalogue totals are 7,884 aligned dependency windows covering
5,313,802 bytes, with 4,964,007 raw-equal positions and 507 raw-equal windows.
All differences are explicitly relocation-qualified; unresolved call targets,
data/ABI closure and source-build provenance limits remain open. Two unequal
socket2 candidates remain separate. The earlier unequal mio candidate is
preserved inside its accepted interval's `prior_candidate`, avoiding overlap.
No dependency bytes count as reconstructed first-party component bytes.

## Integration blockers repaired

The old test runner silently omitted function-style and standalone test files.
It now chooses isolated unittest, pytest or explicit script execution from the
module structure. Real failing function, script and top-level assertion tests
verify propagation. Pytest is pinned in CI and plugin autoload is disabled.
Three pre-existing suites interpret captured instructions by default; those
classes now require explicit opt-in authorization and are skipped in this run.

Two generators selected macOS LLVM through `/usr/bin/objdump` while passing GNU
options and ignored its failure. They now use the selected tools on PATH and
check exit status. Reproduction compares unchanged native output after only
filename-header normalization. A checkpoint test accepts the recorded provider
version difference while retaining all other reproduction comparisons. Three
import-time check scripts gain explicit entrypoints; their model behavior is
unchanged.

One packet was missing its generated record; its existing authenticated
extractor and corruption controls now reproduce the added evidence. One
manifest used an invalid separator; another retained four stale hashes already
in its submitted head. Their originals and failures are preserved, and fresh
native verification precedes rebinding. Prior shared-tool/test input bytes are
kept under the owning packet so historical hashes remain valid. 119 inline
archive blobs receive exact path attributes that preserve their original Git
bytes rather than silently converting them to LFS pointers.

## Validation and remaining limits

The complete current inventory is 573 files: 450 unittest,
76 pytest and 47 script modules. The initial four
failed modules are preserved separately; their corrected full reruns pass.
There are no remaining failing modules. Current source hashes match every
final result. Script model-check counts are distinct from unittest counts;
explicit skips and authorization boundaries are in `regression-validation.json`.
The full sweep is scheduled as sixteen isolated subprocesses using the same
`test_files` and `test_command` functions as `make test`.

`make doctor`, `make verify`, `make catalogue-check` and `make reproduce` pass
locally. GNU 2.47, LLVM 22.1.4, Capstone 5.0.7 and Python 3.13.2 are used for the
focused review. Original packet provider/version qualifications remain intact.
Generated README/progress tables are regenerated by `make catalogue`.
The original dirty working checkout is preserved; integration occurs in its
own worktree. Hosted CI remains separate from these local results.

Next question: connect one established #115 component to its actual caller and
dependency contract, retaining missing source/build/data/ABI and runtime gates.
