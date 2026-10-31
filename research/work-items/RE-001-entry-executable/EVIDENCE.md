# RE-001: executable entry-file selectors

Component: node-runtime (shared tooling with visor). Question: can the entry
selector select file-backed data as code? Status: observed tooling defect.
No reconstructed behavior, function boundary or gate claim.

Base: 1f8c67c63ca4794c9689235471c60297f8a5c985. Reference:
can1357-hl@999556f6e0a474b8312db96ec3149e1c44e97c23; no reference code copied.
Full input SHA-256 values, sizes, linked ELF entry VAs, source file offsets and
section coordinates are in results.json for node #94, #115 and visor.
All captures are authenticated before mutation. Python 3.12.3, Linux x86-64.

## Observation and fix

tools/rea_mcp_check.py uses entry_file_offset to construct a source-file-offset
selector for native-smoke decompilation. Its old mapping accepted every
file-backed section, including non-executable .rodata. The helper now requires
SHF_EXECINSTR as well as file backing and one unambiguous resulting offset.
This preserves the coordinate system and return type.

For each authentic ELF, two controls change only metadata in owned memory:
set e_entry (ELF file offset 24) to the real .rodata VA; or clear SHF_EXECINSTR
in sections containing the authentic entry. Base accepts all six controls.
Fixed code rejects all six. Untouched entry offsets remain equal for all three.
No capture is modified on disk, and no capture or analysis provider is executed.

## Reproduce

From repository root with pinned LFS objects materialized and native
prerequisites on process-local PATH:

    python3 -m unittest discover -s tests -p test_entry_executable.py -v
    make doctor verify test catalogue-check reproduce
    git diff --check

Before: run the new regression with the base tools/elf_index.py: 3 tests,
6 subtest failures, each ValueError not raised. After: 3 tests pass.
The test verifies full SHA-256 before mutations; missing LFS objects are skipped,
not replaced with synthetic captures. Existing entry-offset tests are covered
by the complete suite. validation.log records actual required checks.

## Limits

These controls test the parser below the identity gate, not loader validity of
mutated captures. Execute flags do not prove function boundaries or complete
program-header mapping. Native smoke is not run; no decompilation, target
equivalence, progress, pins or acceptance gates change. Next question: review
whether program-header permissions should additionally constrain entry mapping.

## Observed validation

make doctor verify test catalogue-check reproduce exited 0. Doctor reports
analysis_ready=true and exact_rebuild_ready=false (unrecovered implementation).
All 434 tests passed in 157.674 seconds. All 37 imported files and pinned sources
verified; catalogue outputs are current; inventories, raw counts and refined
classifications reproduce imported evidence. git diff --check passed.
The process-local PATH supplied the already-installed git-lfs/ripgrep runtimes
and standard native tools; no installation or captured execution was performed.

Live duplicate check: all-state GitHub PR inventory (419 PRs, 2026-10-31) and
open issues (none) inspected. The originally suggested NOBITS candidate was
abandoned because open PR #101 covers it exactly. PR #110 covers unwind section
coordinates; #344 covers unwind-header truncation; neither changes entry mapping.
No entry executable/mapping/selector duplicate was found in the final search.
