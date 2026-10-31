# RE-002: complete dynamic arrays before exact provenance

Component: build-provenance offline tooling. Base 1f8c67c63ca4794c9689235471c60297f8a5c985. Question: can an incomplete .dynamic array establish exact dependency and hardening facts? Reference code is not used. Scope is dynamic() in tools/build_provenance.py and one regression, not program-header layout or NOBITS ownership.

Target: node #94, SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f, verified by the regression before parsing. It reads the actual .dynamic records to locate their first DT_NULL. Six in-memory controls change only sh_size (at section-table file offset e_shoff + index * e_shentsize + 32): 0, 16, the DT_NULL-relative offset, 1, 15, and that offset plus 15. They remove the terminator or leave a partial Elf64_Dyn record. Physical payloads and captures are never rewritten or executed. A positive control ends the section immediately after the real complete DT_NULL and compares every derived fact against the untouched capture.

The ELF gABI defines Elf64_Dyn as two 64-bit fields and requires DT_NULL to terminate the array: https://gabi.xinuos.com/elf/08-dynamic.html . This is structural evidence, not a loader execution claim. Base dynamic() silently truncates partial records and reaches EOF without requiring a terminator, then derive() publishes a seemingly complete list of exact dependency/hardening values. The fix rejects partial entries and loop exhaustion without DT_NULL. Entries after a complete DT_NULL remain ignored, as the existing regression requires.

Reproduce from repository root on Windows/Python 3.12.14 with PYTHONUTF8=1 and PYTHONIOENCODING=utf-8:

```text
python -m unittest discover -s tests -p test_provenance_dynamic_completeness.py -v
python -m unittest discover -s tests -p test_build_provenance.py -v
python tools/build_provenance.py --check 94 115 visor
python -m unittest discover -s tests -v
python tools/doctor.py
python tools/artifacts.py verify
python tools/verify_imports.py
python tools/catalogue.py --check
python tools/reproduce.py
git diff --check
```

Before: three tests attempted, six failing corruption subcases; positive complete-array control passes. After: three tests pass; existing nine provenance tests pass, and the stored records for all three individually authenticated targets match unchanged. Transient original logs are retained under the preparation directory as dynamic-before/after/existing/records/full and dynamic-doctor/artifacts/imports/catalogue/reproduce logs.

Required broad checks are attempted, not claimed green. make is unavailable, so the listed Python commands implement its targets. Doctor reports missing GPG/native analysis/Rust tooling. Artifact byte hashes match before missing GPG stops signature verification. Import verification fails at the partial Windows reference checkout (reserved node/aux.rs); catalogue-check stays stale, reproduce stops at artifact verification. Full-suite result is recorded in the PR after completion; baseline281 tests had seven failures, 32 errors and nine skips.

Full suite completed: 284 tests in 106.723 seconds; seven failures, 32 errors, nine skips, matching the baseline failure counts. git diff --check passes.

No binary execution, recovered Rust, source-label validation, complete build recovery, function coverage, equivalence or progress gate is claimed. The metadata controls are not asserted loader-consistent. Captures, source pins and generated catalogues remain untouched. Next: maintainer reproduction with complete native prerequisites.
