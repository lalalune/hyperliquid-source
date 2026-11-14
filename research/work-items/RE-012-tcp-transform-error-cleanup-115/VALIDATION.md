# Observed local validation

Execution `8943ff0f9fe8d195521677571066b29a` on pinned base
`a8616af9432b8d8517b2af677880e117b7c28ef3`:

- `python3 -B research/work-items/RE-012-tcp-transform-error-cleanup-115/verify.py`:
  actual capture authenticated; all 10 selected clause groups, 3 FDE/CIE
  records and 2 unique relocation writers passed.
- `python3 -B -m unittest discover -s tests -p test_tcp_transform_error_cleanup_115.py -v`:
  all 6 test methods passed in 4.443 seconds. Subtests cover 10 clause-byte
  corruptions, 3 FDE corruptions, 3 CIE corruptions and 2 relocation corruptions;
  CIE tests include the shared CIE once for each associated owner.
- `make doctor`: passed; analysis_ready=true, exact_rebuild_ready=false.
- `make verify catalogue-check`: passed before addition of the final packet
  manifest; post-manifest verification is run separately below.
- `make reproduce`: passed; reproduced node115 and visor static inventories.
- Python 3.11.11; GNU binutils 2.40; no captured binary executed.

Earlier execution `057cca41c3437ef04c5a2de630800526` passed the original five
methods before CIE controls and explicit relative-destination decoding were
added. It is not the final proof result.

Final local execution `4c2bcc8073ad1f09ad158f81047aaa25`:
- `make catalogue` regenerated only research inventory counts (3706 -> 3707),
  not implementation/component gates;
- post-manifest `make verify catalogue-check` passed (3728 manifests,
  29758 entries, zero dangling rows);
- all 6 scoped test methods passed again in 4.514 seconds;
- `git diff --check HEAD` reported no whitespace errors.

Independent reconstruction/validation and the full root suite remain pending.
Local tooling success is not target execution, native equivalence, hosted CI,
maintainer acceptance or a completed component gate.

## Bounded changed-environment recovery

Prerequisite execution `7e9b34b6f94e33b505dffcc8b23c2651` observed Python
3.12.3, preinstalled Rust 1.95.0, GNU binutils 2.42, and usable NumPy 2.3.5.
The previously incompatible checksum helper parses successfully under this
Python. Actual command output is retained in `environment-recovery.json`.

Local execution `e0e9d3fa0bfd594e2d6daacbf6b21b02` authenticated the same
node #115 capture and passed all 10 clause groups, 3 FDE/CIE records and 2
relocation writers. All 6 scoped tests passed in 4.432 seconds. The two
previously unpaired objdump-rendering failure modules were checked directly:
`test_innermost_records_static.py` passed all 7 tests in 37.744 seconds and
`test_join_helper_element_static.py` passed all 9 tests in 30.151 seconds.
Exact commands, stdout and stderr are in `recovery-scoped-run.json`.

This is local recovery evidence, not independent baseline equivalence or a
full-suite pass. Earlier independent validation
`1a0d5996e27b4c1a98be80c4a247038b` remains rejected; it had observed failures
and two incomplete 3600-second globals. A new independent reconstruction
on the changed image is required before publication. No captured execution.
