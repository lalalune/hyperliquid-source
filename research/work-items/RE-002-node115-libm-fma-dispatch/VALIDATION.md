# Validation record

- Repository base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Host: macOS arm64; all node analysis was static over the Linux x86-64 ELF.
- Tools: Python 3.14.3; GNU Binutils 2.47.20260726.

## Checks

- `PATH=/opt/homebrew/opt/binutils/bin:$PATH make doctor` — passed;
  `analysis_ready: true`, exact rebuild readiness remains false.
- `make verify` — passed; signed artifacts, 32 imported files, pinned source
  repositories, and 2,145 packet manifests / 22,818 entries verified.
- `make reproduce` — passed; node #115 and visor inventories reproduced.
- `make catalogue-check` — passed; generated catalogue and progress tables
  match pinned inputs; the work-item inventory is 2,152.
- `python3 -B tests/test_node115_libm_fma_dispatch.py` — passed, 7 tests.
- The full `make test` suite was not run for this change. Its runner contains
  1,131 sequential files; a previous run was interrupted after about seven
  minutes while one existing static-analysis file consumed over two minutes of
  CPU. No full-suite result is claimed.

GNU evidence exports were generated with `objdump` and `readelf` 2.47.20260726;
the packet manifest binds each retained file. No captured executable was run.
