# Validation receipt — 2026-10-30

Baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

No captured executable was run. All target interaction was static file
reading. Mutation controls used disposable in-memory byte arrays.

| command | result |
|---|---|
| `make doctor PYTHON=python3.14` | PASS: `analysis_ready=true`; `exact_rebuild_ready=false`; Java/Ghidra and rustc 1.95.0 unavailable |
| packet verifier, ordinary Python | PASS |
| packet verifier, `python -O` | PASS |
| `unittest` for `test_timeout_round_transition.py` | PASS: 16/16 |
| `cargo fmt --check` for the narrow model | PASS |
| `cargo test` for the narrow model | PASS: 10/10 unit tests; 0 doc tests |
| `make verify` | PASS: all pinned artifacts/signatures plus 37 imported files |
| `make catalogue-check` | PASS |
| `make reproduce` | PASS: inventories, raw counts, and refined item classifications reproduce |
| `git diff --check` | PASS |

## Full-suite tool qualification

The first plain macOS run of `make test` used Apple LLVM objdump 21.0.0 and
had no `readelf` on `PATH`. It completed with 373 tests reported, 4 failures,
12 setup errors, and 15 skips. The failures were existing binutils-interface
assumptions: AT&T checks expect GNU `lea` rather than Apple's `leaq`, parsers
expect GNU output, and several tests directly invoke `readelf`. All 16 new
RE-008 tests passed during that failed aggregate run.

Homebrew GNU binutils 2.47 was already installed. The qualified rerun was:

```text
PATH=/opt/homebrew/opt/binutils/bin:$PATH \
  make test PYTHON=/opt/homebrew/bin/python3.14
```

Result: **PASS, 447/447 tests** in 124.844 seconds.

The repository was not changed to accommodate the host-tool difference.

After the final caller-local mutation-claim wording change, a second complete
447-test attempt reached 446 passes and one environment error: a pre-existing
foundation-hour corruption test could not write its 91,774,280-byte temporary
copy because the shared volume returned `ENOSPC`. The new RE-008 module was
green in that run. The affected `test_foundation_hour.py` module was then run
alone after temporary space was released and passed 10/10. No source or test
expectation was changed in response.
