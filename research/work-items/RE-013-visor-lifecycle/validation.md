# RE-013 validation results

Host: macOS arm64; Python 3.9.6; Apple LLVM 21.0.0.  Absolute workspace
paths are omitted from this retained summary.

| Command | Result |
| --- | --- |
| `python3 tools/visor_lifecycle.py --binary artifacts/visor/captured/hl-visor --output ... --disassembler llvm-objdump` | PASS; authenticated 8,305,392 bytes, 11 exact FDE ranges, 30 instruction controls, 17 RIP references plus 2 relocated metadata descriptors, and 15 direct/import/relocation call edges; 8 bounded disassembly files written |
| `python3 -m unittest tests.test_visor_lifecycle -v` | PASS; 5 tests, 0 failures/errors/skips |
| `make verify` | PASS after initializing the repository-pinned submodules; all artifact SHA-256 values and three signatures valid, pinned upstream binary/key/signature match, 37 imported files and all source repositories verified |
| `make test` | **NON-PASS**; 362 tests run in 96.888s: 4 failures, 12 errors, 15 skips |
| `make catalogue-check` | PASS; catalogue and progress tables match pinned inputs |
| `git diff --check` | PASS |

## Repository-wide test limitations

The 5 new lifecycle tests passed within `make test`.  The repository-wide
target was not green on this host.  The failures were unrelated to RE-013 and
fell into two pre-existing host-tool categories:

- GNU-binutils formatting assumptions with Apple `llvm-objdump`:
  `test_consensus_wire.test_objdump_tag_leas`,
  `test_info_request_path.test_objdump_tag_leas`,
  `test_state_hashers.test_objdump_call_sites_from_function_start`, and
  `test_state_roots.test_objdump_literal_leas` failed regexes because Apple
  emits `leaq`, register spacing, and different operand syntax.  The same
  decoder difference caused setup errors in `test_evm_amount_scale`,
  `test_spot_wei_scale`, and `test_wei_buffered_cap`.
- GNU `readelf` is absent: two `test_exchange_dispatch` cases and the
  `test_truncated_debug_static` setup errored.  Other tests correctly skipped
  15 binutils/readelf-dependent cases.

No project file was changed to accommodate the host.  A GNU/Linux/binutils
rerun remains required before treating the complete repository suite as green.

The first `make verify` attempt also correctly stopped on an uninitialized
submodule.  A subsequent LFS checkout attempt encountered a full disk; the
already-authenticated node-94 bytes were installed into the exact pinned
reference checkout using an APFS clone, the remaining source-only submodules
were checked out with LFS smudging disabled, and the final `make verify` passed.
No imported binary evidence was modified.
