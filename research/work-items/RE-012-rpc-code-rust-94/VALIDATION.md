# Validation scope and results

- Target/source admission: the full node #94 size and SHA-256 are rechecked before static analysis; fresh records equal `evidence.json`.
- `make doctor verify catalogue-check reproduce`: pass in this independent checkout after materializing pinned submodules/LFS inputs. All eight artifact hashes/sizes, all three executable signatures, 38 imports and source pins pass. No imported input or pin is changed.
- Environment: macOS arm64, Python 3.11.15; GNU binutils 2.45 (x86-64 ELF support), GnuPG 2.5.24, Git LFS 3.8.1, rustc 1.94.1. Java/Ghidra are optional and not used by this bounded validation.
- Existing relevant static suite: 6 tests pass, zero skips, in `rpc-existing-tests.log` retained locally under ignored `work/`.
- New independently linked Rust validation: 135,171 cases in each of three builds, zero mismatches; all 5 compiled semantic mutants detected. Unit-test output and reproducible corpus/build hashes are retained in this packet. Own optimized library rebuild hashes agree.
- The unchanged repository-wide 971-file inventory is being validated once in the separate local-height checkout. This branch adds only an isolated module and its packet, with no shared tools, existing tests, build configuration, catalogue or gate changes. A whole-suite run on this exact new PR head is not claimed; the direct component build, corpus and relevant static tests above are its validation boundary.
- `rustfmt --check`, packet SHA manifest and `git diff --check` are checked before submission.

Original node/visor execution, native carved code, instruction emulation engines, filesystem/chain operations, networking against Hyperliquid, Docker node acceptance and original ELF equality are not performed. Static-derived agreement is not runtime equivalence. No optional private traces or usage logs are uploaded.
