# RE-002: bind provenance facts to the authenticated input bytes

- Component: build-provenance tooling; no component gate requested.
- Repository base: `1f8c67c` (resolve with `git rev-parse 1f8c67c`).
- Targets: node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes; node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes.
- Observation: `record()` checked the pathname using one open, then reopened it for `derive()`. An atomic pathname replacement between those operations binds #115 facts to #94's declared digest/size.
- Included: source-byte identity of the existing build-provenance extractor. Excluded: function mapping, source recovery, captured execution, any equivalence or security claim.
- No inferred/unlicensed reference source is copied or needed. Existing imported inputs, submodule pins and prior provenance packets are unchanged.

## Reproduction and result

Materialize the repository's LFS inputs and pinned submodules. From the repository root:

```sh
python3 -B tests/test_provenance_input_snapshot.py
python3 -B -m unittest discover -s tests -p test_build_provenance.py
python3 tools/build_provenance.py --check
make doctor
make verify test catalogue-check
```

The same native filesystem reproduction runs before and after the change. It copies the real #94 and #115 captures into a disposable directory, then replaces the analysis path immediately after its first real binary read closes. The test patches only this timing point: hashing and the actual ELF fact extraction run unchanged. The original captures are never modified or executed.

On the base, the replacement control fails: the result keeps #94's `sha256` and `size` but includes #115's compiler stamp `rustc version 1.95.0 (59807616e 2026-04-14)` instead of #94's `rustc version 1.94.1 (e408947bf 2026-03-25)`. The record's existing `file_offset` fields are the source-file coordinates for these observations; they are not linked VAs or rebased analysis addresses.

The corrected extractor reads once, checks the size and SHA-256 of that byte string against the existing manifest, then derives facts from the same bytes. All three regression tests pass: real atomic replacement, wrong release already present, and same-size single-byte corruption. `--check` reproduces all three existing records unchanged. This authenticates the analyzed snapshot; it does not promise that the pathname still names that snapshot after analysis.

## Environment and limits

Validated with Python 3.12.14 on macOS 26.4 arm64. Official Homebrew Git LFS 3.8.1, GnuPG 2.5.24 and GNU binutils 2.47 bottles were SHA-256 checked and relocated into task-local host tools after Homebrew's nested sandbox failed. Signature verification uses an isolated temporary GPG home and `--no-autostart`: no private key or personal keyring is read, and signature checking is not disabled. No captured executable is launched. Initial failed setup/test results are not evidence of a project defect.

No reconstruction progress gate changes. The next independent question is whether other extractors authenticate the same bytes they analyze; that audit is outside this bounded provenance correction.
