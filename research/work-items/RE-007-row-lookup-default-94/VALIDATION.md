# Validation record

Repository base `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, isolated Linux
x86-64 worktree. Versions and shared parser hashes are retained in
`validation/tool-versions.json`. No captured executable or instruction emulator
ran; no installer, credential/configuration change or live node service ran.

| Command | Observed exit | Retained evidence |
| --- | ---: | --- |
| `make doctor` | 0 | `validation/doctor.log`; analysis ready, exact rebuild not ready |
| `make verify catalogue-check`, command-scoped LFS settings below | 0 | `validation/verify-catalogue.log`; authenticated artifacts/signatures, 38 imported files, seven exact source pins and catalogue consistency |
| `make reproduce` | 0 | `validation/reproduce-receipt.json`; exact command, combined-output hash/size and local full-output path |
| `python3 -m unittest discover -s tests -p test_row_lookup_default94.py -v` | 0 | `validation/focused-tests.log`; nine tests, no skips |
| Installed GNU/LLVM decoder checker below | 0 | `validation/decoder-check.log`, `agreement.json`, eight complete native outputs |
| Two regenerations and four comparisons below | 0 each | `validation/regeneration.log`; all comparisons produced no output |

Exact native decoder check:

```sh
python3 research/work-items/RE-007-row-lookup-default-94/check_decoders.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump \
  --binary artifacts/node/94/hl-node \
  --out research/work-items/RE-007-row-lookup-default-94
```

GNU 2.44 and LLVM 19.1.7 agree on all 185 boundaries/byte strings across four
retained FDE ranges, 746 bytes total. The constructor is a rebound previously
studied dependency. No new Rust, byte-window credit, source-level boundary or
full-component equivalence claim follows from these counts.

Exact deterministic regeneration:

```sh
PYTHONHASHSEED=5 TZ=UTC python3 research/work-items/RE-007-row-lookup-default-94/verify.py --out work/regenerate-a
PYTHONHASHSEED=23 TZ=America/Los_Angeles python3 -O research/work-items/RE-007-row-lookup-default-94/verify.py --out work/regenerate-b
cmp work/regenerate-a/evidence.json work/regenerate-b/evidence.json
cmp work/regenerate-a/fixtures.json work/regenerate-b/fixtures.json
cmp work/regenerate-a/evidence.json research/work-items/RE-007-row-lookup-default-94/evidence.json
cmp work/regenerate-a/fixtures.json research/work-items/RE-007-row-lookup-default-94/fixtures.json
```

The seven pinned references were materialized from existing local sources with
no network download, after independently checking every HEAD against
`provenance/sources.json`. Each materialized LFS payload matched its committed
pointer's SHA-256 and size. The isolated reference's index cache was refreshed
under standard command-scoped LFS settings; no persistent Git setting or input
bytes were changed. The successful required check used:

```sh
GIT_CONFIG_COUNT=3 \
GIT_CONFIG_KEY_0=filter.lfs.clean GIT_CONFIG_VALUE_0='git-lfs clean -- %f' \
GIT_CONFIG_KEY_1=filter.lfs.smudge GIT_CONFIG_VALUE_1='git-lfs smudge -- %f' \
GIT_CONFIG_KEY_2=filter.lfs.process GIT_CONFIG_VALUE_2='git-lfs filter-process' \
make verify catalogue-check
```

Static controls deliberately call `structural()` without only the whole-file
SHA check, retaining complete body hashes, data/relocation checks and frozen
decode identity. They reject every recorded branch-byte mutation, layout and
caller-byte changes, FDE/CIE changes, default/descriptor changes and all recorded
RELATIVE target changes. They are byte-admission controls, not independent
semantic CFG proofs. Synthetic normal-table fixtures and constructor-defined
byte ranges are conditional models, not runtime comparison results.

The coordinator separately reviewed source/native ordering and reran all nine
focused tests. This lane does not claim a completed repository-wide suite,
hosted CI, runtime test, generic Once closure, full row reconstruction or gate.
The manifest covers every committed packet file except itself and the focused
test via its relative repository path. From this directory run
`sha256sum -c MANIFEST.sha256`.
