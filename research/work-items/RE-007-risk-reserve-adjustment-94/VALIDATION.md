# Validation record

Working directory: repository root of the isolated worktree, base
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; Linux x86-64. Tool versions and
shared parser hashes are in `validation/tool-versions.json`. All captured
artifacts remained inert; no node/visor, emulator, service, signing operation,
credential operation, package installer or external publication ran.

| Command | Observed exit | Retained evidence |
| --- | ---: | --- |
| `make doctor` | 0 | `validation/doctor.log`; analysis ready, exact rebuild not ready |
| `make verify catalogue-check` with invocation-local LFS filters below | 0 | `validation/verify-catalogue.log`; artifact hashes/signatures, 38 imported files, seven exact source pins, catalogue/progress consistency |
| `make reproduce` | 0 | `validation/reproduce.log`; existing inventories and literal classifications reproduce |
| `python3 -m unittest discover -s tests -p test_risk_reserve_adjustment94.py -v` | 0 | `validation/focused-tests.log`; seven tests, no skips |
| `python3 research/work-items/RE-007-risk-reserve-adjustment-94/check_decoders.py --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump --binary artifacts/node/94/hl-node --out research/work-items/RE-007-risk-reserve-adjustment-94` | 0 | `validation/decoder-check.log`, `agreement.json`, four raw decoder outputs |
| `verify.py --out work/regenerate-a` and `python3 -O verify.py --out work/regenerate-b`, using the full packet-relative script path | 0 each | `validation/regeneration.log`; commands and byte comparisons below |

The focused tests compare the 1,300-value binary64 model against a separate
integer/fraction rounding oracle, and detect the exact-101/100 replacement on
66 values. Their static corruption controls deliberately call `structural()`
without the whole-file digest check, leaving full-body hashes and structural
checks active. They prove byte admission and model distinctions, rather than
native execution or a general semantic equivalence theorem.

Deterministic regeneration used these exact commands; all four `cmp` commands
exited 0 without output:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 research/work-items/RE-007-risk-reserve-adjustment-94/verify.py --out work/regenerate-a
PYTHONHASHSEED=17 TZ=America/Los_Angeles python3 -O research/work-items/RE-007-risk-reserve-adjustment-94/verify.py --out work/regenerate-b
cmp work/regenerate-a/evidence.json work/regenerate-b/evidence.json
cmp work/regenerate-a/samples.json work/regenerate-b/samples.json
cmp work/regenerate-a/evidence.json research/work-items/RE-007-risk-reserve-adjustment-94/evidence.json
cmp work/regenerate-a/samples.json research/work-items/RE-007-risk-reserve-adjustment-94/samples.json
```

Initial setup checks failed before local references were materialized, then
after cloning the seven local pinned references without their per-clone LFS
filter configuration. `validation/initial-verify-failure.log` retains the
second failure. The source clone's HEAD was independently checked against
each `provenance/sources.json` pin; each materialized LFS object was copied
only after checking its pointer SHA-256 and byte size. No remote LFS download
or persistent Git configuration change was made.

The command-scoped filter settings below restore the normal Git LFS clean
comparison for the local clone. The isolated reference's index stat cache
was refreshed with the same settings and
`git -C references/can1357-hl update-index --refresh -- bin/hl-node-mainnet-new`;
the following filtered status was clean. All imported bytes and pins were
then checked by the unchanged repository verification code:

```sh
GIT_CONFIG_COUNT=3 \
GIT_CONFIG_KEY_0=filter.lfs.clean GIT_CONFIG_VALUE_0='git-lfs clean -- %f' \
GIT_CONFIG_KEY_1=filter.lfs.smudge GIT_CONFIG_VALUE_1='git-lfs smudge -- %f' \
GIT_CONFIG_KEY_2=filter.lfs.process GIT_CONFIG_VALUE_2='git-lfs filter-process' \
make verify catalogue-check
```

The broad repository `make test` is delegated to the coordinator's integrated
checkout. It was not run to completion in this lane and no full-suite,
hosted-CI, container or captured-target result is claimed. All static checks
and focused tests above completed; there is no outstanding permission blocker.

The conventional `MANIFEST.sha256` covers every committed packet file except
the manifest itself and also names the focused test with a path relative to
this directory. Verify from this directory with `sha256sum -c MANIFEST.sha256`.
No unrelated manifest or progress record was edited.
