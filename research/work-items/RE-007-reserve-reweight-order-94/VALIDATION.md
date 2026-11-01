# Validation record

Working directory: isolated repository worktree at
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, Linux x86-64. Versions and shared
parser hashes are in `validation/tool-versions.json`. No captured code,
instruction emulator, service, installer, credential operation or external
publication ran. The numeric model is restricted to positive old/new divisors.

| Command | Observed exit | Evidence |
| --- | ---: | --- |
| `make doctor` | 0 | `validation/doctor.log`: analysis ready, exact rebuild not ready |
| `make verify catalogue-check` with command-scoped filters below | 0 | `validation/verify-catalogue.log`: artifacts/signatures, 38 imported files, all seven exact source pins, catalogue consistency |
| `make reproduce` | 0 | `validation/reproduce-receipt.json`: command/exit/output hash; inventories and prior literal classifications reproduce |
| `python3 -m unittest discover -s tests -p test_reserve_reweight_order94.py -v` | 0 | `validation/focused-tests.log`: eight tests, no skips |
| `check_decoders.py` with full path/options below | 0 | `validation/decoder-check.log`, `agreement.json`, six decoder outputs |
| Two regenerations and four `cmp` commands below | 0 each | `validation/regeneration.log`; comparisons emit no output |

Exact decoder command:

```sh
python3 research/work-items/RE-007-reserve-reweight-order-94/check_decoders.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump \
  --binary artifacts/node/94/hl-node \
  --out research/work-items/RE-007-reserve-reweight-order-94
```

The checker decodes both full FDEs and the full existing caller from their FDE
starts. GNU 2.44 and LLVM 19.1.7 agree on every boundary and byte string.
Two full bodies retain 415 instructions; the caller has 600 decoded
instructions and only the eight selected link rows are retained. Complete
caller output hashes and a canonical complete boundary/byte hash are checked.
No semantic completeness is inferred from the decoding agreement.

Exact reproducibility commands:

```sh
PYTHONHASHSEED=3 TZ=UTC python3 research/work-items/RE-007-reserve-reweight-order-94/verify.py --out work/reweight-regenerate-a
PYTHONHASHSEED=19 TZ=America/Los_Angeles python3 -O research/work-items/RE-007-reserve-reweight-order-94/verify.py --out work/reweight-regenerate-b
cmp work/reweight-regenerate-a/evidence.json work/reweight-regenerate-b/evidence.json
cmp work/reweight-regenerate-a/samples.json work/reweight-regenerate-b/samples.json
cmp work/reweight-regenerate-a/evidence.json research/work-items/RE-007-reserve-reweight-order-94/evidence.json
cmp work/reweight-regenerate-a/samples.json research/work-items/RE-007-reserve-reweight-order-94/samples.json
```

The isolated references were cloned without network access from existing local
sources only after independently comparing every HEAD against
`provenance/sources.json`. Each materialized LFS object was copied only after
its committed pointer's SHA-256 and byte size matched. The isolated clone's
index stat cache was refreshed with normal LFS filters; persistent Git
configuration and all input bytes were preserved. Required verification used:

```sh
GIT_CONFIG_COUNT=3 \
GIT_CONFIG_KEY_0=filter.lfs.clean GIT_CONFIG_VALUE_0='git-lfs clean -- %f' \
GIT_CONFIG_KEY_1=filter.lfs.smudge GIT_CONFIG_VALUE_1='git-lfs smudge -- %f' \
GIT_CONFIG_KEY_2=filter.lfs.process GIT_CONFIG_VALUE_2='git-lfs filter-process' \
make verify catalogue-check
```

The focused suite exercises all 58 retained branch encodings, division/store/
reader-link bytes, FDE/CIE metadata, three source Locations and the recorder
slot. These structural tests deliberately omit only full-file SHA admission;
whole-body hashes remain active. They establish byte identity and rejection
controls rather than independent semantic CFG equivalence.

The 672-case positive-divisor sweep includes 504 changed pairs and 168 equal
pairs. Every changed result agrees with the independently stated closed form;
205 differ from the add-first variant. The packet retains eight boundary and
store-order witnesses. Producer invariants and runtime reachability of the
synthetic row values are not established. No runtime or safety conclusion is
drawn from these models.

The coordinator handles the broad repository `make test`. No completed full
suite, hosted CI or container result is claimed by this lane. From this packet
directory, `sha256sum -c MANIFEST.sha256` checks all packet files and the focused
test through its repository-relative parent path. Only the manifest itself is
excluded from its own rows.
