RE-040: cannot-revoke-token-freeze gate @ 0x27506c0 (node #94)

- Component ID: RE-040 (`RE-040-cannot-revoke-freeze-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `e5c9b643`; no radare2 revision (r2 not used)
- Claim: the cannot-revoke-token-freeze RULE only. When the per-token freeze-privilege word `dword [entry+0x10]` is 1 and the frozen-users count `qword [entry+0x28]` is non-zero, both guards fall through to Err `0xdf` + string `cannot revoke token freeze privilege when there are frozen users`. HL own policy, not a vendored crate.
- Prior work: merged #650 (spot-meta inventory) lists `0x27506c0` as an inventory start/owner only. It does not read the privilege/frozen-users gate, Err `0xdf`, or string `0x5999c1`. No sibling packet covers this function.

## Rerun

```bash
# static only (no unicorn required; this packet is static-only)
PYTHONHASHSEED=0 .venv/bin/python tools/cannot_revoke_freeze.py

# packet verify
.venv/bin/python -I -B research/work-items/RE-040-cannot-revoke-freeze-94/verify.py
.venv/bin/python -O -B research/work-items/RE-040-cannot-revoke-freeze-94/verify.py

# independent (stdlib only)
.venv/bin/python -I -B research/work-items/RE-040-cannot-revoke-freeze-94/independent_verify.py

# unit tests (negatives + mutation/tamper on the claimed gate)
PYTHONHASHSEED=0 .venv/bin/python -m unittest tests.test_cannot_revoke_freeze -v
```

## Pins

- Carve: `0x27506c0`..`0x27507ce` (270 bytes), sha256 `0fbf9cf9…fe4f`. Exclusive end is the first int3 after the landing-pad tail; 2-byte int3 pad then next function at `push rbp` `0x27507d0`.
- Callers: exactly one direct `e8` at `0x23e804f` (`e86c863600`); 0 direct `e9`; no `R_X86_64_RELATIVE` reloc with addend `0x27506c0` (no GOT slot, no `ff15` callers).
- Error string (VA / len / verbatim bytes / sha256):
  - `0x5999c1` / 64 / `cannot revoke token freeze privilege when there are frozen users` / `f2ad5057…43a4`. Exactly one packed occurrence. LEA in carve at `0x2750705` (`488d05b592e4fd`) targets it. Same-string LEAs outside the carve at `0x4d74065` and `0x4d74175` are listed as not-claimed.
- Rule (refusal ONLY): entry = `[rsi+0x210] + idx*0xe8` (`imul rcx,rdx,0xe8` at `0x27506e2`). `cmp dword [rax+rcx+0x10],1` at `0x27506ed` (`837c081001`) / `jne` at `0x27506f2` (`0f859b000000`) -> `0x2750793`; `cmp qword [r12+0x28],0` at `0x27506f8` (`49837c242800`) / `je` at `0x27506fe` (`741d`) -> `0x275071d`. Both fall through to Err movw `0xdf` at `0x2750700` (`66c703df00`) + LEA string + mov qword len `0x40` at `0x2750710` (`48c7431040000000`), then `jmp` to the epilogue `0x27507a1`.
- Err tag `0xdf`: movw STORE (not a compare-gate) at `0x2750700`, claimed with the string only. Ok `0x186` at `0x275079c` (after `mov qword [r12+0x10],0` at `0x2750793`) is an observed STORE, not claimed.

## What this does not claim

- Does NOT claim the revoke path itself: clearing `[entry+0x10]` and the Ok `0x186` STORE (privilege not set, or no frozen users).
- Does NOT claim the collection drain loop (`e8` `0x33b1e80` at `0x2750786`) or the OOB `cmp [rsi+0x218],rdx` / `jae` bounds panic via `ff15` GOT `0x576e470`.
- Does NOT claim the same-string LEAs outside this carve (`0x4d74065`, `0x4d74175`) or the caller at `0x23e804f` beyond its call edge.
- Does NOT name the field layout beyond the two offsets read (privilege word `+0x10`, frozen-users count `+0x28`).
- Does NOT emulate (static pin only; no Unicorn vectors).
- No other node builds.

## Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

### Targeted checks (commands + output)

All checks below ran at head `e6df1021`. Output is verbatim; the full repository suite was not run (see above).

head `e6df1021`:

```text
$ .venv/bin/python -I -B research/work-items/RE-040-cannot-revoke-freeze-94/verify.py
verify: key_insns=18 strings=1 direct_calls=1 errors=0
[exit 0]
```

head `e6df1021`:

```text
$ .venv/bin/python -O -B research/work-items/RE-040-cannot-revoke-freeze-94/verify.py
verify: key_insns=18 strings=1 direct_calls=1 errors=0
[exit 0]
```

head `e6df1021`:

```text
$ .venv/bin/python -I -B research/work-items/RE-040-cannot-revoke-freeze-94/independent_verify.py
PASS carve=0fbf9cf933af697d e8=1 strings=1 key_insns=18
[exit 0]
```

head `e6df1021`:

```text
$ .venv/bin/python -O -B research/work-items/RE-040-cannot-revoke-freeze-94/independent_verify.py
PASS carve=0fbf9cf933af697d e8=1 strings=1 key_insns=18
[exit 0]
```

head `e6df1021`:

```text
$ .venv/bin/python -m unittest tests.test_cannot_revoke_freeze -v
test_committed_json_pins (tests.test_cannot_revoke_freeze.CannotRevokeFreezeStaticTests.test_committed_json_pins) ... ok
test_error_string_bytes_verbatim (tests.test_cannot_revoke_freeze.CannotRevokeFreezeStaticTests.test_error_string_bytes_verbatim) ... ok
test_mutation_tamper_carve (tests.test_cannot_revoke_freeze.CannotRevokeFreezeStaticTests.test_mutation_tamper_carve) ... ok
test_mutation_tamper_cmp_priv_imm (tests.test_cannot_revoke_freeze.CannotRevokeFreezeStaticTests.test_mutation_tamper_cmp_priv_imm) ... ok
test_mutation_tamper_err_tag (tests.test_cannot_revoke_freeze.CannotRevokeFreezeStaticTests.test_mutation_tamper_err_tag) ... ok
test_mutation_tamper_je_frozen (tests.test_cannot_revoke_freeze.CannotRevokeFreezeStaticTests.test_mutation_tamper_je_frozen) ... ok
test_mutation_tamper_jne_priv (tests.test_cannot_revoke_freeze.CannotRevokeFreezeStaticTests.test_mutation_tamper_jne_priv) ... ok
test_negative_controls_per_rule (tests.test_cannot_revoke_freeze.CannotRevokeFreezeStaticTests.test_negative_controls_per_rule) ... ok
test_static_output_pin_and_expectations (tests.test_cannot_revoke_freeze.CannotRevokeFreezeStaticTests.test_static_output_pin_and_expectations) ... ok

----------------------------------------------------------------------
Ran 9 tests in 68.609s

OK
[exit 0]
```

head `e6df1021`:

```text
$ .venv/bin/python tools/catalogue.py --check
Stale catalogue: research/catalogue/components.json; run make catalogue
[exit 1]
```

head `e6df1021`:

```text
$ .venv/bin/python -m unittest tests.test_work_item_manifest_completeness -v
test_re008_manifest_completeness (tests.test_work_item_manifest_completeness.ManifestCompletenessTests.test_re008_manifest_completeness) ... ok
test_re010_manifest_completeness (tests.test_work_item_manifest_completeness.ManifestCompletenessTests.test_re010_manifest_completeness) ... ok

----------------------------------------------------------------------
Ran 2 tests in 0.173s

OK
[exit 0]
```

head `e6df1021`:

```text
$ pr-guard/scan.sh . --range $(git merge-base origin/main HEAD)..HEAD
pr-guard: clean
[exit 0]
```

head `e6df1021` (packet manifest, before this documentation commit):

```text
$ sha256sum -c MANIFEST.sha256
cannot_revoke_freeze.json: OK
verify.py: OK
independent_verify.py: OK
[exit 0]
```

Note: `tools/catalogue.py --check` exits 1 here because of a pre-existing condition. The same command, run on an unmodified checkout of the base commit `e5c9b643` (origin/main), prints the same "Stale catalogue: research/catalogue/components.json" message and also exits 1. This branch changes no catalogue file.
