RE-040: cannot-revoke-token-freeze gate @ 0x27506c0 (node #94)

Static recovery of the Hyperliquid cannot-revoke-token-freeze gate in
the pinned node #94 binary: carve `0x27506c0`..`0x27507ce` (270 bytes,
carve sha256 `0fbf9cf9…fe4f`), one direct `e8` caller at `0x23e804f`
(no GOT slot), string `0x5999c1` / 64 `cannot revoke token freeze
privilege when there are frozen users` (one packed occurrence; carve LEA
at `0x2750705`; same-string LEAs outside carve not claimed), and the
refusal rule: privilege word `[entry+0x10]==1` and frozen-users count
`[entry+0x28]!=0` fall through to an Err `0xdf` movw store + string.

Scope: static pin only. The captured binary is never run as a whole; no
Unicorn emulation. Claims the refusal gate + string only. The revoke
path (clear `[entry+0x10]`, Ok `0x186` STORE), the drain loop and the
OOB bounds panic are observed and not claimed.

Prior work: merged #650 (spot-meta inventory) lists `0x27506c0` as an
inventory start/owner only; it does not read this gate, Err `0xdf`, or
string `0x5999c1`. No sibling packet covers this function.

## Identification

- Carve extent: exclusive end at first int3; 2-byte pad then next
  function (`push rbp` at `0x27507d0`)
- Rule: privilege word == 1 and frozen-users count != 0 -> Err `0xdf` + string
- String (VA/len/bytes): `0x5999c1`/64 `cannot revoke token freeze privilege when there are frozen users`
- Err `0xdf` movw STORE at `0x2750700` (claimed with string only)
- Ok `0x186` movw STORE observed, not claimed

## Proof

- Deterministic Python ELF tool (`tools/cannot_revoke_freeze.py`)
  with its own VA->offset via `PT_LOAD`; exact pins (never `>=`);
  field name `key_insns`
- Static-only; no Unicorn
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical output
- `verify.py` holds under `-I -B` and `-O -B`
- `independent_verify.py` imports only hashlib / pathlib / struct
- Negatives + mutation/tamper unit tests (flip jne_priv rel / je_frozen
  rel / cmp imm / Err tag / carve)

## What this does not claim

- Does not claim the revoke path (clear + Ok `0x186` STORE)
- Does not claim the drain loop (`e8` `0x33b1e80`) or the OOB bounds panic
- Does not claim same-string LEAs outside carve (`0x4d74065`, `0x4d74175`)
- Does not claim a full spot-token freeze path; does not emulate
- No other node builds

### Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

#### Targeted checks (commands + output)

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
