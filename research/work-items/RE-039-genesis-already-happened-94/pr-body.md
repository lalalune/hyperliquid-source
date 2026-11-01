RE-039: genesis-already-happened host gate @ 0x3720150 (node #94)

Static recovery of the Hyperliquid genesis-already-happened host gate
in the pinned node #94 binary: carve `0x3720150`..`0x37201f6` (166 bytes,
carve sha256 `d4ff8c43…c302`), GOT slot `0x5773ef8` with
`R_X86_64_RELATIVE` addend `0x3720150`, 6 inbound `ff15`, 0 direct
`e8`/`e9`, string `0x599262` / 24 `genesis already happened`
(one packed occurrence; carve LEA at `0x37201d8`; same-string LEAs
outside carve not claimed), BTree membership->Err rule (found-equal
`je` + `rdx==0` `je`) to Err `0xe9` movw store + string.

Scope: static pin only. The captured binary is never run as a whole; no
Unicorn emulation. Claims the membership->Err gate + string only. Ok
`0xea` (OOB) and Ok `0x186` (admit/not-present) are observed movw
STOREs and are not claimed.

Prior work: merged #449 (genesis finish @ `0x371b950`) is an adjacent
SIBLING that explicitly left this host-gate slot unread (GOT `0x5773ef8`
cited only as an unread host gate). It does not claim entry `0x3720150`,
string `0x599262`, or the membership->Err rule. Next prologue
`0x3720200` is pay_out (sibling #1163).

## Identification

- Carve extent: exclusive end at first int3; 10-byte pad then next
  function (`push rbp` at `0x3720200`, pay_out #1163)
- Rule: BTree membership found-equal / rdx==0 -> Err `0xe9` + string
- String (VA/len/bytes): `0x599262`/24 `genesis already happened`
- Err `0xe9` movw STORE at `0x37201d3` (claimed with string only)
- Ok `0xea` / `0x186` movw STOREs observed, not claimed

## Proof

- Deterministic Python ELF tool (`tools/genesis_already_happened.py`)
  with its own VA->offset via `PT_LOAD`; exact pins (never `>=`);
  field name `key_insns`
- Static-only; no Unicorn
- PYTHONHASHSEED 0/7/99 and `-O` give byte-identical output
- `verify.py` holds under `-I -B` and `-O -B`
- `independent_verify.py` imports only hashlib / pathlib / struct
- Negatives + mutation/tamper unit tests (one negative for the claimed
  membership gate: flip je_found rel / cmp key / carve)

## What this does not claim

- Does not claim Ok `0xea` (OOB) or Ok `0x186` (admit) STORE arms
- Does not claim same-string LEAs outside carve (`0x2355dea`, `0x49f631a`)
- Does not claim #449 sibling genesis-finish or #1163 pay_out
- Does not claim a full genesis path; does not emulate
- No other node builds

### Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

#### Targeted checks (commands + output)

All checks below ran at head `bba3924f`. Output is verbatim; the full repository suite was not run (see above).

head `bba3924f`:

```text
$ .venv/bin/python -I -B research/work-items/RE-039-genesis-already-happened-94/verify.py
verify: key_insns=22 strings=1 direct_calls=0 errors=0
[exit 0]
```

head `bba3924f`:

```text
$ .venv/bin/python -O -B research/work-items/RE-039-genesis-already-happened-94/verify.py
verify: key_insns=22 strings=1 direct_calls=0 errors=0
[exit 0]
```

head `bba3924f`:

```text
$ .venv/bin/python -I -B research/work-items/RE-039-genesis-already-happened-94/independent_verify.py
PASS carve=d4ff8c4365267de0 ff15=6 strings=1 key_insns=22
[exit 0]
```

head `bba3924f`:

```text
$ .venv/bin/python -O -B research/work-items/RE-039-genesis-already-happened-94/independent_verify.py
PASS carve=d4ff8c4365267de0 ff15=6 strings=1 key_insns=22
[exit 0]
```

head `bba3924f`:

```text
$ .venv/bin/python -m unittest tests.test_genesis_already_happened -v
test_committed_json_pins (tests.test_genesis_already_happened.GenesisAlreadyHappenedStaticTests.test_committed_json_pins) ... ok
test_error_string_bytes_verbatim (tests.test_genesis_already_happened.GenesisAlreadyHappenedStaticTests.test_error_string_bytes_verbatim) ... ok
test_mutation_tamper_carve (tests.test_genesis_already_happened.GenesisAlreadyHappenedStaticTests.test_mutation_tamper_carve) ... ok
test_mutation_tamper_cmp_key (tests.test_genesis_already_happened.GenesisAlreadyHappenedStaticTests.test_mutation_tamper_cmp_key) ... ok
test_mutation_tamper_je_found_gate (tests.test_genesis_already_happened.GenesisAlreadyHappenedStaticTests.test_mutation_tamper_je_found_gate) ... ok
test_negative_controls_per_rule (tests.test_genesis_already_happened.GenesisAlreadyHappenedStaticTests.test_negative_controls_per_rule) ... ok
test_static_output_pin_and_expectations (tests.test_genesis_already_happened.GenesisAlreadyHappenedStaticTests.test_static_output_pin_and_expectations) ... ok

----------------------------------------------------------------------
Ran 7 tests in 82.052s

OK
[exit 0]
```

head `bba3924f`:

```text
$ .venv/bin/python tools/catalogue.py --check
Stale catalogue: research/catalogue/components.json; run make catalogue
[exit 1]
```

head `bba3924f`:

```text
$ .venv/bin/python -m unittest tests.test_work_item_manifest_completeness -v
test_re008_manifest_completeness (tests.test_work_item_manifest_completeness.ManifestCompletenessTests.test_re008_manifest_completeness) ... ok
test_re010_manifest_completeness (tests.test_work_item_manifest_completeness.ManifestCompletenessTests.test_re010_manifest_completeness) ... ok

----------------------------------------------------------------------
Ran 2 tests in 0.135s

OK
[exit 0]
```

head `bba3924f`:

```text
$ pr-guard/scan.sh . --range $(git merge-base origin/main HEAD)..HEAD
pr-guard: clean
[exit 0]
```

head `bba3924f` (packet manifest, before this documentation commit):

```text
$ sha256sum -c MANIFEST.sha256
genesis_already_happened.json: OK
verify.py: OK
independent_verify.py: OK
README.md: OK
pr-body.md: OK
[exit 0]
```

Note: `tools/catalogue.py --check` exits 1 here because of a pre-existing condition. The same command, run on an unmodified checkout of the base commit `6d727b9e` (origin/main), prints the same "Stale catalogue: research/catalogue/components.json" message and also exits 1. This branch changes no catalogue file.

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
