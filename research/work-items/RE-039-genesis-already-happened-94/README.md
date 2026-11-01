RE-039: genesis-already-happened host gate @ 0x3720150 (node #94)

- Component ID: RE-039 (`RE-039-genesis-already-happened-94`); no `docs/COMPONENTS.md` progress change is claimed
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `6d727b9e`; no radare2 revision (r2 not used)
- Claim: the genesis-already-happened membership->Err RULE only — reject when token id in rdx is already present in the genesis BTree set (found-equal after seta/sbb), or when rdx==0, via je to Err `0xe9` + string `genesis already happened`. HL own policy, not a vendored crate.
- Prior work: merged #449 (genesis finish @ `0x371b950`) is an adjacent SIBLING that explicitly left this host-gate slot unread (GOT `0x5773ef8` cited only as an unread host gate). It does not claim entry `0x3720150`, string `0x599262`, or the membership->Err rule. Next prologue `0x3720200` is pay_out (sibling #1163).

## Rerun

```bash
# static only (no unicorn required; this packet is static-only)
PYTHONHASHSEED=0 .venv/bin/python tools/genesis_already_happened.py

# packet verify
.venv/bin/python -I -B research/work-items/RE-039-genesis-already-happened-94/verify.py
.venv/bin/python -O -B research/work-items/RE-039-genesis-already-happened-94/verify.py

# independent (stdlib only)
.venv/bin/python -I -B research/work-items/RE-039-genesis-already-happened-94/independent_verify.py

# unit tests (negatives + mutation/tamper; one negative for the claimed membership gate)
PYTHONHASHSEED=0 .venv/bin/python -m unittest tests.test_genesis_already_happened -v
```

## Pins

- Carve: `0x3720150`..`0x37201f6` (166 bytes), sha256 `d4ff8c43…c302`. Exclusive end is the first int3 after the body; 10-byte int3 pad then next function at `push rbp` `0x3720200` (pay_out, #1163).
- GOT slot `0x5773ef8` with `R_X86_64_RELATIVE` addend `0x3720150`; exactly 6 inbound `ff15` at `0x23e7fdf` / `0x23e80f6` / `0x4ad7b7f` / `0x4ad7c96` / `0x4ad84af` / `0x4ad85c6`; 0 direct `e8` / `e9`.
- Error string (VA / len / verbatim bytes / sha256):
  - `0x599262` / 24 / `genesis already happened` / `a4ee7b2f…1036`. Exactly one packed occurrence. LEA in carve at `0x37201d8` (`488d0d8390e7fc`) targets it. Same-string LEAs outside the carve at `0x2355dea` and `0x49f631a` are listed as not-claimed.
- Rule (membership->Err ONLY): BTree key compare `cmp rdx, [rcx+rdi*8+0x10]` at `0x3720195` (`483b54f910`); `seta r10b` / `sbb r10b,0`; `test r8d,r8d` / `je` at `0x37201b6` (`741b`) -> `0x37201d3` Err. Also `test rdx,rdx` / `je` at `0x372015f` (`7472`) -> same Err. Err movw `0xe9` at `0x37201d3` (`66c700e900`) + LEA string + mov qword len `0x18` at `0x37201e3` (`48c7401018000000`).
- Err tag `0xe9`: movw STORE (not a compare-gate) at `0x37201d3`, claimed with the string only. Ok `0xea` (OOB path) and Ok `0x186` (admit/not-present) are movw STORE observations at `0x37201cd` / `0x37201f0` — not claimed.

## What this does not claim

- Does NOT claim Ok tag `0xea` (OOB `cmp [rsi+0x198],rdx` / `jae` path) or Ok tag `0x186` (admit/not-present path); both are observed movw STOREs only.
- Does NOT claim the same-string LEAs outside this carve (`0x2355dea`, `0x49f631a`).
- Does NOT claim merged #449 genesis-finish path @ `0x371b950` (sibling; unread host-gate slot only) or #1163 pay_out @ `0x3720200`.
- Does NOT claim a full genesis / spot-token path end-to-end; claims the membership->Err gate + string only.
- Does NOT emulate (static pin only; no Unicorn vectors).
- No other node builds.

## Build verification

The full repo test suite (one `unittest discover` over about 5,000 tests) needs about 25 GB of memory, more than the local build machine has, so it was not run locally; the full suite is left to CI. The following targeted checks are run instead: the packet's own `verify.py` and `independent_verify.py`, its unittest file, the repo catalogue/progress-table check, and the test modules touching the files this packet changes. Exact commands and output are recorded below.

### Targeted checks (commands + output)

PENDING — filled after targeted check run at packet head.
