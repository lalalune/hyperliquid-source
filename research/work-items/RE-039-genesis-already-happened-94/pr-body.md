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

PENDING — filled after targeted check run at packet head.

<!-- run-receipt.mjs disclose: provider=Grok-Bot model=Grok-Bot client=Grok-Bot client-version=Grok-Bot -->
