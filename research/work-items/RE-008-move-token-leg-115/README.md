# RE-008: node #115 move_token leg 0x54df920 and the 0x55817e0 early exit (stage 100)

- Component ID: abci. Question: #6212 (stage 99) found that `0x5580d10` calls `0x54df920` with `r8d = 1` (failure formats `move_token to_spot: `) and then `r8d = 0` (`move_token from_spot: `), unless its `r8` equals stack argument 0 and `r8` is 0 or `r9` equals stack argument 1. It left open what one leg does and whether the stage 98 path (#6210) reaches the legs at all.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6210 and #6212. Imports only the merged `freeze_snapshot_115` helpers.
- Claim status: instruction bytes, call and slot targets, relocations, Location records and constants are observations. "debit", "credit", "balance", "vault" and the to/from-spot naming of the legs are inferred labels. The binary was not executed.
- Scope included: the argument checks, error tags and `+0x4a8` updates of `0x54df920`; the two `0x54df920` calls and the early exit in `0x5580d10`; the `0x5582180` → `0x55817e0` → `0x5580d10` argument chain. Scope excluded: the bodies of the slot targets `0x446bdd0`, `0x447db40`, `0x3bf4b00`, `0x3bf4fa0`, `0x4479470`, the callees `0x3bfa910`, `0x4472ea0`, `0x54e0ec0`, `0x5630000`, the Locus `ust` update after the credit, and the other 11 callers of `0x54df920`.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/move_token_leg_115.py --check
python3 -m unittest tests.test_move_token_leg_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: arguments and checks of 0x54df920

| Check | Bytes | Result |
|---|---|---|
| `rdx` < box `+0x7d0` (Locus `cls` length) | `0x54df94b` | else `l1/src/dex_registry/clearinghouses.rs:11:29` unwrap panic, tag `0x156` |
| element = box `+0x7c8` + `rdx` * 0x510 | `0x54df972` | reads element `+0x58` (`0x54df994`) |
| key `rcx` looked up in Locus `vlt` (box `+0xa18`) | `0x54df9b2` | entry byte `+0xb7` tested (`0x54dfb35`) |
| amount `r9` sign | `0x54dfba7` `js` | negative → `Result::unwrap` panic at `l1/src/qtys/mod.rs:847:1` |
| amount * 100 overflow | `0x54dfbb5`..`0x54dfbcd` | tag `0x106` |
| amount <= 0 | `0x54dfc41` | tag `0x1a2`, no update |

`r8` selects the leg (`cmp r15, 2` at `0x54dfb52` and `0x54dfe69`, `cmp r15, 1` at `0x54dfbe0` and `0x54dfe73`).

## Evidence 2: the three legs

| `r8` | Path | Update of element `+0x4a8` |
|---|---|---|
| 1 | balance via slot `0x64e5078` (`0x446bdd0`); below the amount → tag `0x34` (`0x54dfc05`, `0x54dfec1`); else slot `0x64e7170` (`0x447db40`) | `-= amount` (`0x54e0124`, store `0x54e012d`) |
| 0 | slot `0x64e5af8` (`0x3bf4b00`) on Locus `scl` (box `+0x80`) must pass; then `0x3bfa910` with `ecx = 1` and `0x4472ea0` | `+= amount` (`0x54dff8a`, store `0x54dff93`) |
| 2 | amount from slot `0x64e7160` (`0x4479470`, `edx = 2`); slot `0x64e7170` | `-= amount` (`0x54e0092`, store `0x54e00a5`) |

A signed overflow on `+0x4a8` saturates (`cmovo` at `0x54e0232`) and is recorded with Location `l1/src/qtys/impl_ntl.rs:70:1` through the registry slot `0x64e4ea8` (#6056). The credit leg then updates Locus `ust` and adds a converted amount / 10000 (`0x346dc5d63886594b`, `shr 11`) to `[r14+0x18]`. The converted amount is the input times the element's f64 at `+0x4e0`, clamped to ±`0x147ae147ae147ae` (i64::MAX / 100).

Inference: with `r8 = 1` → "to spot" the leg debits the clearinghouse total, with `r8 = 0` → "from spot" it credits it.

## Evidence 3: the stage 98 path never reaches a leg

- `0x5582180` passes `ecx = 0` (`0x558310a`) to `0x55817e0` (`0x5583117`).
- `0x55817e0` keeps `rcx` in `r12` (`0x55817f4`; no other write to `r12`), stores it as stack argument 0 (`0x5581bfe`) and calls `0x5580d10` with `r8d = 0` (`0x5581c19`, call `0x5581c1c`).
- In `0x5580d10`, `r8` = stack argument 0 (`0x5580d7e`) and `r8 = 0` (`0x5580d88`) → `0x558136b` stores 0 and tag `0x1a2` and returns.

So on this path `0x5580d10` only increments Locus `ctr` (#6212) and moves nothing.

## Results and limitations

- `0x54df920` has 13 direct callers; only the two in `0x5580d10` are mapped.
- What `0x446bdd0`, `0x447db40`, `0x3bf4b00` and `0x4472ea0` read and write is not mapped; "balance" and "vault" are labels only.
- Which other callers of `0x5580d10` (51 direct calls, #6212) pass arguments that reach the legs is not mapped.
- No Rust is added and no progress gate is requested.
