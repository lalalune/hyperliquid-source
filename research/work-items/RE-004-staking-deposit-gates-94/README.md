# RE-004: staking deposit amount gates in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the order of the gates, the constants, the status text and the call sites; inference for the action behind the function and for the names of the balance words; unresolved items are listed under limits
- Scope included and excluded: included are `0x2734840` and its copies `0x4d40eb0`, `0x4d44e60`, run as real bytes. Excluded, and stubs here: the balance holder `0x371b3a0`, the staking call `0x39964d0`, the debit `0x371b140`, `0x371cf40`, `0x371d120`, `0x3987cb0`, the token name helper, the event helpers. The callers `0x2731f50`, `0x4d408c0`, `0x4d3b850` are not read.

## Reproduce

```
python3 tools/staking_deposit_gates.py --out research/work-items/RE-004-staking-deposit-gates-94
python3 -m unittest tests.test_staking_deposit_gates
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes under a minute.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`). FDE extents are exact: `0x2734840..0x2734ca9`, `0x4d40eb0..0x4d41319`, `0x4d44e60..0x4d452f2`, with 244, 244 and 260 instructions. Each copy is called 3 times, all from one function (`call-sites.tsv`).

Arguments: `rdi` output record, `rsi` user (20 bytes), `rdx` amount `x`, `rcx` state.

Copies. The first two have the same rows apart from call targets. In the third, the staking word `+0x8f8`, the word `+0x3380` and the byte `+0x8f2` are raised by `0xa80`. The third also replaces the last event call: `0x4855a50` then `0x4856460`, both on owner `+0x5b8`, in place of `0x3576710` on owner `+0x8f3` (`slots.tsv`).

Status text comes from the Display table `0x59a8d0` (`status-text.tsv`):

| Tag | Text |
|---|---|
| `0x13f` | Invalid input number |
| `0xfb` | Native token does not exist |
| `0x2f` | Deposit amount cannot be zero. |
| `0x2c` | Insufficient funds available to deposit. |

The order below holds in all three copies. A word at `+0x58` is raised by one (saturating) on entry and lowered by one (saturating) on every exit.

1. `x >= 0x0ccccccccccccccc` (`constants.tsv`): `0x13f`, payload `x`.
2. Byte `+0x80` is 0: `0xfb`. Any non-zero value passes. The token id is `+0x88`.
3. `x == 0`: `0x2f`.
4. Holder of the user from the map at `+0x80`. Its B-tree (`+0x10` root, `+0x18` height) is searched for the token id. An entry gives words `T` (`+0`) and `H` (`+8`). No tree, or no key, gives `T = H = 0`.
5. `H + x` wraps, or `H + x > T`: `0x2c`. So with no row every amount is refused, and `x = T - H` passes.
6. Staking call on `+0x8f8` with the user, `x` and the time triple at `+0x60`. A failure copies its 0x60-byte record out.
7. Debit call on the map at `+0x80` with the user, token and `x`. A zero low byte of the result gives `0x2c`. The staking call has already run on this path.
8. Value from `0x371cf40` at `+0x3380`, then `0x371d120` with the token, 1, `x` and that value.
9. A 20-byte heap copy of the user.
10. If the word at `+0` is exactly 1: `0x3987cb0` with byte `+0x8f2`, `+0x08`, `+0x28` and 0. Otherwise 32 zero bytes stand in for its result.
11. Token name, then a bounds test of the token id against `+0x218` (panic past the end, after step 8 has run).
12. Event word `0x8000000000000016`, the name, `f64(x) / 10^wei` and byte 1. `wei` is byte `+0x49` of the token record (table `+0x210`, stride `0xe8`), and the power comes from the f64 table `0x584b08`. Status `0x186`.

Input pieces (`input-pieces.tsv`). With one row `T = 5000`, `H = 1000`, `x` splits at `1`, `4001` and the cap. Both ends of each piece walk the same set of rows with the same status, on all three copies.

Reference compare. `l1/action/c_deposit.rs` holds the action format, the outer gates and a phase choice. It has no row for steps 1, 3, 5 or 12, and neither address is in the reference tree. The status names above are the only link to a deposit from bytes.

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts the output record, all fixture bytes and the event list of each run.

## Results and limitations

- 174 named cases and 600 generated cases: 0 mismatches, comparing fixture bytes, stub arguments and event order. All rows but the landing pads are reached (`evidence.json`).
- 269 byte edits on reached rows: 263 killed, 6 survived, each with a recorded reason (`mutations.tsv`). An unedited image must pass under the same step limit first.

Limits:

- All callees are stubs. What the staking call, the debit and the value from `0x371cf40` compute is not claimed.
- The action name is an inference. The texts and the staking call fit a deposit into staking, but the callers are not read.
- `T` and `H` as total and hold are names from sibling packets; this packet shows only the compare.
- Whether the debit in step 7 can refuse after step 5 passes is not read. If it can, the staking call has no undo in these rows.
- `f64(x)` was checked at chosen values and vectors, not over every `x`.
- The meaning of the mode word, of byte `+0x8f2` and of the byte 1 in the event is unresolved.
