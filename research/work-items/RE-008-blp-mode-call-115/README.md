# RE-008: node #115 blp mode call 0x5609fb0, side predicate and move_token pair (stage 99)

- Component ID: abci. Question: #6210 (stage 98) found that `0x55817e0` calls `0x5609fb0` with `r8d = 3`, then the slot `0x64e7180` predicate on Locus `blp`, then `0x5609fb0` with `r8d = 0`, and ends in `0x5580d10` (`move_token to_spot` / `from_spot`). It left open what the mode does, what the predicate tests and which `0x5580d10` leg runs.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6205 and #6210. Imports only the merged `freeze_snapshot_115` helpers.
- Claim status: instruction bytes, call targets, the jump table, relocations and strings are observations. "side", "first/second half", "leg" are inferred labels. The binary was not executed.
- Scope included: the three call sites in `0x55817e0`, the mode path in `0x5609fb0` → `0x57cbe30` / `0x55a03c0` → `0x55a07e0`, the side test in `0x369b360`, and the entry, early exit and two legs of `0x5580d10`. Scope excluded: the bodies of `0x5492440`, `0x54df920`, the table-walking arms of `0x57cbe30`, and what the two halves hold.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/blp_mode_call_115.py --check
python3 -m unittest tests.test_blp_mode_call_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: the calls in 0x55817e0

| Site | Call | Arguments |
|---|---|---|
| `0x5581946` | `0x5609fb0` | `r8d = 3`, `r9d = 0` |
| `0x55819ed` | slot `0x64e7180` → `0x369b360` | `rdi = box+0x670` (Locus `blp`), `rdx = rbx`, `ecx = 0` |
| `0x5581a37` | `0x5609fb0` | `r8d = 0`, `r9d = 0`, only when the predicate returns true |

## Evidence 2: what the mode does in 0x5609fb0

- `0x5609fc4` keeps the mode in `ebp`; `0x5609ff2` passes it in `edi` to `0x57cbe30`.
- `0x57cbe30` switches on the mode byte through jump table `0x9351f4`. Arm 0 is `0x57cbfeb`, arm 3 is `0x57cbfe6` (`mov eax, 3`); both jump straight to the return at `0x57cc0e3`. Arms 1 (`0x57cbe4b`) and 2 (`0x57cbf16`) walk tables.
- `0x560a11b` passes the mode in `ecx` to `0x55a03c0`, which stores it at `[rsp+0xe]` and passes it on to `0x55a07e0` (call at `0x55a0504`).
- `0x55a07e0` reads the mode only as `(mode & 1) << 4` (`0x55a0e5c`, `0x55a0f3c`): an offset of 0 or 0x10 into entries of 0x20/0x28 bytes. Mode 3 selects the second 16-byte half, mode 0 the first.
- `0x5609fb0` returns tag `0x1a2` when `0x55a03c0` returns `0x11`, else tag `0xf1` with byte `0xc`.

## Evidence 3: the predicate 0x369b360

- Slot `0x64e7180` is relocated to `0x369b360`.
- It looks the 20-byte key up in the map at `blp +0x88` (`memcmp` length `0x14` at `0x369b3f9`), then the u64 argument in that value's inner map.
- It returns true when the word at entry `+0x8 + ((ecx ^ 1) << 4)` is 0 or no entry exists (`0x369b5c9`..`0x369b5db`). The `0x55817e0` call passes `ecx = 0`, so it tests the second half.

Reading: after operating on the second half (mode 3), `0x55817e0` operates on the first half (mode 0) only when the second half's word is 0. Labelling the halves is an inference.

## Evidence 4: 0x5580d10

- On entry it adds 1 to Locus `ctr` (`+0xab0`, saturating to `u64::MAX`, `0x5580d32`..`0x5580d47`).
- If `r8` equals the first stack argument and either `r8 == 0` or `r9` equals the second stack argument, it returns tag `0x1a2` with value 0 at once (`0x5580d7e`..`0x5580d99` → `0x558136b`).
- Otherwise it calls `0x54df920` with `r8d = 1` (`0x55812c0`); a non-`0x1a2` result goes to the block that formats `move_token to_spot: ` (`0x432bcb`). Then it calls `0x54df920` with `r8d = 0` (`0x5581350`); a failure formats `move_token from_spot: ` (`0x438c95`).
- The `0x55817e0` call (`0x5581c1c`) passes `r8d = 0`. Whether it takes the early exit depends on its stack arguments, which are not mapped.

## Results and limitations

- Result: the mode of `0x5609fb0` selects one of two 16-byte halves (mode & 1); the predicate tests the other half's word; `0x5580d10` also counts in Locus `ctr` and runs two legs, to_spot then from_spot.
- Limits: what the halves hold; the table arms 1, 2 and 4–7 of `0x57cbe30`; the bodies of `0x5492440` and `0x54df920`; the stack arguments of the `0x5580d10` call; whether mode 3 sets record byte `+0x3c` (#6205) — no such store was found on this path.
- Next lead: `0x54df920` and its `r8d` leg flag.
