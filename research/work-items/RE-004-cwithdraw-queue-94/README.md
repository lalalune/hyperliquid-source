# RE-004: cWithdraw gate and pending withdrawal queue in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the order of the tests, the constants, the serde keys, the status text and the call sites; inference for the action name, the word names and the chain names; unresolved items are listed under limits
- Scope included and excluded: included are the gate `0x3993110`, the queue function `0x3c13000`, the stake sum `0x3c0f050` and the entry helper `0x33bac00`, run as real bytes. Stubs here: the 20-byte compare (slot `0x576e488`), the time add (slot `0x576efb8`), the node inserts `0x2f90ca0` and `0x33bff70`, the row list growth (slot `0x57744d0`), the allocator. Excluded: the handlers that call the gate, the source of the extra amount `y`, and the code that drains the queue.

## Reproduce

```
python3 tools/cwithdraw_queue.py --out research/work-items/RE-004-cwithdraw-queue-94
python3 -m unittest tests.test_cwithdraw_queue
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes about a minute.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`). FDE extents are exact: `0x3993110..0x39935c8` (291 instructions), `0x3c13000..0x3c133fc` (231), `0x3c0f050..0x3c0f34b` (186), `0x33bac00..0x33bad4e` (76).

Reach. The gate has no direct caller. Three indirect calls go through slot `0x5774d40` (`gate-call-sites.tsv`). The fixed bytes just before each load the staking word and the chain byte: `+0x8f8` and `+0x8f2` at two sites, `+0x1378` and `+0x1372` at the third (a shift of `0xa80`). The queue function has one direct call, `0x39935a2`, from the gate.

Gate arguments: `rdi` output, `rsi` staking struct `S`, `edx` mode, `rcx` user (20 bytes), `r8` amount `x`, `r9` extra amount `y`, stack word pointer to the time triple `now`. Time triples are `(i32, u32, u32)`, compared in that order; the first word is signed.

Fields, from serde keys in the serializer (`field-names.tsv`):

| Offset in `S` | Key | Bytes read here |
|---|---|---|
| `+0x168` | `delegations` | map user to inner map; inner value word `+0` is a stake amount |
| `+0x1f8` | `user_states` | map user to value of `0x18` bytes: `+0` word `U`, `+8` lock time |
| `+0x210` | `pending_withdrawals` | struct of two maps, keys `queue` and `user_to_total_withdrawal` |

The queue map (root at `S+0x210`) has 12-byte time keys and `Vec` values `(cap, ptr, len)` with rows of `0x20` bytes: `+0` amount, `+8` user, 20 bytes. The total map (root at `S+0x228`) has user keys and values of `0x10` bytes: `+0` pending total `P`, `+8` row count `N`.

Status text comes from the Display table `0x59a8d0` (`status-text.tsv`):

| Tag | Text |
|---|---|
| `0x12c` | Action not allowed while staking long term |
| `0x12d` | Insufficient balance to withdraw from CStaking |
| `0x12e` | Too many concurrent CStaking withdrawals |
| `0xbe` | Add result error |

Order of the tests:

1. User row in `user_states`. If the row exists and the lock date word is not 0: `now < lock` gives `0x12c`. `now == lock` passes. Otherwise the date word is set to 0 in place, and this write stays even when a later test refuses.
2. `x + y` wraps: `0x12d`.
3. `U` is the row's first word, 0 with no row. `D` from `0x3c0f050`: sum of the inner amounts of the user's `delegations` row, 0 with no row, and 0 when the sum wraps (no saturation).
4. `D + U` wraps: the room is 0, so only `x + y == 0` passes, and `P` is not read.
5. Otherwise room `= max(D + U - P, 0)`. `x + y > room`: `0x12d`.
6. Queue function, with `U` as its limit. A user with a total row: `N > 4` gives `0x12e`; then `P + x` wraps or `U < P + x` gives `0x12d`. No row: `U < x` gives `0x12d`.
7. `P += x` and `N += 1` through `0x33bac00`, which makes a zero row first. An empty map builds a root node of `0x198` bytes.
8. Unlock time = `now` + seconds, from the f64 table `0x2039f0`: 300.0 when the low byte of the mode is 1 or 2, else 604800.0 (`seconds-table.tsv`, `mode-bytes.tsv`, all 256 low bytes).
9. The row `(x, user)` goes on the list under that time; a missing key makes an empty list. Status `0x186`.

So two limits apply at once. `x + y + P <= D + U` lets stake count, but `x + P <= U` then holds `x` to the undelegated word alone. A user can hold at most 5 pending rows.

`amount-pieces.tsv`: for three fixed rows, `x` splits into pieces whose two ends walk the same set of rows with the same status. With `U = 3000`, `D = 5000`, `P = 1000`, `y = 0`, `x` passes up to 2000, is refused by the queue up to 7000 and by the gate above that.

Reference compare. `l1/staking.rs` has `pending_withdrawals: BTreeMap<Address, Vec<WithdrawalRequest>>` with `destination`, `wei` and `unlock_epoch`. The bytes show two maps instead: unlock time to rows of `(amount, user)`, and user to `(total, count)`. There is no destination and no epoch in a row, and the key is a time. The reference has the two error names but no rule for them. It has `staking_epoch_duration_seconds`, but neither the limit of 5 nor the constants 604800 and 300 for this wait. `MAX_TRACKED_PENDING_WITHDRAWALS` in `40_validator_sign_withdrawal.rs` is another subject.

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts the status, all fixture bytes and the event list of each run.

## Results and limitations

- 158 named cases and 600 generated cases: 0 mismatches, comparing fixture bytes, stub arguments and event order, over real B-tree nodes with stale keys in unused slots. All gate rows are reached.
- 284 byte edits on reached rows: 278 killed, 6 survived, each with a recorded reason (`mutations.tsv`). An unedited image must pass under the same step limit first.
- Rows not reached (`evidence.json`): `0x3c133f6` and `0x3c133fa`, the `0xbe` exit. Step 6 refuses a wrap first and a new row starts at 0, so this add cannot wrap. In `0x3c0f050`, the unrolled descent for height 8 or more and two panic exits. In `0x33bac00`, the full-node panic.

Limits:

- `cWithdraw` is an inference: the reference table labels the handler holding site `0x2758a41` with that name, and the status texts agree.
- `U` as undelegated, `P` as total pending and `N` as the count are inferences. Keys `delegated`, `undelegated`, `totalPendingWithdrawal`, `nPendingWithdrawals` sit in that order in the serializer `0x2a3f830` (`field-names.tsv`), but what fills that struct was not read. `user_to_total_withdrawal` as the map at `S+0x228` rests on its position in the struct and the shape of its rows.
- That the lock word means long-term staking rests on the text of tag `0x12c` alone.
- `y` is not explained. The handler passes a saturating sum of a list it builds; this packet treats `y` as an input.
- Mode bytes 1 and 2 as Sandbox and Testnet rest on the enum order in the reference; a mainnet value of 3 comes from sibling packets. Byte 0 also takes the 7-day arm.
- The time add is a stub, so only its inputs are pinned. The fixture picks each unlock key.
- Trees reach height 2; a real run over taller trees is not shown.
- Nothing here shows where `P` and `N` fall again, or who drains the queue.

Next question: which function pops the queue at unlock time, and does it lower `user_to_total_withdrawal` by the same amount and count?
