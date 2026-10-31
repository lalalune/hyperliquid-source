# RE-004: withdraw3 amount gates and bridge limits in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the order of the gates, the constants, the status text, the serde keys and the call sites; inference for the unit of the amount and for the action behind the function; unresolved items are listed under limits
- Scope included and excluded: included are the core `0x2734200` and its copies `0x4d49260`, `0x4d498a0`, plus the short helpers they reach and that run as real bytes here: `0x374fce0` (bridge record), `0x3c097b0` (scale call), `0x3332600` and `0x3332700` (dex record). Excluded, and stubs here: the decimal parser `0x3799510`, the scale helper behind slot `0x5773848`, the address parser `0x3813b40`, the first dex debit `0x370da60`, the map insert `0x3941fe0`, the row and hash helpers, the volume helpers and the lazy pair read `0x14385c0`. The caller `0x2732530` and its copies are not read.

## Reproduce

```
python3 tools/withdraw_amount_gates.py --out research/work-items/RE-004-withdraw-amount-gates-94
python3 -m unittest tests.test_withdraw_amount_gates
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes about 2 to 4 minutes, depending on load; most of that is the mutation sweep.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`). FDE extents are exact: `0x2734200..0x273483e`, `0x4d49260..0x4d4989e`, `0x4d498a0..0x4d49ede`. Each copy has 339 instructions and each is called 3 times, all from one function (`call-sites.tsv`).

Arguments: `rdi` output record, `rsi` user (20 bytes), `rdx` action, `rcx` state. Action fields used: `+0x08`/`+0x10` destination text, `+0x20`/`+0x28` amount text, `+0x50` nonce.

Copies. The first two copies differ only in call targets. The third has the same rows with every state offset from `+0x5b8` upward raised by `0xa80`; the 16 rows are in `copy-differences.tsv`. Offsets below are for the first layout. State words `+0x10`, `+0x28`, `+0x58`, `+0x60` are the same in all three.

Status text comes from the Display table `0x59a8d0` (`status-text.tsv`).

| Tag | Text |
|---|---|
| `0x143` | Invalid input length |
| `0x75` | `Withdrawals disabled {}` (a bool at record `+2`) |
| `0x27` | Error withdrawing from bridge |
| `0xc6` | `Invalid nonce: {}` (here the text `nonce error`) |
| `0x5a` | Nonce already used. |
| `0x30` | Withdrawal amount cannot be zero. |
| `0x28` | Withdrawal amount over single withdrawal limit. |
| `0xb6` | Failed to parse user address |

The order below holds in all three copies. `n` is the action nonce and `x` the parsed amount. A word at `+0x58` is raised by one (saturating) on entry and lowered by one (saturating) on every exit, so a value of `u64::MAX` ends as `u64::MAX - 1`.

1. Destination length above 100: `0x143`, payload pointer to the action. Amount length above 100: `0x143`, payload pointer to action `+0x18`.
2. Window. Passes only if `now >= T` and `h >= H`. `now` is the triple at `+0x60` and `T` the triple at `+0x3aa4`, compared signed on the first word and unsigned on the other two. `h` is `+0x28`, `H` is `+0x3988`. On failure: `0x75` with byte `h >= sat(word(+0x10) + 5000)`.
3. Flag pair. If byte `+0x31a2` is exactly 1 and byte `+0x34d8` is 0: `0x27`. Other values of the first byte do not refuse, and any non-zero second byte passes.
4. `n * 1000` over `u64` by a full `mul`: `0xc6`, with the 11 bytes `nonce error` in a heap string. `n` up to `floor(u64::MAX / 1000)` passes.
5. Stored nonce. The map at `+0x740` (entry `0x58` bytes, 20-byte key, word `+0x18`) gives the stored value. No items, or a missing key, gives 0. `n * 1000 <= stored`: `0x5a`. So `n = 0` is always refused.
6. Decimal parse, then scale: `0x3c097b0` calls the helper in slot `0x5773848` with mode 2 and exponent 6. A failure from either copies the helper's 0x60-byte record out.
7. `x == 0`: `0x30`. This test is in the core at `0x27344b6`; `0x3c097b0` has no such test.
8. `x > bal`: `0x27`. `bal` is `+0x34c8`.
9. Dex 0 is looked up in the vector at `+0x5b8` (stride `0x2f0`). A missing record panics through `Result::unwrap`, status `0x141`.
10. `x > 10^13`: call `0x14385c0`, then `0x28`.
11. Dex 0 looked up again. `x >= 3*10^12`: call `0x14385c0`, and go on. The call returns two words that are not read. The bytes form is `x >> 12 > 0x2ba7def2`, and `(0x2ba7def2 + 1) << 12` is exactly `3*10^12` (`constants.tsv`). Cases just under and at that level end with equal fixture bytes, so the level changes no fixture state here.
12. Destination parse. Any failure: drop the record, `0xb6` alone.
13. Debit `0x370da60` on dex 0 with `x`, `+0x3840`, `+0x5d0`. A failure copies its record out. On success its `+8` word is `net`.
14. Bridge record `0x374fce0` at `+0x3398`: insert key `(n*1000, user)`, value `(net, destination)`, unwrap, then `bal -= net`, panic `bridge2 withdrawal balance bug` on underflow.
15. Row of the user: word `+0` gets `n*1000`, byte `+0x3d` gets 0.
16. Volume helper with `-x`, second word 0. Status `0x186`.

Note the two amounts: the gates, the debit and the volume use `x`, while the record and `bal` use `net`.

Bridge fields. The serializer rows in `fields.tsv` give field `+0x130` the key `bal`, `+0x138` the key `last_pruned_deposit_block_number`, `+0x140` the key `oaw`. With the bridge at `+0x3398`, these are state `+0x34c8`, `+0x34d0`, `+0x34d8`. Two vote arm stores write bytes `+0x31a2` (`0x235b43c`) and `+0x34d8` (`0x235b462`); the arms were not read further.

Input pieces (`input-pieces.tsv`). With `bal = u64::MAX`, `x` splits at `1`, `3*10^12`, `10^13 + 1`, and `n` splits at `1` and `floor(u64::MAX/1000) + 1`. Both ends of each piece walk the same set of rows with the same status, on all three copies.

Reference compare. `l1/exchange/handlers/47_withdraw3.rs` has the shape of this function, and these points differ from the bytes:

| Reference | Bytes |
|---|---|
| Status 40 is a follow-on overflow guard, raised after the record, on the negated amount | `0x28` is the fixed limit `x > 10^13`, before the destination parse; the negate has no check |
| No `3*10^12` row | Step 11 |
| Status 39 only for the bridge limit | Also step 3 |
| `sub_3C097B0` returns 48 for zero | The test is in the core |
| Stored nonce optional: absent means no check | Absent reads as 0, so `n = 0` is refused |
| Debit and record take the same `usd` | The record takes `net` from the debit |
| `max_bridge_withdraw_usd` | The word is the serde field `bal`, which the same path lowers |
| `oaw` typed `u32` | This path reads one byte; the serializer loads four |

## Implementation and comparison

not yet implemented. The tool holds a rule list `spec_run`, written apart from the bytes, that predicts the output record, all fixture bytes and the event list of each run.

## Results and limitations

- 333 named cases and 600 generated cases: 0 mismatches. Every run compares about 56 KB of fixture bytes, stub arguments and event order. All 339 rows of each copy are reached. Unreached rows of the helpers are in `evidence.json`; they are panic tails and landing pads.
- 464 byte edits on reached rows: 454 killed, 10 survived, each with a recorded reason (`mutations.tsv`). An unedited image must pass under the same step limit first.

Limits:

- The helper in slot `0x5773848` is a stub. This packet pins mode 2 and exponent 6 but does not prove how it rounds.
- The inference that `x` is USD with 6 decimals rests on exponent 6 alone, which would make the limit 10 million and the level 3 million. Neither figure appears in the bytes as a dollar amount.
- `0x14385c0` is a stub. It reads a lazily set pair at `0x577ab88`; what that pair is and why it is called on these two branches is unresolved. With the stub, the level at step 11 has no effect; a side effect of the real helper's first call is not excluded.
- The meaning of `T`, `H`, `+0x10`, `+0x31a2`, `+0x34d8` and the `0x75` bool is unresolved. The name `oaw` is only a key.
- Stale stack bytes follow the tag in the `0x27`, `0x28` and `0x30` records from the shared exit. Their Display arms print no payload, so the tool clears that tail before comparing.
- Input pieces are shown by both ends walking equal row sets, plus the reading that `x` and `n * 1000` meet no other compare in these rows. No taint proof is in the tool.
- That the `net` from the debit stays at or below `x` is not checked here. If it does, the balance panic in step 14 cannot fire after step 8.
- `0x2732530` and its copies are not read, so which action paths reach this function comes from the reference only.
