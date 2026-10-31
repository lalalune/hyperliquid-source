# bridge: the deposit credit step `0x27123d0` in node #94

This packet runs the function that turns a finished deposit into user state, so a reconstruction can write the credit from the bytes: result bit 0 of the deposit core gates it, an unseen user is marked and registered first, only the first dex gets the amount, one ledger record carries the amount over 1e6 as f64, and two words of a per-user row each rise by the amount divided by 10000.

- Component ID: `bridge` (deposit path after `bridge-deposit-votes-94`; arms 44 and 84 of RE-010 both call it)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for bytes, branch order, constants, Location records and call sites; inference for what the marked byte, the row words and the ledger record mean; unresolved items are under limits
- Scope included and excluded: included is the whole function `0x27123d0`, 346 rows, run as real bytes. Excluded, and stubs here: the deposit core `0x374e2e0` (the deposit votes packet), the address hash `0x399c7a0`, the row lookup `0x1f849b0`, the first-seen call `0x2716bc0`, the balance add `0x36ff4f0`, the ledger push at slot `0x5774738` and the status drop `0x3379490`. #131 lists `0x27123d0` in an inventory, and #38 and #234 as a census row; none of them binds its body. The body `0x4d055f0` has the same size and is not run.

## Reproduce

```
python3 tools/bridge_deposit_credit.py --out research/work-items/bridge-deposit-credit-94
python3 -m unittest tests.test_bridge_deposit_credit
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder walks the bytes, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run takes under a minute.

## Evidence

Addresses are virtual addresses. Instruction rows are in `function-rows.tsv`; the function ends exactly at its FDE end. Rows quoted below are bound in `key-rows.tsv`, so a moved row fails the run.

### Order of the function

| Step | Rows | What happens |
| --- | --- | --- |
| 1 | `0x27123f1` | amount at or above `0x0ccccccccccccccc`: status `0x13f` with the amount |
| 2 | `0x27123f9` | byte at action `+0x40` not zero: status `0x37`, byte kept at result `+3` |
| 3 | `0x2712486` | core through slot `0x5774a00`, with the 12 time bytes of state `+0x60` |
| 4 | `0x2712496` | any other core status is copied out |
| 5 | `0x271249e` | result bit 0 clear: status `0x186`, nothing else (the core gives 0 below 5,000,000) |
| 6 | `0x27124c7` on | user lookup, below |
| 7 | `0x27127e3` | `0x36ff4f0` with the first dex, the user, the amount |
| 8 | `0x27127f2` | first dex word `+0x238` plus the amount |
| 9 | `0x271288b` | one ledger record |
| 10 | `0x27128c5` on | row words plus amount over 10000 |

Only bit 0 of the result is tested: `core_result_two_bit_clear`, `core_result_three_bit_set`.

The gates sit before the core, so a refused amount or byte leaves the votes alone. Both arms reach this function: `call-sites.tsv` has `0x1e5ff76` and `0x1e64811`.

### Finding a known user

The function walks the dex list at state `+0x5c0`, `+0x5c8`, `0x2f0` bytes each, and skips a dex whose count at `+0x110` is zero. Otherwise it probes a table of `0x78`-byte rows, control bytes at `+0xf8`, mask at `+0x100`, hash seed at `+0x118`. A hit in any dex ends the walk. Then one more table at state `+0x318`, `+0x320`, count `+0x330`, seed `+0x338`, with `0x58`-byte rows. All 20 address bytes are compared (`probe_last_byte_differs`, `probe_last_word_differs`, and the `base_` pair).

A user in none of them is new: the row from `0x1f849b0` at state `+0x740` gets byte `+0x3d` set to 1, and `0x2716bc0` runs. A known user skips both. Only the first-seen path touches that byte.

### What the amount does

- Only dex 0 gets the balance call and `+0x238`, whichever dex held the user (`total_only_first_dex`, `known_second_dex`).
- With an empty dex list, a credit panics through the expect at `0x27129bd`, after the first-seen step for a new user (`no_dex_new_user_panics`). A result of 0 does not reach that (`no_dex_result_zero_is_fine`).
- `+0x238` is a signed add. On overflow the recorder runs with Location `l1/src/qtys/mod.rs:830` and the word saturates (`locations.tsv`).
- The ledger record starts with word `0x8000000000000001`, then the f64 of the amount over `1000000.0` from `0x20ae60`. It goes to the push with a one-element user list, the time, and the 32 bytes at action `+0x20`, which is key `+0x18`.
- Row `+0x10` and `+0x18` each rise by `floor(amount / 10000)`, from the multiplier `0x346dc5d63886594b` and shift 11 of the high word (`constants.tsv`), checked at both sides of the step. An amount under 10000 adds nothing (`scale_below_one_unit`). Overflow runs the recorder with Location `l1/src/qtys/impl_ntl.rs:665` and saturates at `i64::MAX` (`row_saturates_a`, `row_saturates_both`).

The row is fetched a second time for this, so a new user does two lookups.

## Implementation and comparison

Not yet implemented as Rust. `tools/bridge_deposit_credit.py` is a rule list written from the steps above, compared with real bytes, not a reconstruction claim.

`Model` predicts each status, the arguments of each stub, the first dex word and the row. The compare is exact. Tables are real control bytes, with same-tag rows, full groups and a second probe group.

| Check | Result |
| --- | --- |
| Named scenarios | 49, 51 operations |
| Generated scenarios | 200 |
| Mismatches | 0 |
| Byte edits on reached rows | 123: 112 killed, 11 survived |

`mutations.tsv` has every edit with the first scenario that killed it. Survivors have a class label only and are rows this packet does not constrain.

## Results and limitations

- 14 of 346 rows are not reached: an allocation failure and the unwind rows (`unreached.tsv`).
- `0x2716bc0` is a stub, so what registering a new user does is not shown. `0x36ff4f0` is a stub, so the user balance rule is not shown here.
- `0x399c7a0` is a stub with a fixed value, so the hash and its seed are not shown; probe order is, for that value.
- The 0xb0-byte record is compared on its first two words only. What the push does is not followed.
- The field names of the row at state `+0x740`, of `+0x3d`, and of dex `+0x238` are not established. The two Location paths, in `qtys`, are the only labels here.
- `status-text.tsv` gives "Price too large" for status `0x37`, read from the status table. That text does not fit a deposit byte and is not claimed as its meaning. What byte `+0x40` holds is the kind byte of the key, by offset.
- `0x374e2e0` is a stub, so its statuses and result byte are chosen per scenario.

Next question: what `0x2716bc0` registers for a new user, and which reader uses row `+0x10` and `+0x18`.
