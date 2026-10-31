# RE-007: system user pass of `apply_bole_liquidations`: value test, sell loop, buy loop, price guard, size cap, gate release

This packet shows how the system user turns its BOLE rows into spot orders, so a reconstruction can now write which tokens it sells, how much it buys, what the order price and size limits are, and which failures release gate `+0x5b3`.

- Component ID: RE-007 (risk, oracles, liquidation), BOLE liquidation path
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for bytes, layouts, order of calls, constants, rounding and comparison direction; inference for what the words mean; unresolved items are listed under Results and limitations
- Scope included and excluded: included, whole and with mutants, are the pass `0x2739d70`, the wrappers `0x4d4a3a0` and `0x4d4a260` with their bodies `0x46f7560` and `0x46f8400`, and the 3 copies of the order builder `0x27653a0`, `0x4d96870`, `0x4d96610`. The unit helpers `0x32815f0` and `0x32813d0` and the standard B-tree map code run as real bytes under them, with no mutants: they are helpers here and appear in other packets. Stubbed with checked arguments: the health read, snapshots, row collector, spot view, cancel, cancel report consumer, event writer, post check, order price, book reference price, hasher and order entry. `evidence.json` lists each edge. The shortfall sweep `0x2765600` is excluded.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned binary in place:

```
python3 tools/artifacts.py verify
python3 tools/system_user_pass.py --out research/work-items/RE-007-system-user-pass-94
python3 -m unittest tests.test_system_user_pass
sha256sum -c MANIFEST.sha256   # inside the folder
```

The tool takes about 250 s on an idle machine and checks the input SHA-256 first. It reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`, with no objdump or readelf output. It never runs the binary. All numbers below come from the generated files.

| File | Content |
|---|---|
| `evidence.json` | functions with hashes, callers, constants, twin comparison, wrapper calls, body tags, stubs, case outcomes |
| `path-map.tsv` | the pass in order |
| `decision-samples.tsv` | real runs: cancels, orders, gate and result for 8 row sets |
| `order-samples.tsv` | real runs of the order builder: price, size and asset |
| `mutations.tsv` | every flipped branch, condition, immediate and offset, with a reason for each that stayed |

## Evidence

Coordinates are virtual addresses. Offsets are from the exchange pointer unless marked otherwise. The BOLE state sits at +0x498.

### Hosts

| Copy | Step body | Entry | Body | Order builder | Cancel report | Post check | Book table |
|---|---|---|---|---|---|---|---|
| primary | `0x222caf0` | `0x2739d70` | inline | `0x27653a0` | `0x2739210` | `0x2739b00` | `+0x3388` |
| second | `0x4714080` | `0x4d4a3a0` | `0x46f7560` | `0x4d96870` | `0x46f1b90` | `0x46f26f0` | `+0x3388` |
| recording | `0x47121b0` | `0x4d4a260` | `0x46f8400` | `0x4d96610` | `0x46f12a0` | `0x46f2480` | `+0x3e08` |

The primary keeps the whole pass in one function. In the other two the same logic is split into a wrapper (snapshot, body, writer, post check) and an outlined body that returns a tag. All 3 ran the same cases. `twins` in `evidence.json` shows the second and recording bodies have the same operation list.

### Order of work

`path-map.tsv` has the 12 stages. The step passes the `0xbb` system address as the user, so the user row and the rows from `0x3739ef0` are the same account there.

1. Health read. A failed read returns its byte. A negative word panics in `unwrap`. When word +8 of the row copy is 0, the pass returns the row's low byte and writes nothing.
2. Only byte `+0x5b3 == 1` opens the body. Other values skip to the writer and post check, with no change to the byte.
3. Rows come as `(token, debt, supply)`, 24 bytes each. For each row:

```
available = min(supply, token.pool) + spot_balance        # saturating, a log on overflow
token 0:      have += value(available, floor); need += value(debt, ceil) when debt != 0
other, debt:  shortfall[token] = max(debt - available, 0); need += value(shortfall, ceil)
other, no debt: skipped
```

`token.pool` is word +0x18 and the price word +0x10 of the row in the token tree at `+0x568`. `value` is `0x32815f0`: `amount * price / (100 * 10^gap)`, with `gap` the difference of the two decimal bytes at table row +0x48 and +0x49. A wide result at or above `0x28f5c28f5c28f5c` fails it. Sums `have` and `need` saturate, with a log. A shortfall of 0 still creates a map row.

4. `need > have`: for each row token that is not 0 and has no debt, in row order: cancel, read the spot balance after the cancel, sell all of it.
5. `need != 0`: cancel token 0, with no order after it. Then in key order for the shortfall map: cancel, buy the shortfall.

So sells and buys go out in the same pass, and a buy uses the amount computed before any cancel, while a sell uses the balance after its cancel. `need == have` sells nothing and still buys. A token with a debt row is never sold, even with a large balance. `decision-samples.tsv` shows each of these.

### Gate release

The byte `+0x5b3` is cleared when a row token is missing from the tree, when a value fails, when the row collector fails with a byte other than 0x11, or when a cancel fails. A cancel fails with tag 3 and a byte other than 0x11, or when a report carries flag +0x108 equal to 1. In all of these the writer and post check still run, and the pass returns the post check result. The outlined bodies load a tag for each failure into r12b (`body_tags` in `evidence.json`), and their wrappers only compare it with 0x11, so no tag value survives the pass. Cancel tag 2 goes on with no report. Other tags go to the report consumer, then on.

### Order builder

`0x27653a0(exchange, token, side, amount, seconds)`. Side 1 is a sell.

| Step | Sell | Buy |
|---|---|---|
| amount 0 | return | return |
| slippage to `0x3736960` | 0.01 (`0x20a2f8`) | 0.005 (`0x20b168`) |
| price word 0 | return | return |
| guard table `+0x4a8`, skipped when `+0x4c0` is 0 | price raised to word row-0x10 when below | price lowered to word row-8 when at or above |
| guard word 0 or no row | keep price | keep price |
| size | `min(amount / 10^gap, 5e13 / reference)` | same |
| size 0 | return | **order still goes out** |

`seconds` is `word +0x4d8 / 1000.0`, the same word as the bucket width of the step gate. The order entry gets two records: head (BOLE words 0 and 1, seconds, `0xbb` address) and body (asset, size, price, exchange, side, 0). The asset index must be below word `+0x3390` (`+0x3e10` in the recording copy), else a bound panic. The reference price `0x32780d0` has no zero test before the divide.

## Implementation and comparison

not yet implemented

The comparison is a Python evaluator over the real bytes against a separately written specification (`Spec`), which predicts every outward call in order, the result byte, the gate, logs and vector frees. It also checks that all map nodes are freed.

| Measure | Value |
|---|---|
| Cases | 533 |
| Mismatches | 0 |
| Instructions stepped | 861,850 |
| Stepped / total: order primary | 145 / 145 |
| Stepped / total: pass primary | 814 / 896 |
| Stepped / total: order second | 145 / 145 |
| Stepped / total: wrapper second | 69 / 75 |
| Stepped / total: body second | 687 / 753 |
| Stepped / total: order recording | 145 / 145 |
| Stepped / total: wrapper recording | 69 / 75 |
| Stepped / total: body recording | 687 / 753 |
| Mutants killed / survived / unreached | 845 / 60 / 32 |

## Results and limitations

Inferences:

- Rows are debts and supplies of the system user, as in the bole step packet: debt is rounded up and supply down there. Token 0 acts as the quote, since it is the only token counted in `have` and it is never ordered.
- `5e13 / reference` looks like a notional cap per order. With a price scaled by 1e8 it would be 500,000 units. The scale is not pinned here.
- `seconds` in the order head may be a lifetime for the generated order. Nothing here reads it.
- The guard table looks like per-token price limits. Its writer is not pinned, so the meaning of the two words comes from the comparison direction alone.

Unresolved and limits:

- The specification comes from reading the same code, so a match is a cross-check. Mutants show the run can tell, not that the reading of intent is right.
- 60 mutants survived and 32 were unreached, each with a reason in `mutations.tsv`.
- Stubs give the row set, spot view and cancel result. A real sequence of these calls is not simulated. In particular, cancels may change balances between rows, which the fixture models with one before and one after table.
- Rows in a live state are unique and sorted by the B-tree. Repeated tokens appear only in the sum overflow cases.
- Row byte +0 returned when word +8 is 0 may be a niche in the row type. Whether that state exists is not known, and in that branch the clone is not dropped.
- `0x2730520` receives only registers rdi to rcx here. Its switch arm 6 is not read.
- The unit helpers `0x32815f0` and `0x32813d0` appear in other packets, so they get no mutants here, and the formula above is only what this call sees.
- The copies carry their own overflow Location records, so only the primary compares those addresses. The copies compare the count.
- `0x2765600` and the readers of the set at `+0x8b8` are the next stage.
- No progress gate is requested.
