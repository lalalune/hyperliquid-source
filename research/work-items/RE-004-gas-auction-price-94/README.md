# RE-004: gas auction price curve, restart rule and payment gates in node #94

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the decisions, the output fields, the serde field offsets, the call sites and the status text; inference for what the actions behind the gates are; unresolved items are listed under limits
- Scope included and excluded: included are the price function `0x325ccb0`, the state rows of the restart closure `0x33742d0`, the bucket roll copies `0x2702060`, `0x4cee310`, `0x4cee5e0`, the gates `0x2744020`, `0x4d5c4f0`, `0x46ce080`, `0x46ce200`, and the info row `0x2a25590`, run as real bytes. The two slot loops `0x3bb0400` and `0x3c1a9e0` are checked for shape only. Excluded are the callers of the gates, the function that charges and records the end price, the timing and logging tail of the restart closure, and the rows of `0x4cee5e0` after the slot loop returns.

## Reproduce

```
python3 tools/gas_auction_price.py --out research/work-items/RE-004-gas-auction-price-94
python3 -m unittest tests.test_gas_auction_price
```

Run from the repository root with Python 3 and the standard library; no external program is used, and the output hashes are in `MANIFEST.sha256`. The tool reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output and it does not execute the binary. A run takes about 30 to 60 s, depending on load.

## Evidence

Coordinates are virtual addresses. Rows come from the tool's own decoder (`function-rows.tsv`). `0x325ccb0` is reached through slot `0x57739b8` by 8 `call` sites, all listed in `call-sites.tsv` with the sites of the other functions.

Field layout. The serializer `0x230bc10` names each field of `struct GasAuction` from bytes (`fields.tsv`). The word at `+0x00` is the option tag of `end_gas_wei`; it uses the value 2 as the niche for a whole auction that is absent, as the roll loop below shows.

| Offset | Field |
|---|---|
| `+0x00` | `end_gas_wei` tag: 0 none, 1 some |
| `+0x08` | `end_gas_wei` value |
| `+0x10` | `bucket_guard`: bucket size in milliseconds |
| `+0x18` | `bucket_guard`: last bucket number |
| `+0x20` | `initial_gas_to_last_auction_gas_ratio` (u64) |
| `+0x28` | `start_gas_wei` |
| `+0x30` | `token` |
| `+0x38` | `min_gas` |

State offsets. Two serializers name three auctions (`state-auctions.tsv`): `register_token_gas_auction`, `perp_deploy_gas_auction`, `spot_pair_deploy_gas_auction` at `+0x32a8`, `+0x32e8`, `+0x3328` in one layout and `+0x3d28`, `+0x3d68`, `+0x3da8` in the other. The first serializer's offsets are relative to an inner struct; base `0x1b20` is inferred from the match with the three roll offsets. A fourth auction sits at `+0x90`; no key was tied to it.

Status text comes from the Display table `0x59a8d0` (`status-text.tsv`):

| Tag | Text |
|---|---|
| `0x176` | Gas auction completed. Try again later. |
| `0x177` | Gas auction has not started. Try again later. |
| `0x178` | Gas fee is greater than the maximum fee set by user |
| `0x179` | Insufficient gas at current auction price. |
| `0x17a` | Deploys are currently disabled |
| `0xbf` | Sub result error |

Price `0x325ccb0(out, auction, now)`. Checks run in this order:

1. Low byte of `+0x00` not zero: `0x176`.
2. `T` is the bucket start from slot `0x576e888`, which reads `+0x10` and `+0x18`. `T` later than `now` (date signed, then seconds, then nanoseconds, each unsigned): `0x177`. Equal passes.
3. Slot `0x576e8c0` gives seconds `s` between the two times. `x = round(s * 1000.0)` through slot `0x576f6d8`.
4. `e = sat(x)`.
5. `start < min_gas`: `0xbf`, after the time calls.
6. `span = start - min_gas`, `f = max(1.0 - f64(e) / f64(bucket), 0.0)`, `p = f * f64(span)`, `u = sat(p)`.
7. `price = u + min_gas`. If that sum wraps, `price = min_gas`.

`sat(v)` is 0 for NaN and both infinities, 0 for `v <= 0`, `u64::MAX` for `v >= 2^64`, and `trunc(v)` otherwise. The function writes tag `0x186` and the price; it does not write the auction.

Consequences read from the same rows, each pinned in `edges.tsv` or `outcomes.tsv`:

- The price falls linearly from `start` to `min_gas` over one bucket and truncates toward `min_gas`. `start = 1000`, `min_gas = 100`, bucket 60000: 1000 at 0 s, 775 at 15 s, 550 at 30 s, 100 at 59.999 s and later.
- A double rounds `span`, so at zero elapsed the price can exceed `start`: `start = 2^53 + 3`, `min_gas = 0` gives `2^53 + 4`.
- A wrapped sum gives `min_gas`, not a saturated price: `start = u64::MAX`, `min_gas = 1` gives 1 at zero elapsed.
- An infinite or NaN `x` gives `e = 0`, so the price is `start`. A huge finite `x` gives `min_gas`.
- Bucket 0 gives `min_gas`, through NaN or infinity in the divide.
- The compare with `1.01` at `0x325ce87` has a branch to `min_gas`. No input takes it: see the inference below.

Whole-domain tails. Both float tails were split over all `2^64` bit patterns until each piece had one decision record (`stage-pieces.tsv`). The rows `0x325cd8b..0x325ce31` give 13 pieces and `0x325cec2..0x325cf26` give 14, in 1196 and 1444 runs. Every piece end and 8 interior points match `sat`.

Restart `0x33742d0(args, refs)`. `refs` holds pointers to `start`, the auction, the ratio and `min_gas`. The flag byte at `args+0x20` is the rolled flag. With flag not 1 it returns that byte and writes nothing. With flag 1:

- 32-bit tag at `+0x00` is 1: `start = end * ratio` when the 128-bit product fits in 64 bits. When it does not, `start` keeps its old value.
- Any other tag: `start = min_gas`.
- Then the 64-bit word at `+0x00` becomes 0. The end value at `+0x08` stays in place.

There is no floor on the sale path, so `end = 2`, `ratio = 3`, `min_gas = 1000` stores 6. The next price call on that auction then gives `0xbf`. The restart name string at `0x584604` is `gas_auction_restart`, and the closure goes on to timing and logging.

Bucket roll `0x2702060`, `0x4cee310`, `0x4cee5e0` (`roll-copies.tsv`). `now` in milliseconds is `(days * 86400 + seconds) * 1000 + nanos / 1000000`, floored at 0. The visit order is perp deploy, register token, spot pair, `+0x90`. For each auction:

1. 32-bit tag 2: skipped.
2. `b = now / bucket`, by a 32-bit or 64-bit `div` chosen by `(now | bucket) >> 32`. No zero test.
3. `b > last`: store `b`. The rolled flag is `b > last`.
4. Call the restart closure in both cases.

A word at `+0x3610` (`+0x4090` in the second layout) equal to `2^63` skips the next step. Otherwise slot table `+0x3618`, `+0x3620` (`+0x4098`, `+0x40a0`) goes to `0x3bb0400`. That function and `0x3c1a9e0` hold the same roll rows for slot auctions of stride `0x50`. The tool checks their shape only: one store of the bucket word and one call to the closure.

Gates. `0x2744020` and `0x4d5c4f0` take a parameter block: `+0x00` limit tag, `+0x08` limit, `+0x10` auction pointer, `+0x18..+0x2c` user, `+0x2c` keep byte, `+0x2d` exempt byte.

1. All-zero user: ok with flag 2, before any other check.
2. Null auction: `0x17a`.
3. Exempt byte set: ok with flag 2.
4. Keep byte set and low byte of `+0x00` set: price is the end value. No time is read and no limit is compared.
5. Otherwise price from `0x325ccb0`; any error is returned. With the keep byte clear and a limit tag set, `price > limit` gives `0x178`, and equal passes.
6. Balance row for the token: total `+0`, hold `+8`. Absent counts as 0, 0. `hold + price` wrapping or above total gives `0x179`.
7. Ok writes `+0x08` price, `+0x10` token, `+0x18` the keep byte.

`0x46ce080` and `0x46ce200` take the auction, the user, a limit flag byte and the limit in registers. They run steps 5 to 7 with the keep byte 0 and only the low byte of the flag.

Refusal output differs per copy. `0x2744020` writes the price and the token. `0x4d5c4f0` writes the token only; that word is the 4-byte difference between sizes 806 and 802. `0x46ce080` and `0x46ce200` write the tag alone.

Info row `0x2a25590`. It returns current price, end value, bucket start seconds, bucket seconds and start price, for a token in table `+0x180`, length `+0x188`, stride `0xe8`.

- Prices are `f64(wei) / 10^w`, where `w` is token byte `+0x49` and the powers come from table `0x584b08` (`constants.tsv` pins rows 0 to 19). `w` has no bound in these rows.
- A failed price call drops the error and gives a null.
- The end value is present when the whole 64-bit tag word is not 0, while the price test reads its low byte.
- `bucket seconds = bucket / 1000` by `(x >> 3) * 0x20c49ba5e353f7cf >> 68`. Exact for all u64: `m * 125 - 2^68 = 19`, and `19 * 2^61 < 2^68`.
- A token index past the length panics, before the price call.

## Implementation and comparison

Rust implementation: not yet implemented.

Comparison with `references/can1357-hl` (a clue, not a source): a search of the tree finds `DeployGasAuctionChange` and `GasAuctionChange` in `l1/action/vote_global.rs`, plain structs with no logic, and no `start_gas_wei`, `end_gas_wei`, `min_gas` auction field or restart. None of the rules above has a counterpart there.

## Results and limitations

Results from `evidence.json`:

- 327 named cases and 1200 generated cases, with 0 mismatches against a separately written specification. Output bytes, auction words, stub arguments and event order are compared. Named outcomes are in `outcomes.tsv`. The first specification wrote price and token on every refusal; the bytes disagreed in three of four copies, and the rule above is the corrected one.
- `mutations.tsv`: 560 byte edits on reached rows, 527 killed, 33 survived, each with a recorded reason. An unexplained survivor stops the tool, and an unedited image must pass under the mutant step limit. Most survivors are date constants that apply only to year 0 or earlier, where the clamp at 0 hides them.
- Unreached rows are listed per function. `0x325ceda` needs `p > 2^64`, which the whole-run cases never give; the split runs do execute it. `0x2702302` and its copy free a returned vector, and the stub returns none. `0x4cee5e0` has 84 unreached rows, for the same reason plus its landing pad.

Limits:

- Time helpers and the round helper are stubs. Slot `0x576e888` returns a chosen time and slot `0x576e8c0` chosen seconds, so their own arithmetic is not claimed here. The stub for slot `0x576f6d8` rounds halves away from zero by a rule of this packet; the real helper `0x565f410` is not run.
- The float tails are whole-domain. The middle rows, `f` and `p`, are held by vectors and edges only. The `1.01` claim is an inference, not a run.
- The balance map holder (slot `0x5773170`) is a stub; the B-tree rows are real bytes over fixtures of height 0 and 1.
- The writer of `end_gas_wei` and the callers that set the keep and exempt bytes are outside this packet, so the meaning of those bytes is not claimed. Keep byte, `span`, `e` and `sat` are labels of this packet.
- A bucket of 0 faults at the `div` in the roll rows. Whether any writer can store 0 is not read. The tests pin only that the evaluator stops there.
- The name of the auction at `+0x90` is unresolved. The caller of `0x2a25590` was not read, so which auction it reports is unresolved too.

Inferences, not generated evidence:

- The `1.01` branch is dead: `e` and `bucket` are not negative, so `q = f64(e) / f64(bucket)` is a non-negative number, `+inf`, or NaN. `1.0 - q` is then at most 1, `-inf`, or NaN, and `maxsd` with 0.0 returns 0.0 for NaN. So `f` is in `0.0..=1.0`, and the rows look like a shared scaled-amount helper with an upper guard.
- Tag `0xbf` after `end * ratio` needs `ratio` 0, or an end value below `min_gas / ratio`. The price function never returns below `min_gas`, so with `ratio >= 1` and an unchanged `min_gas`, an end value that came from this function cannot cause it. Who writes `ratio` is not read.
- The texts fit a Dutch auction for deploy gas: the first sale in a bucket closes it, the next bucket starts from `end * ratio`, and a bucket with no sale starts from `min_gas`.

The analysis ran to completion for the scope above. No progress gate is requested.

Next question: which vote or genesis path writes `start_gas_wei`, `min_gas`, the ratio and the bucket size, and does it refuse a ratio or bucket of 0?
