# fees: perp fill fee settlement, from the fee record to balances, the deposit total and the dex credit

This packet shows what `0x3710a70` does with the fee output of `0x37130b0` on every perp fill: which words leave the party balance or isolated margin, which words lower `total_net_deposit`, when the `znfn` word grows, which 8 addresses skip the fee, and how the maker's margin sum is rebuilt, so a reconstruction can settle a perp fill from these rules (the reference has no such step).

- Component ID: fees (`l1/fees/*`; the code sits next to `l1/clearinghouse/*`, only the fee path and the host body are claimed)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c`; `references/can1357-hl` as a lead only, nothing copied
- Claim status: observation for the byte behaviour below; inference where marked; no Rust implementation
- Scope included and excluded: included are `0x3710a70` (fill apply, 4399 bytes, 935 instructions) as a whole function, `0x36f7350` (132 instructions) and `0x37e4fb0` (66 instructions). Excluded are the fee body `0x37130b0` (`fees-trade-fee-94`), the dex credit `0x37067b0` (`fees-collection-94`), the position update `0x36fe830` and the row, set and entry helpers listed in `stubs.tsv`. Those stay stubs with checked arguments. Node #115 is not read.

## Reproduce

From the repository root, Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. The binary is read as bytes and never executed.

```
python3 tools/fees_perp_settlement.py --out research/work-items/fees-perp-settlement-94
python3 -m unittest tests.test_fees_perp_settlement
```

The tool checks the binary SHA-256 first and fails on any other input. It takes about 40 s: 913 vectors, then the mutation survey. Two full generations ran in parallel with different hash seed, time zone and a PATH with no binutils; they were byte-identical.

## Evidence

Coordinates are virtual addresses. Function bounds are FDE extents; the decoder must land on each end. `path-map.tsv` is the whole path in order, `fee-words.tsv` the use of each fee output word, `margin-rule.tsv` the maker tail, `flows.tsv` worked results from evaluated bytes, `locations.tsv` every panic and recorder record, `call-sites.tsv` the callers, `exempt-addresses.tsv` the 8 addresses, `serde-names.tsv` the field names, `pins.tsv` the bytes that carry the claims, `stubs.tsv` the functions left out, `unstepped.tsv` every instruction no vector stepped, with its reason.

`0x3710a70(clearinghouse, byte, fill, ctx)`. Four call sites through slot `0x5774868`: `0x26ed0ec`, `0x4312265`, `0x4315ec5` pick a clearinghouse from a 0x2f0-stride list, and `0x37087ed` is the netting path. The fill holds two 0x100-byte party blocks (user at party +0xd8), then fill +0x200 price, +0x208 asset, +0x210 size, +0x218 notional, +0x234 maker party index.

For party 0, then party 1:

1. Exempt test `0x37e4fb0` (slot `0x5773228`): 8 fixed addresses, read from `.rodata`. A hit skips steps 2 to 8 and sets a flag; the size must still be non-negative, and the party's net is 0.
2. Fee slot `0x5774890` with the frame of `fees-trade-fee-94`: party +0x20..+0x48, ctx, asset, user, `s = party == fill +0x234`, party, the byte argument. So `s` is true for the maker.
3. Gross `+0x50` and rebate `+0x58` must be non-negative as i64, or panic at `l1/src/qtys/mod.rs:843:1`.
4. Row of clearinghouse +0xf8, created on a miss, then user into set +0x188. Position entry by an inline B-tree search of row +8 on the asset; a vacant asset inserts.
5. `net = gross - rebate`. Position value byte +0 picks the payer: 0 takes it from row +0, any other value from value +8. The store saturates as i64 and calls the recorder at `l1/src/qtys/impl_ntl.rs:62:1`. A rebate is a negative net, so it credits.
6. The position wrapper `0x36f7350(asset, size, size, row +0x20, clearinghouse +0x170)` runs with the same size twice. Run real, it moves row +0x20 only on a change from or to 0 and moves the asset total by `new - old`, so here both stay. It can still create the asset's total entry.
7. Clearinghouse +0x238 falls by extra (skipped at 0), builder (bit 0 of output +0) and referrer (dword output +0x28 == 1). Each has the sign panic and the i64 saturation.
8. Deployer `+0x68` and protocol `+0x70` go to two signed saturating sums. Neither has a sign gate. The whole 0x78-byte output is stored at party +0x58.
9. The size must be non-negative (`l1/src/qtys/mod.rs:844:1`). Party 0 gets `+size`, party 1 gets `-size`, whatever fill +0x234 says.
10. `0x36fe830(out, clearinghouse, asset, price, signed size, user)` with a stack word: the party's net, 0 if exempt. A tag other than 0x186 panics at `l1/src/clearinghouse/cl_trait.rs:293:101`.

After both parties:

11. With no exempt party and `deployer + protocol == 0`, clearinghouse +0x2d8 grows by the notional, unsigned saturating. The test uses the sums, not the gross, so a fill with gross fee that sums to 0 counts (`zero total sum`), and a lazy cell at `0x577ab98` is forced first.
12. Slot `0x5774918` credits (clearinghouse, deployer sum, protocol sum, ctx) on every fill, even at 0.
13. The maker's size is read from its row through `0x36f57f0`, 0 if absent. Map +0x128 (user, stride 0x50) then an inner map (asset, stride 0x40) gives a row. A miss at any level, or item count 0, ends here. Otherwise the row's size is replaced and the outer sum at entry end -8 becomes `sat(sum + f(new))`, floored at 0 after `- f(old)`. `f` is in `margin-rule.tsv`.

`f(s) = floor(max(small, value) / L)`, `value = min(floor(big / count) * (count - 2|s|), big - 2 K |s|)`, with `big`, `small` and `count` chosen by the sign of `s`, and value 0 on any of 6 limit tests.

Field names, from serializer `0x370c340` (`serde-names.tsv`): +0x238 sits after key `total_net_deposit`, +0x240 after `total_non_bridge_deposit`, +0x2d8 before key `znfn`.

Worked rows, from `flows.tsv`, gross 9000 with deployer 2500 and protocol 6500 per party:

| Case | party 0 row | party 1 row | deposit total | znfn | credit |
|---|---|---|---|---|---|
| plain fee, both parties | -9000 | -9000 | 0 | 0 | 5000, 13000 |
| taker pays, maker rebate 1500 | -9000 | +1500 | 0 | 0 | 2500, 6500 |
| builder 100, referrer 70, extra 40 on both | -9000 | -9000 | -420 | 0 | 5000, 12580 |
| no fee words, notional 777000 | 0 | 0 | 0 | +777000 | 0, 0 |
| party 0 exempt | 0 | -9000 | 0 | 0 | 2500, 6500 |

Inferences, not observations:

- `+0x238` is the total behind key `total_net_deposit`: the key sits directly before the load in the serializer. Builder, referrer and extra leave it because they leave this dex's books; the code that pays them is not read here.
- `znfn` holds notional of zero-fee fills: the writer in this path gives that use, and the 4 letters are not expanded anywhere in the binary text I read. `0x370a640` zeroes it, `0x370c340`, `0x370d030` and `0x26c8f10` read it.
- Map +0x128 is resting order margin: `A`, `B` read as notional of two sides, `C`, `D` as their sizes, `K` as a price, `L` as leverage, and only the maker's row moves. The reference's name `rescale_position_oi_unit` for `0x370e6a0` agrees with `L` being the position's value +4. This also answers why this host doubles a size next to a product, a question left open in another packet's doubling census.
- Fill +0x234 names the maker: `s` means maker in `fees-trade-fee-94`, and only that party's margin row moves.
- The 8 exempt addresses are the privileged list of `fees-open-order-cap-94`, by the same function `0x37e4fb0`.
- Row +0x20 is the count of open positions: `0x36f7350` adds one going from 0 and subtracts one going to 0. Set +0x158 then holds users with a position. No write to it was read here.

## Implementation and comparison

not yet implemented

The evaluator interprets decoded instructions; a separately written specification predicts the list of stub calls in order, every word and block byte. Stubs spoil caller-saved registers and check arguments: the fee frame byte by byte, position handles against an independent tree walk, hasher places. Maps are real hashbrown layouts with decoys and tombstone walls that put keys at the exact byte of the second and third group. Position trees are real node layouts up to 3 levels with stale keys past the length.

`reference-diff.tsv` holds 8 differences against the reference. The main ones: party 0 always buys, the reference's `side_notional_hint` is the net fee, and +0x238 is not a transfer budget.

## Results and limitations

- 913 vectors (626 fill and margin vectors, 287 size hook vectors), 0 mismatches. `evidence.json` has the counts.
- 346 mutants: 336 killed, 5 survived, 5 unreached, each with a reason in `mutations.tsv`. The survey flips conditions, immediates and non-stack field offsets, not stack slots.
- Instructions stepped: 888 of 935 in `0x3710a70`, 131 of 132 in `0x36f7350`, 66 of 66 in `0x37e4fb0`. All others are listed in `unstepped.tsv`: padding, the leverage hook call, 2 recorder arms ruled out by the limit test before them, a ud2, an unwind pad and one jump.
- The fill vectors force row +0x20 through the `0x36f7350` stub to step the set +0x158 arms. The real function, run in its own vectors, cannot move that word at this site, so those two arms and the leverage hook are dead here. They are kept as generic wrapper code, by inference.
- `L == 0` is not tried: `div` would fault. Whether a stored row can hold 0 is not read.
- Not read: `0x36fe830` itself, so what it does with the net stack word is known only from the reference. The fill byte argument is only forwarded here.
- Maker index values other than 0 and 1 are not tried.

Next question: what does `0x36fe830` do with the net fee stack word, and which function builds the map +0x128 rows (`0x370e2a0` doubles a size in the same shape)?
