# RE-007: the liquidate action from signer gate to position hand-over on node #94

This packet shows who may liquidate, what the three request shapes admit, and at what price a liquidated position is handed over: a reconstruction can now write the `liquidate` action and the part of the executor after the plan from bytes, including 7 points where the reference text is wrong.

- Component ID: RE-007
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for the bytes, gates and arithmetic; inference for field names; unresolved items are listed in Results and limitations
- Scope included: handler `0x23e66f0` with copies `0x4ad4900`, `0x4ad5910`; route builder `0x3424d20`; agent chain `0x275f050` with copies; executor `0x2725150` with copies `0x4d2b3c0`, `0x4d2cd20`; event row `0x392b7b0`; list clone `0x254e820`
- Scope excluded: the plan `0x36fff10` that decides what is liquidated, which is checked at its edge and stubbed; the other executor host `0x27078a0`; order send and cancel bodies

## Reproduce

```
python3 tools/liquidate_path.py --out research/work-items/RE-007-liquidate-path-94
python3 -m unittest tests.test_liquidate_path
```

Python 3 standard library plus `tools/fde_extents.py` and `tools/elf_index.py`. The tool checks the input digest first and takes about 110 s. It writes `evidence.json`, `path-map.tsv`, `reference-diffs.tsv`, `gate-samples.tsv`, `price-samples.tsv` and `mutations.tsv`. Nothing is executed from the target: instructions are decoded from ELF bytes and stepped in a Python evaluator. No objdump or readelf output is parsed.

## Evidence

Addresses are virtual addresses in the file-backed sections of the target. Function bounds are exact `.eh_frame` FDE starts and ends. All numbers below come from `evidence.json`.

The dispatch row is RE-010 index 10, tag 126, wire name `liquidate`, arm `0x2759d84`. The handler has one direct caller, `0x2759240`, and the copies follow the same call list with their own helper addresses. The executor has a second host, `0x27078a0`, which this packet does not read.

### Handler gates

`path-map.tsv` lists the stages in order. The action holds the tag at +0, the request at +8, the user at +0x20 and the liquidator at +0x34.

1. The liquidator must be in the address set at exchange +0x3948, or the row is 0x23 (35).
2. If the signer differs, the liquidator must be a key of the map at exchange +0x8d0, or the row is again 0x23. Then the walk goes from key to the address at row +0x98 until that address equals the signer. A missing key gives 0x7c (124) with signer and liquidator. `0x275f050` is the same walk as a function.
3. Tag 2 is one asset. An odd tag is a map of address to asset set. Any other even tag means no assets.
4. Each asset goes through `0x3c0cc70`. Kind 1 is 0x15e (350). The id is cut by 10000 to read the dex row at exchange +0x5c0, stride 0x2f0, and byte +0x230 must be 3, or the row is 0x61 (97).
5. A map or a set longer than 10000 is 0x143 (323).
6. Every list entry is authorised like the signer: it must be in +0x3948 (0x23), and unless it is the signer it must be a key of +0x8d0 (0x23) with a chain that reaches the signer (0x7c).

### Route

`0x3424d20` runs after all entries pass, so asset refusals come first. A liquidator that also appears in the map is 0x25 (37). Then it walks the map in key order, pushes each address after the default one, and inserts each asset in a map of asset to address. A repeated asset is 0x24 (36) with the id, and this catches two wire assets that encode to one id.

### Executor

The handler always passes dex index 0, from `xor ecx, ecx` at `0x23e72ed`. An id from another dex passes the handler gate against its own dex row, and only the book walk uses that dex.

1. `0x36fff10` returns a status or rows of 0x68. Any other status is returned as is.
2. Each row gives one event: `Isolated` when word 0 is 1, else `Cross`, then +0x30 and signed +0x38 divided by 1e6 as doubles.
3. Flag 1 cancels the user's orders in that asset's book. Flag 0 walks all markets of the dex by id = dex row +0x30 x 10000 + index. A position with word 0 != 0 and word +0x10 != 0 keeps its orders, and every other market cancels with reason 13.
4. Each row takes one order id per item from exchange +0x38, saturating at u64::MAX. Items of size 0 take an id too.
5. For each item (asset, size, value) with size != 0:

```
share = |value| / row +0x30, or 0.0 when +0x30 is 0
rest  = value - saturating(row +0x38 * share)     saturating, logs on overflow
long:  rest = max(rest, 1)     short: rest = min(rest, -1)
price = floor(|rest| / |size|), at least 1
price * |size| >= i64::MAX panics
```

6. The order row goes to `0x26f4cd0` with source byte 1, the 32 block bytes and mode bytes k, b, k, b, where k = 1 when row word 0 is 0, else 2, and b = 1 for a short.
7. Row word 0 == 2 ends the walk. The executor returns the +0x28 word of every row.

`price-samples.tsv` shows the formula on real runs. `gate-samples.tsv` shows refusals with the outward calls made before them.

### Inferences

- `.rodata` holds the keys `liquidatedNtlPos`, `accountValue`, `leverageType`, `liquidatedPositions` and `liquidation`. The event row is built from `Cross` or `Isolated` and the two /1e6 words, so +0x30 is read as notional and +0x38 as account value. Items are read as (asset, size, notional).
- With those names the price is the signed notional minus the position's share of account value, per unit of size, which is a bankruptcy price. Bytes show the arithmetic only. The name is an inference.
- The map at +0x8d0 is called a delegate map in the reference. Its rows are 0xb0 wide and row +0x98 is an address. The chain walk fits a parent or agent link. The field name is unresolved.
- Byte +0x230 of the dex row is read as the `MainOrHip3` tag with 3 = Main, per earlier packets. The reference calls it a market status.

## Implementation and comparison

Rust implementation: not yet implemented. Comparison here is byte evaluation against a separately written Python specification, not a Rust build.

Each case runs on all 3 copies. A case compares outward calls in order, arguments, frees, result row, order id counter and overflow logs. Real helpers and stubbed edges are listed in `evidence.json`.

| Metric | Value |
|---|---|
| Cases | 441 (68 action and 79 executor cases on each of 3 copies) |
| Mismatches | 0 |
| Instructions stepped | 499,813 |
| Stepped / total: handler primary | 711 / 823 |
| Stepped / total: route shared | 243 / 295 |
| Stepped / total: agent chain primary | 88 / 91 |
| Stepped / total: executor primary | 997 / 1224 |
| Stepped / total: event row shared | 72 / 85 |
| Stepped / total: list clone primary | 80 / 94 |
| Stepped / total: handler second | 711 / 823 |
| Stepped / total: agent chain second | 88 / 91 |
| Stepped / total: executor second | 978 / 1205 |
| Stepped / total: handler recording | 711 / 823 |
| Stepped / total: agent chain recording | 88 / 91 |
| Stepped / total: executor recording | 969 / 1195 |
| Mutants killed / survived / unreached | 697 / 76 / 81 |

`reference-diffs.tsv` lists the 7 points where `l1/exchange/handlers/10_liquidate.rs` differs from the bytes. The reference is only a lead and nothing was copied from it.

Mutation pass on the primary copies: each condition, immediate and field offset is flipped alone and the reaching cases are rerun. 76 survived and 81 were not reached. Each has a reason in `mutations.tsv`.

## Results and limitations

- 0 mismatches. This covers the listed functions and does not cover the plan.
- The refusal rows carry stale words on 2 paths. A list asset of kind 1 reports the id of the asset before it, because the slot is written after the test. A set over the limit reports the previous entry's pointer, because the pointer slot is written after the test. For the first asset or entry the word is an old stack value, so the specification checks only the status there. Consumers that print these rows are not traced.
- `0x36fff10` is stubbed, so row contents here are fixtures. Which positions and which amounts reach the executor is not shown.
- A sentinel row with word 0 == 2 is exercised by fixtures. Whether the plan can emit one is unknown.
- Copies differ in arguments: the recording copy shifts +0x5b8, +0x5c0, +0x8d0, +0x8f2, +0x3370 and +0x3948 by 0xa80 and its sink takes exchange +0x5b8. The two copies pass cancel and send arguments in another order. Mutants run on primary only.
- Height 8 or more is not built.
- No progress gate is requested.

Next question: what does `0x36fff10` do between the margin read at `0x37d7360` and the row list, starting with status 0x20 at `0x370090d` and the per-liquidator loop at `0x3700080`?
