# fees: spot fill fee settlement from the fee record to the fee pool

This packet shows what happens to a spot fee after `0x3742460` computes it: which party balance each record word moves, how the net of each token is shared with the token deployer, and that the rest lands in the tree the spot sweep `0x26fe810` drains, so a reconstruction can settle a spot fill without the reference's reversed supply delta rule.

- Component ID: fees (`l1/fees/*`; the code sits next to `l1/spot_clearinghouse/*`, only the fee path is claimed)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c`; `references/can1357-hl` as a lead only, nothing copied
- Claim status: observation for the byte behaviour below; inference where marked; no Rust implementation
- Scope included and excluded: included are `0x372b9d0` (matched fill, 7182 bytes), `0x372e0a0` (order charge, 3515 bytes), `0x3c018a0` (fee split, 835 bytes) as whole functions. Excluded are the fee body `0x3742460` (`fees-trade-fee-94`), the conversion `0x333e310` (`RE-001-spot-meta-333e310-94`), base wei `0x375e300`, and the sweep itself (`fees-collection-94`); these stay stubs or pins.

## Reproduce

From the repository root, Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. The binary is read as bytes and never executed.

```
python3 tools/fees_spot_settlement.py --out research/work-items/fees-spot-settlement-94
python3 -m unittest tests.test_fees_spot_settlement
```

The tool checks the binary SHA-256 first and fails on any other input. It took about 420 s here at load 8 or more: 1072 vectors, then the mutation survey. Two generations with different hash seed and time zone were byte-identical; those two reused the rows of one complete survey, because two full parallel runs did not finish inside the slot at load 18.

## Evidence

Coordinates are virtual addresses. Function bounds are FDE extents; the decoder must land on each end. `path-map.tsv` is the whole path, `split-rules.tsv` the accumulator rules, `flows.tsv` worked results from evaluated bytes, `locations.tsv` every panic and recorder record, `call-sites.tsv` the callers, `pins.tsv` the bytes that carry the claims, `stubs.tsv` the functions left out.

Matched fill `0x372b9d0(clearinghouse, byte, fill, tracker)`. Three call sites through slot `0x5774828`. The fill holds two 0xf8-byte party records, then px +0x1f0, spot +0x1f8, size +0x200, notional +0x208 and a side byte +0x224.

1. Slot `0x57747a0` gives base token, an ok bit and base wei. Spot past the pair list panics. `px * size` overflow or a clear ok bit returns with nothing changed.
2. Gate: party 0 total of quote >= quote wei, party 1 total of base >= base wei. Only word 0 of the balance is read, so hold plays no part and total alone passes. A miss returns with nothing changed.
3. Party 0 receives base wei of the base token and pays quote wei of the quote token. Party 1 is the mirror. This does not depend on the side byte, which only feeds the fee record's cross byte.
4. If the pair base is not in the quote map at clearinghouse +0x260 and the outcome test `0x3728670` is true, there is no fee record for either party; the tag words and the gross, rebate and extra words of the party block are written 0.
5. Otherwise the fee body writes a 0x68-byte record, which is copied to party +0x60 unchanged, and the split `0x3c018a0` runs.
6. Gross leaves the received amount, and a gross above it panics. Rebate is added to total of the token the party pays. Then the received amount is added to total, and the paid amount leaves total and hold; hold saturates at 0 through the recorder, total panics on underflow, which needs a self trade on a pair with one token. Rebate and receive each add the token to the user's index at clearinghouse +0x400.

Split `0x3c018a0(out, acc, tokens, leg, px, record, meta)`. `acc` is 4 words. See `split-rules.tsv`. The convert test is the leg: leg 0 converts gross, leg 1 converts rebate, each through `0x333e310` with the base token and px; a refusal panics. Record +8 (tag +0 bit 0), +0x30 (tag +0x28 byte) and +0x60 are added to `acc[2 + leg]`. Any overflow panics with status 0xbe.

Tail, in both hosts, base token then quote token, with collected `acc[0]`, paid `acc[2]` for base and `acc[1]`, `acc[3]` for quote:

- Paid above collected: recorder kind 2, then the pool entry at clearinghouse +0x3a0 falls by the gap, saturating at 0.
- Otherwise a token past the row list panics. When row +0xd2 bit 0 is set, the deployer at row +0xd3 gets `floor(net * share / 1e5)` of the token, where share is row +0xa8, cast through f64, with factor above 1.01 giving 0, and a token listed in the quote map giving 0. The row, the balance entry and the index row are created even for amount 0. Deployer total saturates. Net falls by the amount, saturating at 0, and that is reachable because the factor may pass 1.0. The rest goes to the pool, saturating.

The pool is the sweep tree: `0x26fe810` loads exchange +0x420 and takes its clearinghouse at exchange +0x80, and +0x80 + 0x3a0 = +0x420 (`pins.tsv`). The node shape, length at +0xba, is the same. So the source of `total_spot_fees_collected` in `fees-collection-94` is this tail.

Order charge `0x372e0a0(clearinghouse, byte, count, order, tracker)`. A zero count or a zero word at +0x1f8 returns. Spot is at +0x1f0 here and px at +0x1f8. One party, the record at +0xf8 of the same layout. Fee class comes from the quote map and the outcome test, and class 2 is reachable here. Leg is 1. Record +0x58 is cleared before the split, so a rebate is dropped. Gross leaves total of the quote token, capped at `total - hold`, saturating at 0; hold ends unchanged. The accumulator is not reduced to the capped amount, so the tail shares and pools the full gross (see `flows.tsv`, last row). The caller at `0x24fce08` skips the call when the outcome test is false (`pins.tsv`); the other two callers are copies not read here.

Inferences. Party 0 as the buyer and party 1 as the seller come from the token direction. "Hold" for word +8 comes from the spend gate shape and the reference's name. "Fee pool" for clearinghouse +0x3a0 rests on the sweep pin. Reading record words as gross, rebate and extra follows `fees-trade-fee-94`; +8 as builder and +0x30 as referrer amount are labels from the reference.

Reference diffs are in `reference-diff.tsv`, 10 rows. The largest: `update_supply_delta` has the sign reversed and has no deployer share, `token_supply_deltas` is the swept fee pool, and `deployer_share` asks for an aligned quote flag that the bytes never read.

## Implementation and comparison

Rust: not yet implemented. Comparison: a Python evaluator steps the real bytes of the 3 functions, the party copy `0x3bb6760` and the B-tree helpers (`0x33bb560`, `0x33bc720`, `0x33c0d60`, `0x3398240` and 4 leaf inserters). A separate specification, `Ledger` and `fill_spec` in the tool, predicts every balance word, pool word, index row, created user row, recorder call, outcome test call, fee record byte, party block byte and panic Location. Final trees are walked, and key order and count words are checked.

1072 vectors (584 split, 312 fill, 176 charge): 0 mismatches. Instructions stepped: 2131 of 2248. Unstepped instructions are padding, unwind pads, and the arms listed in Limits.

Mutation survey flips each branch, set and cmov condition, immediate and non-stack displacement of the 3 functions: 790 mutants, 749 killed, 35 survived, 6 unreached, each survivor and unreached row with its reason in `mutations.tsv`. Tests: 32 pass, including negative controls on the digest, a function bound, pin bytes, a constant, a wrong expected balance, and 6 live byte flips.

## Results and limitations

- Stubbed: see `stubs.tsv`. The fixed conversion ratio stands in for `0x333e310`, so no claim is made about real conversion rounding. Fee record words are vector inputs, not fee body output.
- Stack displacements are not in the survey. Whole-function runs and stale-slot checks cover them only indirectly.
- Not stepped, ruled out by earlier checks in the code: the second spot bound in each host, the `0x372c9b0` rootless arm, the `0x372d059` and `0x372e7ef` rootless arms, the infinity test in the deployer cast, and the hold arms at `0x372e495` to `0x372e4c5`, `0x372e50c`.
- The two copies of the order charge callers and the callers of the matched fill are listed, not read, apart from `0x24fce08` and the argument setup at `0x26e9acc`.
- No progress gate is requested.

Next question: which writer fills party +0x28..+0x50, the 0x28 bytes carried into the fee record head, and is it the builder choice that `fees-builder-gate-94` admits at order time?
