# fees: node #94 aligned quote token path, from the enable writer to the spot fee class bytes

This packet settles what the aligned quote token switch does to fees: one writer stores it in the token's aligned map entry and in byte +0x58 of every perp dex row with that collateral, and four spot sites and two outcome hosts turn it into the record byte the fee body scales by, so a reconstruction can name the `trial` byte of `fees-trade-fee-94` (it is `collateralIsAlignedQuoteToken`), name the record bytes `al` and bucket, and rebuild both enable refusals that the reference omits.

- Component ID: fees
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for byte-derived rules below, inference where marked, unresolved items listed under Results and limitations
- Scope included and excluded: included are the writer 0x274db00 and copies 0x4d6e380, 0x4d6ea40, the same-deployer collector 0x27e61a0 with its filter 0x257d2f0, the spot wrapper 0x372f020, the outcome hosts 0x3726360 and 0x3726980, and the record-building ranges of 0x372e0a0 and 0x372b9d0. Excluded are the deployer gate 0x2751b30 (a stub), the outcome helpers 0x385c150 and 0x3c18fb0 (#766, stubs), the B-tree remove, insert and drop helpers of the writer (stubs), the rest of the two fill hosts, the referrer and builder arms of the fee body, and the rate rows (a stub). The fee body 0x3742460 runs as real bytes but is not mutated here; `fees-trade-fee-94` covers it.

## Reproduce

Run from the repository root:

```
python3 tools/fees_aligned_quote.py --out research/work-items/fees-aligned-quote-94
cd research/work-items/fees-aligned-quote-94 && sha256sum -c MANIFEST.sha256
python3 -m unittest tests.test_fees_aligned_quote
```

Python 3 standard library only. The tool refuses any binary whose SHA-256 differs from the value above, never runs the binary, and calls no external program. Sections and FDE data come from `tools/elf_index.py` and `tools/fde_extents.py`. A full run takes about 200 s. It writes `evidence.json`, `path-map.tsv`, `writer-rules.tsv`, `pins.tsv`, `class-samples.tsv`, `reference-diff.tsv` and `mutations.tsv`.

## Evidence

Coordinates are virtual addresses in the ELF above. Every generated number comes from bytes. `S` is the state the spot code takes, `meta` is `S + 0x10`, and the tracker is the fee context of `fees-trade-fee-94`.

### The path

| Order | Stage | Address | Behaviour |
|---|---|---|---|
| 1 | vote | 0x1b2c4e0 family | `alignedQuoteTokenConfig` carries `cross_scale`, `add_rebate_scale`, `vlm_contribution_scale` (`fees-schedule-vote-94`) |
| 2 | schedule | 0x3744550 | patch bit at update +0x68 copies 3 words from update +0x70 to tracker +0x90, +0x98, +0xa0 (0x3744a28, frame +0x130 of the 0xc0-byte copy that starts at frame +0xa0) |
| 3 | enable | 0x274db00 + 2 copies | below |
| 4 | spot class | 0x372f020 and 3 sites | below |
| 5 | fee body | 0x3742460 | class changes the rate, the aligned byte picks a multiplier |
| 6 | perp | 0x37130b0, 0x37153f0 | the same 3 words, chosen by clearinghouse +0x58 |

### Boundaries

| Address | End | Role | Decoded / stepped |
|---|---|---|---|
| 0x274db00 | 0x274e1b2 | writer | 375 / 366 |
| 0x27e61a0 | 0x27e6422 | collect | 166 / 101 |
| 0x257d2f0 | 0x257d3d3 | filter | 49 / 48 |
| 0x372f020 | 0x372f23e | wrapper | 135 / 132 |
| 0x3726360 | 0x3726746 | mint | 226 / 202 |
| 0x3726980 | 0x3726ecf | burn | 307 / 261 |
| 0x372e0a0 | 0x372e2f5 | stats site | 136 / 136 |
| 0x372bec0 | 0x372c119 | loop site | 119 / 113 |
| 0x4d6e380 | 0x4d6ea32 | writer second | 375 / 366 |
| 0x4d6ea40 | 0x4d6f0f2 | writer third | 375 / 366 |
| 0x3742460 | 0x374301c | fee body, real, not mutated | 662 / 322 |

The stats and loop rows are ranges that end after the call to the fee body. The second and third writers run every writer vector and are not mutated. The second differs from the first only in callee and literal addresses. The third also reads the dex list at +0x1040, +0x1048 instead of +0x5c0, +0x5c8.

### Writer 0x274db00

Arguments: rdi result, rsi state, rdx token, cl enable, r8b force. Nine direct callers (`writer_callers` in `evidence.json`, read by byte shapes): the deployer arms in 0x23e7d10, 0x4ad78b0, 0x4ad81e0 pass force 0 and a constant enable, one site for each value. The validator vote arms 0x2387390, 0x49fe410, 0x49fee90 pass force 1 and enable from action +0x10.

`writer-rules.tsv` has the outcomes. In order:

1. A token past the list at state +0x218 panics. Token row is `[state+0x210] + token * 0xe8`.
2. Bit 0 of row +0xd2 clear gives tag 0xef, `Invalid quote token`. So a token with no deployer is refused even with force. The deployer is the 20 bytes at row +0xd3.
3. Enable: the status tree at state +0x2e0 must hold the token with byte 0. A missing key or any other byte gives 0xef, and force does not lift it.
4. Enable: 0x27e61a0 collects the keys of the aligned tree at state +0x2b0 whose token row has the same deployer. `active` is not read, so an inactive entry still counts. The token is removed from that set. Anything left gives 0xf0, `Duplicate aligned quote token deployer`.
5. Enable: gate 0x2751b30 gets the deployer and mode 4 when the remove found the token, else 2. Its first test skips the body in mode 4. A tag other than 0x186 is forwarded with its 0x60 bytes.
6. Enable, entry present: force 0 and value +0x2c zero gives tag 0xdf with text `cannot enable disabled aligned quote token`. Otherwise value +0x2c = 1, and no other value byte changes.
7. Enable, no entry: a value is inserted with zero words, state +0x60 (12 bytes) at value +0x20, and +0x2c = 1.
8. Disable, force 0: a status byte other than 1 gives 0xdf with `cannot disable aligned quote token before disabling quote token`. A missing status passes. Then value +0x2c = 0 if an entry exists. A missing entry is no error.
9. Every success walks the dex list (stride 0x2f0, unrolled by 4). Each row with row +0x50 == token gets row +0x58 = enable. Tag 0x186.

Serializer 0x37580a0 prints row +0x50 under `collateralToken` and row +0x58 under `collateralIsAlignedQuoteToken` (`pins.tsv`, `keys`). That is the byte 0x37130b0 loads at 0x371314c and 0x37153f0 tests at 0x371548d, which the older packets call `trial` or leave unnamed.

### Collector 0x27e61a0

It runs the iterator 0x257d2f0 over the aligned tree, sorts and builds a BTreeSet. The filter reads `[closure+0x180] + key * 0xe8` with closure state +0x90, so the same token table. Bit 0 of row +0xd2 and all 20 deployer bytes must match. A key past the list panics. Vectors include owners one byte apart at each of the 20 positions.

### Spot class 0x372f020

Slot 0x5774820, 6 sites in 3 order hosts. Input record: +0..+0x27 kept, +0x28 fee context, +0x30 spot index, +0x38 user, +0x4c cross, +0x4d leg, +0x4e flag; rcx notional. An index at or past `[S+0x180]` panics.

Row is `[S+0x178] + index * 0x20`: base at +0, quote at +8.

- Class: 1 when the base is a key of the tree at S+0x260. The value byte is not read here. The offset equals `quote_token_to_status` at metadata +0x250 in `RE-004-deployer-share-credit-94`. Otherwise the predicate at slot 0x5773198 on (meta, base) gives 2 when true, else 0. A class 1 token never reaches the predicate.
- Weight: f64 S+0x150, read in every class.
- Aligned byte: value +0x2c of the quote in the tree at S+0x230, else 0. The offset is metadata +0x220, `quote_token_to_aligned_quote_token_info` in the same packet. Only the quote is looked up.

The fee record then holds: +0..+0x27 input, +0x28 weight, +0x30 class, +0x31 leg, +0x38 notional, +0x40 user, +0x54 cross, +0x55 aligned byte, +0x56 flag.

0x372e0a0 (at 0x372e2f0) and the loop in 0x372b9d0 (at 0x372c114) inline the same selection. 0x372e0a0 forces leg 1, with cross from record +0x224. The loop passes its side byte as leg and sets cross when that byte equals record +0x224.

### Outcome hosts

Slots 0x5773880 (0x3726360, 6 sites) and 0x5773870 (0x3726980, 3 sites). Both force class 2 and leg 0, set cross to 1, take the weight from meta +0x140 (the same word as S+0x150), and use the flag argument as +0x56. The aligned byte comes from the outcome's quote token.

- 0x3726360: 0x385c150 gives unit, quote and limit, or an error byte. The outcome must be in the hash table at meta +0xd0 (stride 0x90), else 4. With bit 0 of r9 the size is `min(limit, amount / unit)`, else the limit. Size 0 gives word 3. `size * unit` overflowing gives byte 0xe. Output: fee record at +8, quote at +0, two rows `(token, row word, size)` from bucket end -0x68 and -0x40, one row `(token, quote, notional)`, final byte 1.
- 0x3726980: amount 0 gives word 3. Table miss gives 4. 0x3c18fb0 gives two legs; a left error wins, then a right error, and different quotes give byte 0xf. `amount * [bucket end -8]` overflowing gives 0xe. Output rows are the input 16-byte items each with the amount, one row `(token, quote, notional)`, final byte 3. The input Vec is freed on every path.

### What the fee body does with them

Run as real bytes behind 0x372f020, 0x3726360 and 0x3726980 (`class-samples.tsv`):

- Class 0 keeps the rate, class 1 divides by 5, class 2 gives `max(rate, 0) * weight`, so an outcome never pays a rebate.
- A positive value is multiplied by tracker +0x90 when `aligned byte & cross byte` is non-zero.
- A negative value is multiplied by tracker +0x98 when the aligned byte is non-zero and cross is 0.

`fees-trade-fee-94` modelled `al` as a truth value. The two tests differ for a byte of 2, a value `rustc` should not store in a bool; it is listed because the bytes define it. The volume side (`fees-spot-volume-94`) compares the byte with 1 and multiplies by tracker +0xa0. These three are the only readers of +0x90 and +0x98 in the byte-shape scan (`scale_readers`, 0x37130b0 and 0x3742460). The +0xa0 list also holds non-tracker loads with the same shape: 0x26e48c0 and its 2 copies (a row word), 0x3337780 (a serializer) and 0x3c02dc0 (the validator frame). The perp volume site 0x37154a5 uses a SIB form the scan leaves out, so it is a pin instead.

### Inferences

- Class 1 is the stable pair discount: the base token is itself a quote token. Only the membership test is observed.
- Class 2 is outcome tokens: the predicate 0x3728670 ids rule in `RE-004-wire-asset-codec-94` fits, and both outcome hosts force class 2.
- The 3 tracker words are the 3 names of `alignedQuoteTokenConfig`, by the order of the patch; the words are f64 by `movsd` and `mulsd`, where the reference types them u64.

## Implementation and comparison

not yet implemented. Comparison here is between decoded ELF bytes and a separate closed-form Python model, not a Rust build.

The evaluator interprets decoded instructions. Stack and heap start filled with a marker, and callee stubs spoil caller-saved registers. Trees are real B-tree layouts up to height 2 with 3 node shapes. The outcome table is a real hashbrown layout with mirrored control bytes and crowded probes. Writer stubs check their arguments, frames, entry handles and value bytes. Each stub call is compared in order. Every spot case compares the fee record bytes the host built, and the fee output of the real body. The filter, the iterator, the set build and the vec growth run as real bytes under the collector; the writer sees the collector as a stub with the same rule, so its vectors stay small.

## Results and limitations

- 5040 vectors, 0 mismatches: burn 86, collect 24, loop 312, mint 113, stats 313, wrapper 1564, writer 2628.
- 651 mutants: 582 killed, 26 survived, 43 unreached. Every row that is not killed has a reason in `mutations.tsv`. Mutants cover the first writer, the collector, the filter head, the wrapper, both outcome hosts and both site ranges.
- The 43 unreached rows are unwind pads, allocation failure arms, sort swap arms, the false tag and second group arms of the outcome table probe, and the aligned tree descent inside the outcome hosts (those trees stay one node high; the wrapper and site vectors reach height 2).
- `reference-diff.tsv`: 7 rows. `l1/spot_meta.rs` has the status test but no deployer rule, no gate, no re-enable refusal and no dex row write.

Unresolved:

- What happens to an entry's `active` at a later quote token disable. Only this writer was read.
- The body of gate 0x2751b30 in modes 2 and 4 is not modelled here.
- Sort path at 21 or more collected keys is not run (slot 0x5774f68).
- The meaning of record bytes +0x4d and +0x4e before the wrapper: leg and flag are names from `fees-trade-fee-94`.
- The reader of value +0 and +8..+0x1f, and why outcome hosts always set cross.
- Whether a byte other than 0 or 1 can reach value +0x2c. This writer stores only 0 and 1.

Next question: the fill host loop in 0x372b9d0, and who debits the spot fee after the record: 0x372c13e onward.
