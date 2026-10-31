# RE-004: SetReserveAccumulator vote, the map at state +0x3a00 and the ReserveAccumulator codecs

This packet names the map that drives the `0xfe` user's spot buy cycle and shows how node #94 fills it. The map is `reserve_accumulators`, and `VoteGlobalAction::SetReserveAccumulator` rebuilds it: with wire keys `o`, `d`, `m` the vote empties the map, then writes one row per spot of the native token, with `order_ntl`, a decay window of at least 10 and `max_px`. A reconstruction can now write the action, its checks in order, the amount ladder over all of u64, the row layout and both state encodings. This answers the next question of `RE-006-system-buy-order-94`, and the reference has none of it beyond three field names with wrong types.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check. Nothing is copied from it.
- Claim status: observation for everything under Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences are marked and listed apart.
- Scope included: the vote arm in all three dispatchers, the clear and list clone helpers, the JSON vote reader, and the row field matcher, writers and readers. Scope excluded, and run as real code without a claim: the row constructor and the tree insert (rows in `RE-006-quote-token-enable-94`, #413, and #824), the decimal text parser (#286, #548), the DeterministicEma field writers (#600) and the buy cycle (#271). The binary vote readers are read by eye only.

## Reproduce

From the repository root:

```
python3 tools/reserve_accumulator_vote.py --out research/work-items/RE-004-reserve-accumulator-vote-94
python3 -m unittest tests.test_reserve_accumulator_vote
```

The tool takes under a minute on a loaded machine. `--mutants` adds the byte edit sweep and `mutations.tsv`; that takes over 10 minutes under load, so it is not part of the default run and its file is not in this packet. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no external program, so the binutils version cannot change the output. The binary is never executed: an evaluator reads its instruction bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `arm-rows.tsv`, `amount-ladder.tsv`, `wire.tsv`, `outcomes.tsv`, `pins.tsv`, `texts.tsv`, `serde.tsv`, `slots.tsv`, `constants.tsv`, `reference.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are ELF virtual addresses. Function ends come from FDEs. `function-rows.tsv` holds 21 whole functions, 5269 instructions and 23318 bytes. `arm-rows.tsv` holds the 570 rows reached past the jump of each dispatcher. The dispatchers themselves have rows in other packets, so only their arm rows are given here and the entry is found from the jump table.

### Wire

Tag word 61 (`0x3d`) of `VoteGlobalAction`, text `struct variant VoteGlobalAction::SetReserveAccumulator with 3 elements`. The JSON reader `0x1bc1470` (copy `0x306afa0`) matches one-byte keys by their byte at `0x1bc165a`. `wire.tsv` lists 91 fixed texts with their results, and both copies agree on all of them.

| Key | Array position | Record offset | Type | Row field it becomes |
| --- | --- | --- | --- | --- |
| `o` | 0 | `+0x38` | u64 | `order_ntl` |
| `d` | 1 | `+0x08` | String (cap, ptr, len) | `ema.decay_duration` |
| `m` | 2 | `+0x20` | String (cap, ptr, len) | `max_px` |

All three are required, a repeat is `duplicate field`, order is free, and an array of any other length is refused. Other keys are skipped, including the long names, so `{"order_ntl":3,...}` does not set `o`. `d` and `m` are texts and a JSON number there is refused.

### Vote arm

Arms `0x2356317`, `0x4caac4a` and `0x4cb35da`, one per dispatcher. Copy c shifts the map by `0xa80`, to `+0x4480`. `pins.tsv` holds the rows named below. In order:

1. `state +0x80 == 0`: tag `0xdf`, text `native token is not set`. The map is untouched.
2. Native index at `+0x88` not below the count at `+0x218`: bounds panic. The map is untouched.
3. Clone the native token's spot list (`0x254e740`, token row `+0x50`, stride `0xe8`).
4. Empty the map (`0x333a6d0`, slot `0x5773d78`): root and length 0, every node freed.
5. `o >= 0x0ccccccccccccccc`: tag `0x13f`, payload `o`.
6. For each spot in list order: `len(d) >= 101` tag `0x143`; parse `d` (slot `0x5773328`); `len(m) >= 101` tag `0x143`; parse `m`; build the row; if there is one, insert at key `spot`. A parser failure passes its status object through unchanged. Texts are parsed again for each spot.

So steps 5 and 6 can refuse after the map is already empty. With no spots the texts are never read. A repeated spot leaves one row. The rows of `outcomes.tsv` hold each case.

### Amount ladder

The row's word is a function of `o` alone. `amount-ladder.tsv` gives it for all of u64, and `ladder_rows` checks the bound on the reciprocal, so the divide step is exact for every input.

| `o` | Result | Stored `order_ntl` |
| --- | --- | --- |
| `0 ..= 0x68db8bac710cb` | row | `o * 100` |
| `0x68db8bac710cc ..= 184467440737095599` | row | `floor(o / 100) * 100`, not scaled |
| `184467440737095600 ..= 0x0ccccccccccccccb` | status ok, no row | none, so a vote here leaves the map empty |
| `0x0ccccccccccccccc ..` | tag `0x13f` | none |

The first cut is `floor(u64::MAX / 10000)`. The third row comes from the constructor's limit `0x28f5c28f5c28f5b` on the cut value, which #413 reads as out of reach on the quote enable path. The row is built with `window = max(10.0, d)` as `maxsd` with 10.0 as destination (constant at `0x20a8a8`), so a tie and a NaN keep `d`.

### Row

Value of the map, `0x48` bytes in a B-tree node of `0x380` bytes (`0x3e0` inner), keys at `+8`. Key text comes from the writers.

| Offset | Key | Set by the vote |
| --- | --- | --- |
| `+0x00` | `ema.num` | 0 |
| `+0x08` | `ema.denom` | 0 |
| `+0x10` | `ema.decay_duration` | `max(10, d)` |
| `+0x18` | `ema.n_samples` | 0 |
| `+0x20` | `ema.last_sample_time` (date word 0 is null, then seconds, nanos) | date word 0, the other 8 bytes and 4 of padding are left as the frame held them |
| `+0x30` | `spot` | key |
| `+0x38` | `order_ntl` | ladder |
| `+0x40` | `max_px` | `m` |

The struct texts are `struct ReserveAccumulator with 4 elements` and `struct DeterministicEma with 5 elements`. The binary also holds the path `base/src/ema_tracker.rs` with the assert text `decay <= 1.`, which were not tied to this type here.

### Codecs

- MessagePack writers `0x333a810`, `0x333a9e0` and copies: fields in the order `spot`, `order_ntl`, `max_px`, `ema`, then `num`, `denom`, `decay_duration`, `last_sample_time`, `n_samples`. A flag picks a 4 entry map with names or a 4 entry array. Integers take the smallest form, floats always `cb`, time a string or nil.
- JSON writers `0x333ad50`, `0x1e84360`, `0x42e2340`: the same order, pretty printed, a non-finite float is `null`, time like `2026-07-19T01:02:03.004`.
- Map writer `0x3c3da20`: `ReserveAccumulators` is a list of `[key, row]` pairs, so the key and `spot` are both on disk. `0x31cc460` and `0x1de4dc0` do the same in MessagePack (read by eye).
- JSON readers `0x1c2c470`, `0x3102f10`, pair reader `0x1b80ac0`, `0x3041730`: all four row fields required, repeats refused, other keys skipped, `spot` and the key are usize, floats accept integer literals, and `max_px: null` is refused. A row's `spot` is not compared with its key by these functions. `wire.tsv` holds 116 row and pair texts.

### Reference comparison

`reference.tsv` has each row. `l1/action/vote_global.rs` has `order_ntl: i128`, `decay_duration: u128`, `max_px: u64`; the record is one u64 and two strings. Its `SetReserveAccumulator` has no apply logic. `RE-006-system-buy-order-94` records that `l1/books.rs:984` calls the cycle `ImpactState::observe`.

## Inferences

- Those field names and the wire type fit: `o` is a notional per order, `d` the EMA decay in seconds, and `m` a price cap. The cycle reads the same three words as amount, window and cap, as #271 records. The word in the name `ReserveAccumulator` suggests a buy that accumulates a reserve; no byte says what for.
- With `o` in wire units of 1e-6, `o * 100` gives 1e-8 units, and `0x333a520` divides by 100 again for its caller. The unscaled band looks like a result of a shared helper, not a feature of the vote.
- A failed vote may be rolled back above this arm, which would make the early clear harmless. The caller's handling of a refusal is not read here.

## Implementation and comparison

Rust implementation: not yet implemented. The comparison is between real function bytes in a Python evaluator and a separately written Python rule list. Fixtures are real B-tree nodes with stale keys in unused slots. All code runs real, except allocator, copy, compare and set hooks, panic hooks, and the text parser on vote cases, which a stub answers while checking its argument and the gate order; 15 end to end cases run the real JSON reader, the real dispatcher and the real parser in one pass. The `Once` state at `0x577ab98` is taken as done, and rows after it do not read what it guards. Vote cases compare status, payload, each row, map words, the rest of the state image, parse order and every allocation left over. Reader cases compare fixed tables taken from a first real run and then read by eye; they are the expected serde_json texts. Writer cases compare every byte with a separate encoder.

The `--mutants` sweep flips every reached conditional row, immediate and non-stack displacement of 10 functions and the three arms, with up to 10 cases per row, then up to 90 for a row that survived those.

## Results and limitations

| Metric | Value |
| --- | --- |
| Named cases | 1058 |
| Random vote vectors | 800 |
| Mismatches | 0 |
| Mutant sweep | see below; not part of the default run |
| Unreached rows in subject functions | 863 |
| Unit tests | 61, no skips |

Mutation: one complete development sweep, before the capacity, junk byte and depth cases were added, gave 904 killed of 1103 edits with 10 cases per row. A later sweep with those cases and the second pass did not finish inside the run, so no final count is claimed. The 199 survivors of the first sweep were not classified one by one. Those read by hand were low byte edits of whitespace and compare immediates, the formatter state byte `+0x20`, the `0xf0` record copy length and sink capacity bounds, and that is a reading, not a generated result. Rows on the vote gates are held by named unit tests with edited bytes.

Limits:

- All states are built by the harness. No live vote or row was seen.
- `evidence.json` lists every unreached row by function.
- The MessagePack vote readers (`0x18a38c0`, `0x2cef5e0`, `0x40ce860`) and value array readers (`0x1f3ed20`, `0x1f4ccf0` and copies) are not run. The value array reader takes the three elements in the same order, and its first element goes through a newtype named `Unvalidated` (pin at `0x1f3ee05`).
- Maps have at most two levels.
- The parser is a real callee in 15 cases only. Which texts it accepts is not a claim here.

No progress gate is requested.

Next question: what does the caller of the dispatcher do with a refusal, so does a refused SetReserveAccumulator keep the emptied map, and who sent the `Unvalidated` wrapper around `o`?
