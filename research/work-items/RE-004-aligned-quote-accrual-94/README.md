# RE-004: aligned quote yield: stake-weighted median rate, daily_wei_owed accrual, delayed payout

This packet shows how node #94 turns validator rate votes into an aligned quote token's yield debt and then pays it. A stake-weighted median of fresh votes becomes one rate; each sample adds `trunc(amount * dt * rate / 31557600)` to a per-date map, `daily_wei_owed`; and on the first block of a new UTC date the entry dated 45 days back (2 days on chain byte 2) is sent to the token's address and removed only if the transfer succeeds. A reconstruction can now write this whole path with the right map type, gates and failure behaviour. The reference types `daily_wei_owed` as `Vec<Wei>` and holds none of this logic.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check. Nothing is copied from it.
- Claim status: observation for everything under Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences are marked and listed apart.
- Scope included: the bucket guard and vote split, the median chain, the sampling and payout block in all three host copies, and the two date map helpers in both copies. Scope excluded: the row builder, the transfer, the vote writer, the EVM read behind slot `0x57746a0`, the writers of `evm_minted_supply`, and the info response.

## Reproduce

From the repository root:

```
python3 tools/aligned_quote_accrual.py --out research/work-items/RE-004-aligned-quote-accrual-94
python3 -m unittest tests.test_aligned_quote_accrual
```

The tool takes about 2.5 minutes on a loaded machine. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no external program, so the binutils version cannot change the output. The binary is never executed: an evaluator reads its instruction bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `window-rows.tsv`, `copies.tsv`, `keys.tsv`, `pins.tsv`, `constants.tsv`, `texts.tsv`, `serde.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are ELF virtual addresses. Function ends come from FDEs. `function-rows.tsv` holds 11 whole functions, 1365 instructions and 5926 bytes. `window-rows.tsv` holds 2034 reached rows inside larger hosts: the sampling block of each copy, the closure of the guard, and the pick loop of the weighted median. Those hosts have rows in other packets for other questions, so their rows are given here and their FDE starts are not subjects.

### Names and offsets

`S` is the state pointer. `keys.tsv` holds each serializer row, its bytes and the key text it uses.

| Offset | Key | Meaning here |
| --- | --- | --- |
| `S+0x2b0` | `quote_token_to_aligned_quote_token_info` (spot meta `+0x220`) | map token to a 0x30 byte record |
| record `+0x00` | `evm_minted_supply` | u64 |
| record `+0x08` | `daily_wei_owed` | map root, height, length |
| record `+0x20` | `first_aligned_time` | not read here |
| record `+0x2c` | `active` | byte |
| `S+0x2f8` | `ta2` (spot meta `+0x268`) | map token to a 0x68 byte record, `daily` map at `+0` |
| `S+0x3abc` | `last_aqa_sample_time` | 12 byte time, `S+0x453c` in copy c |
| `S+0x3248` | `validator_l1_stream_tracker` | median record, `S+0x3cc8` in copy c |

The serializer of the last two uses a base of `S+0x1b20`, and of the two maps a base of `S+0x90`; `test_serializer_shift_joins_two_known_offsets` holds those sums to the offsets the sampling block reads. `copies.tsv` lists the block bounds and offsets for all three copies. Copy c moves the time, median, chain byte and token table offsets, and copies b and c keep the state pointer in `r12` with a stack copy at `[rsp]`.

`daily_wei_owed` is not a vector. Its node has i32 date keys at `+0x60`, u64 values at `+8`, the length at `+0x8e` and edges at `+0x90`, with leaf size 0x90 and inner size 0xf0, and the code walks it as a B-tree. The key is the packed date word of the block.

### Median rate

The closure runs from `0x3265810` with the key text `median_risk_free_rate`, and its three call sites are in the per-block step list. Record words: `+0` tag, `+8` f64 median, `+0x10` period in ms, `+0x18` last bucket, `+0x20` vote map.

1. `bucket = max(block ms, 0) / period`. If it is not above `+0x18`, nothing else runs. Otherwise it is stored.
2. `0x3265980` walks the vote map (20 byte validator key, then f64 rate and 12 byte time) in key order. With `ttl = f64(period) / 1000`, a row is fresh if `time + ttl` is strictly after the block time, compared as date, seconds, nanoseconds. Other rows are old.
3. Old rows are removed from the map (`0x2fd6ec0`). A date word of 0 ends this walk.
4. `0x32d5280` narrows fresh rows to 0x20 bytes in place, `0x3bb6c70` asks slot `0x5775c90` for the stake map, and `0x3bb1830` keeps a row only if its rate is finite and not negative (`-0.0` stays) and its validator is in the stake map.
5. Rows sort by the f64 total order of the rate, then stake. Fewer than 2 rows skip the sort, under 21 use `0x3387e80`, and others use slot `0x5775c98`.
6. `total` is the sum of stakes. If that wraps, or is 0, or no rows are left, there is no result. Otherwise `half = total >> 1`, and the rate of the first row whose running sum is above `half` is the result.
7. A result stores tag 1 and the f64. No result leaves both words as they were, so an old median outlives its votes.

### Sampling block

The block is `0x2763764..0x27644e6` in copy a. `now` is the 12 bytes at `S+0x60`, `last` is the stored time, and `prev` is the word at `S+0x6c`.

1. `S+0` is saved and held at 0 until the block ends.
2. If `last` has date word 0, `last = now`.
3. `dt` comes from slot `0x576e8c0(now, last)`.
4. If `dt` is below 1.0 or NaN, there is no accrual and `last` stays. The row list is built only if `prev < date`.
5. Otherwise the row list is built. With no rows, go to step 7. With rows, `rate` is the median, or 0.0 with tag 0.
   - `rate < 0` or NaN panics with `assertion failed: self >= 0.`
   - `x = dt * rate / 31557600`. A NaN product panics with `assertion failed: self.0 >= 0.`
   - If `0 <= x <= 1.01` fails, the loop is skipped.
   - For each row: `p = f64(amount) * x`; clamped to `[0, 2^64]`; `add = trunc(p)`, or `u64::MAX` above `2^64 - 2048`. `map[date]` is found or inserted at 0 and `add` is added. A wrap calls the recorder with Location `0x56dfd78` and stores `u64::MAX`.
6. The key is the block's date, whatever span `dt` covers, and a key is inserted even when `add` is 0.
7. `last = now`. This holds even when the fraction gate skipped the loop, so that span is lost.
8. If `prev < date` (signed), the payout runs.

Row list entries are 0x30 bytes: `+0` map pointer, `+8` token, `+0x10` amount, `+0x18` 20 byte address, `+0x2c` flag.

### Payout

`cutoff` is the date minus 45 days, or minus 2 when the chain byte is 2, through slot `0x576e8b0` (run as real bytes).

1. For each row, `map[cutoff]` is read. A hit adds (token, value, address, flag) to a list.
2. Rows with an older oldest key are collected in a second list, which is then freed unread. Keys older than `cutoff` are never paid and never removed by this block.
3. For each hit, in order: flag 2 ends the loop. `token >= S+0x218` logs tag `0xea`. `value >= 0x0ccccccccccccccc` logs tag `0x13f`. Otherwise the transfer `0x2729c30` runs with the address, the token and the value (`0x4d35340`, `0x4d336b0` in copies b, c).
4. A failed transfer logs the error, keeps the key and goes on.
5. On success the token is looked up in `S+0x2b0` (flag 0) or `S+0x2f8` (flag 1), and `cutoff` is removed from that record's map. A token not in the map is not an error.

A logged failure is not retried: a later date change looks up a later cutoff, so a key that failed stays until something else removes it.

`constants.tsv` holds every constant with its reader row. `texts.tsv` holds the panic texts.

### Row sources, read but not run

`0x3baedf0` builds the row list and is listed by another packet, so here a stub supplies the rows and checks all 21 iterator words. `pins.tsv` pins its rows. Read by eye:

- Flag 0 rows come from `S+0x2b0`, where `active == 1` and token record `+0xd2` is not 0. The amount is `evm_minted_supply >> 1`. The address is the 20 bytes at token record `+0xd3`.
- Flag 1 rows come from `S+0x2f8`, where token record `+0xbc == 1`. The amount is an EVM word read through slot `0x57746a0` and scaled by `0x3281770`. The address is byte `0x50`, zeros and the token id big endian.

### Reference comparison

`references/can1357-hl/l1/spot_meta.rs` has `daily_wei_owed: Vec<Wei>` and `spot_clearinghouse/types.rs` has the record, but the only write is an empty `Vec::new()` at `spot_meta.rs:446`, and no accrual, median or payout exists. `rg -i "risk_free|last_aqa|aqa"` finds only comments and action names. `impl_spot_deploy.rs` and `handlers/26_spot_deploy.rs` set `active` and the time.

`research/upstream-docs/node.README.md` line 421 says validators publish this rate once per day at 22:00 UTC through `validatorL1Stream`, which fits a vote map with an age limit.

## Inferences

These are readings of the observations above, not separate byte facts.

- `dt` is seconds and `31557600` is a Julian year, so `rate` is an annual fraction. The elapsed helper was read by eye: it subtracts two times and returns ms / 1000.0. Its stub in the tool returns an injected value.
- The tracker's first words are an `Option<f64>` and a bucket guard. The serde text gives `struct ValidatorL1StreamTracker with 1 element`, and the key `risk_free_rate` was not joined to each word.
- `evm_minted_supply >> 1` is half of the supply. Why half is not shown.
- Token record `+0xd3` is the linked EVM contract, from earlier packets' reading of `+0xbc` and `+0xd1`.
- Chain byte 2 looks like a test network, as in other packets.
- `ta2` records are `Aqav2TokenInfo`, from the text right after the key.

## Implementation and comparison

Rust implementation: not yet implemented. Comparison is between the real instructions, run by the evaluator in `tools/aligned_quote_accrual.py`, and a separately written rule list in the same tool (`spec_sample`, `spec_median`, `owed`).

The median cases start at `0x3265810` and stop at `0x3372ea1`, after the median is stored and before the timing metric. The sampling cases start at each copy's block and stop at its end. All listed helpers, tree inserts and removals, and the date helper run as real bytes on real B-tree nodes. Stubs check their arguments: the row builder, the elapsed helper, the transfer (including that `S+0` is 0 during it), the error log, the time add, the stake map, the library sort and the allocator. The tool compares the stored time, the median words, every date map (walked through parent links), the vote map, the transfer and log events, the panic text, and the whole 36 KB state image.

474 named cases and 1200 vectors match. Every named case's result is in `outcomes.tsv`. `dt` and `rate` are injected, so cases reach values a live chain may never hold.

Mutation test: every reached conditional row, immediate and field offset is edited in turn in the guard, split, median entry, join, small sort, collect, the copy a date map helpers, the copy a sampling block, the closure window and the pick loop. Copies b and c, `0x4956ae0`, `0x4942fc0` and `0x2fd6ec0` run all cases but are not mutated. To keep the tool short, each edit runs at most 12 evenly spaced cases of those reaching its row. 612 of 716 edits are caught. The other 104 are NOT classified: `mutations.tsv` labels them as such. Some may be equivalent, and some may be real gaps that a longer case list would catch, so read this as a floor on what the cases detect.

## Results and limitations

- 67 unit tests pass with no skips, including corrupt digest, key, field row, pin, constant, constant reader, text and parent link controls. `--out` run twice under another hash seed and time zone gives identical files.
- Unreached rows are listed per function in `evidence.json`: 196 rows, mostly unwind and panic rows, plus deep tree descent, since cases have at most 2 tree levels.
- The row builder, transfer and vote writer are not run. Their real behaviour is an edge of this packet. In particular the transfer's meaning for (address, token, value) is taken from the record words it receives, and what `S+0x2b0` entries' `evm_minted_supply` means rests on the serde key.
- The metric tail of the closure past `0x3372ea1` is not run. No state word is written there by eye, but the stop means the tool does not show that.
- `dt` from the real helper is not computed by the tool, so ms rounding of `dt` is an edge.
- A period of 0 divides by zero at the guard. No case runs it. The default value of the period was not read.
- `prev` at `S+0x6c` is taken as the earlier block's date, by name of use only. Its writer was not read.
