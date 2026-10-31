# fees: node #94 dailyUserVlm and feeSchedule view path

This packet settles which day-tree word is taker volume and which is maker volume: the JSON keys name word 1 `userCross` and word 0 `userAdd`, so a reconstruction can name both sides of the fee tier inputs, the four rate slots and the units of volume and cutoffs from bytes instead of inference.

- Component ID: fees
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for byte-derived rules below, inference where marked, unresolved items listed under Results and limitations
- Scope included and excluded: included are 7 whole functions: the daily list 0x25806a0, its row 0x28f0c10, the owner day sum 0x26f95d0, the exchange day sum 0x26f9900, the schedule copy 0x2a3bb60, its collect 0x2a10690 and the view caller 0x2586ae0, plus the field maps of 5 struct serializers. Excluded are the bodies of the map row lookups 0x371b3a0 and 0x36f57f0, the address hash, the date add, the view builder 0x27d7fe0 (`fees-user-view-94`), the 14-day tier sum (`fees-tier-select-94`), the writers of the day trees, the rollover family and the text form of the floats.

## Reproduce

Run from the repository root:

```
python3 tools/fees_daily_view.py --out research/work-items/fees-daily-view-94
cd research/work-items/fees-daily-view-94 && sha256sum -c MANIFEST.sha256
python3 -m unittest tests.test_fees_daily_view
```

Python 3 standard library only. The tool refuses any binary whose SHA-256 differs from the value above, never runs the binary, and calls no external program. Sections and FDE data come from `tools/elf_index.py` and `tools/fde_extents.py`. A full run takes about 26 s on 3 workers.

## Evidence

Coordinates are virtual addresses in the ELF above. Every generated number comes from bytes. Offsets use the exchange state that the view passes (outer +0x570). The tier packet reads the same fields 0xa80 lower.

### Boundaries

| Address | FDE end | Role | Decoded / executed |
|---|---|---|---|
| 0x25806a0 | 0x25807f8 | daily list | 93 / 79 |
| 0x28f0c10 | 0x28f101e | one day row | 243 / 241 |
| 0x26f95d0 | 0x26f98fa | owner day sum | 199 / 195 |
| 0x26f9900 | 0x26f9b64 | exchange day sum | 150 / 146 |
| 0x2a3bb60 | 0x2a3bed5 | fee schedule copy | 204 / 189 |
| 0x2a10690 | 0x2a10933 | chain collect | 184 / 164 |
| 0x2586ae0 | 0x2586c42 | view caller | 75 / 70 |

Callers, read by a byte scan of `e8` calls (`callers` in `evidence.json`): 0x25806a0 has one, 0x27d816b in the view builder. 0x28f0c10 is called twice from 0x25806a0. 0x26f95d0 and 0x26f9900 are called only from 0x28f0c10. Slot 0x5774ef0, which `fees-user-view-94` shows the view builder calling, holds 0x2a3bb60.

Instructions not executed are listed under `unexecuted` with a reason: unwind blocks, jumps after calls that do not return, and the `reserve` arm of 0x2a10690, which compares two values computed by the same steps.

### What each row of dailyUserVlm holds

Row size 32. The keys and offsets are read from the instructions of serializer 0x2a3cc50.

| Row | Key | Source |
|---|---|---|
| +0 | `userCross` | sum of day-tree word 1 over the owners, as f64, over 100 |
| +8 | `userAdd` | sum of day-tree word 0 over the owners, as f64, over 100 |
| +0x10 | `exchange` | word 0 of the total trees, as f64, over 100 |
| +0x18 | `date` | the date dword |

Word 0 is the first sum of `fees-tier-select-94` and word 1 the second. `fees-unit-conversion-94` shows the writer adds to word 1 when the record tag equals the side, so `tag == side` selects cross. That packet's unresolved "which sum is maker" closes here: word 0 is add volume.

### Daily list 0x25806a0

Arguments: rdi output Vec, rsi a closure of (date pointer, state, user pointer, range start dword, range end dword, exhausted byte). The view passes (0, 14) with the byte clear.

- Byte 1, or start above end: cap 0, pointer 8, length 0.
- Otherwise capacity is end - start + 1, in 32-byte rows. A failed allocation calls the slot 0x576dfb8 handler.
- A byte other than 0 or 1 keeps the capacity and adds no row. `rustc` should never store that value in a bool; it is listed because the bytes define it.
- Rows are built from end down to start, so with (0, 14) the first row is date - 14 and the last row is the date itself.

The current day is in this list, and it is outside the tier window `date - 1 .. date - 14`. The view has 15 rows where the tier sum has 14.

### Row 0x28f0c10

1. `k * 86400` is tested as `TimeDelta::days`: k up to 2^31 passes, above panics. Slot 0x576e8b0 adds -k to the date. A result of 0 panics. Both panics use the same text, ``NaiveDate - TimeDelta` overflowed``, at the Location in `date_location`.
2. Owners are the user, then the 20-byte address at +0x18 of each 0x40-byte row of the Vec under the user in the map at state +0x4260 (stride 0x30, Vec pointer at entry +0x20, length at entry +0x28, count +0x4278, hasher +0x4280). A count of 0 skips the hash, and a linked owner is not filtered, so the user can count twice.
3. For each owner, 0x26f95d0 returns 2 words. Each add saturates and calls the recorder at slot 0x5773190 with Location `l1/src/qtys/impl_ntl.rs:664:1`.
4. 0x26f9900 returns the exchange word once per day.
5. The 3 words convert to f64 correctly rounded. The 2 sums go through a packed conversion, and the exchange word through a scalar one. Their constants differ: pair 0x202fd0 and single 0x20a960, both 100.0.

### Owner day 0x26f95d0

Arguments: rdi state, rsi and rcx 2 pointers to the owner, rdx and r8 2 pointers to the date. Keys are i32 and compare signed.

1. Slot 0x5773170 (state +0x80, owner) gives a row with a tree at +0x28 and height at +0x30. A null root or a missing day gives (0, 0).
2. A non-zero byte at state +0x110c doubles both words, saturating. A word with the top bit set records and becomes 2^64 - 1.
3. For each 0x2f0-byte row of the list at state +0x1040 (length +0x1048): if byte state +0x1372 == 2 the row counts only when word +0x30 is one of 0, 18, 44, 53, 55, 58, 59, 108, 109. Other mode values read no word.
4. A counted row asks 0x36f57f0 (row +0xf8, owner) for a row with the same tree fields, and its 2 words are added, saturating. Dex words are not doubled.

### Exchange day 0x26f9900

Arguments: rdi state, rsi and rdx 2 pointers to the date. Tree at state +0x3d8, height +0x3e0. Only value word 0 is read. The same byte doubles it, and the same filter chooses list rows, whose tree is at row +0x258, height +0x260. Word 1 of these trees is read nowhere in this path.

### feeSchedule copy 0x2a3bb60 and 0x2a10690

Argument: rsi is the tracker. These offsets match the tier packet with the tracker 0x5d0 into its state: `+0x618` is tracker +0x48 and so on. Keys come from serializers 0x2a3c790, 0x2a3c030, 0x2a3bee0 and 0x2a3cde0.

| Output | Key | Source |
|---|---|---|
| +0x48, +0x50, +0x58, +0x60 | `cross`, `add`, `spotCross`, `spotAdd` | tracker, same offsets |
| +0x68 | `referralDiscount` | tracker, same offset |
| +0, +8, +0x10 | `tiers` vip Vec | 0x28-byte rows, built below |
| +0x18, +0x20, +0x28 | `tiers` mm Vec | 0x10-byte rows copied unchanged |
| +0x30, +0x38, +0x40 | `stakingDiscountTiers` | ladder rows with one (0, 0) row in front |

A vip source row has 0x30 bytes, and the output row 0x28:

- output +0 `ntlCutoff` is the source u64 at +0x20, converted, over 1e6.
- output +8..+0x27 `cross`, `add`, `spotCross`, `spotAdd` are source +0..+0x1f, raw bits.
- source +0x28, the word `.rodata` calls `staking_keep_frac_for_referrer` beside `VipFees`, is dropped. The strict arena proves it is not read.

The mm row keys are `makerFractionCutoff` and `add`, and the ladder row keys are `bpsOfMaxSupply` and `discount`.

0x2a10690 is a generic collect of a chain: an optional front row, then a slice. Tag 1 yields the front row, 0 does not, and 2 has no front. Capacity above 2^60 - 1 rows, or above `0x7ffffffffffffff8` bytes, calls the failure handler with align 0. An allocation failure calls it with align 8. The copy loop takes a scalar path under 12 rows and when the ranges overlap.

### Units

Inference from the 3 divisors above, each of which is an observation. The tier step tests `first + second >= cutoff / 10000` in integers. The views show `word / 100` and `cutoff / 1e6`. So `word / 100 >= cutoff / 1e6`, up to the floor of the integer division: the tier test compares the same two numbers the view prints. A word is a hundredth of a printed unit and a cutoff a millionth.

### View caller 0x2586ae0

It calls the builder with state outer + 0x2c8, the outer state, the flag byte outer +0x4b90, and moves 0x120 bytes twice. The 2 Durations at result +0x120 and +0x128 are added. A sum above 3.0 (from 0x20aab8; a not-a-number sum does not qualify) only forces cells: Once at log cell +0x50 when that word is non-zero, then Once at 0x577ab98 when byte +0x48 is in bits 13, 14, 18, 19, 20, 21, 31 and that word is non-zero. Nothing else is written, and no log call sits on the branch. Either way the 2 Durations are not part of the result.

## Implementation and comparison

not yet implemented. Comparison here is between decoded ELF bytes and a separate closed-form Python model, not a Rust build.

The evaluator interprets the decoded instructions with strict arenas: a read of an unset byte faults, so a shifted field read fails. Allocation, the hash 0x399c7a0, the row lookup slot, 0x36f57f0, the date add, the recorder, the panics, the view builder and Once are stubs that check their arguments and spoil caller-saved registers. The maps are hashbrown layouts with mirrored control bytes and probe walls. Day trees are real node layouts up to height 3. The date stub steps a dword by 16 per day, which is not real calendar stepping; real date adds belong to `fees-start-trial-94`.

## Results and limitations

- 916 vectors, 0 mismatches. Outcomes and groups are in `evidence.json`.
- No mutation result. The survey in the tool (`generate(with_survey=True)`) did not finish in the time available, so `mutations.tsv` has only its header. The vectors are tested only by the negative controls in the unit tests.
- Daily vectors outside the range, day and tree groups use range (0, 1) instead of (0, 14).
- Serializer fields are read from instructions, and tests pin all 5 maps.
- `reference-diff.tsv`: 4 rows. `references/can1357-hl` names the same keys with String values, and names the day words `first_side` and `matching_side` with no link to maker or cross.

Unresolved:

- Whether `tag == side` in the writer means taker. The keys say cross; the record tag itself was not traced to the order.
- The pool word of the MM step. A 14-day exchange sum is the obvious reading, but the closure was not read, and the rollover family is covered by open #140.
- Whether the total trees are the ones `fees-unit-conversion-94` adds to for non-zero sides, which would make `exchange` a one-sided count.
- What the log cell at slot 0x576e928 is, and why the slow branch stops after forcing cells.
- The meaning of the map at state +0x4260, of mode byte +0x1372 and of the allow list.
- Sequences of calls are not evaluated. Partial survey logs showed unreviewed survivors, for example 0x26f96a8 and 0x26f98b5, so vector gaps may exist.

Next question: does the writer of the total trees add both sides of a fill, so that `exchange` and the MM bound count a trade once or twice?
