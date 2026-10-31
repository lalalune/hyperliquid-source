# fees: node #94 fee tier selection, 14 prior days to a vip row and an mm row

- Component ID: fees
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for byte-derived rules below, inference where marked, unresolved items listed under Results and limitations
- Scope included and excluded: included are the head of the 3 fee row builders, from entry to the stake stage, and the whole day sum 0x3425a20. Excluded are the stake stage after the head, the row vector the builders fill, the writers of the day trees, the caller closure that supplies the pool word, and every reader of the output rows.

## Reproduce

Run from the repository root:

```
python3 tools/fees_tier_select.py --out research/work-items/fees-tier-select-94
cd research/work-items/fees-tier-select-94 && sha256sum -c MANIFEST.sha256
python3 -m unittest tests.test_fees_tier_select
```

Python 3 standard library only. The tool refuses any binary whose SHA-256 differs from the value above, never runs the binary, and calls no external program. Sections and FDE data come from `tools/elf_index.py` and `tools/fde_extents.py`. A full run takes about 260 s on 3 workers.

## Evidence

Coordinates are virtual addresses in the ELF above. Every generated number comes from bytes. Field names come from .rodata where a row says so and are mine otherwise.

### Boundaries

| Address | FDE end | Role | Decoded / executed |
|---|---|---|---|
| 0x26fbab0 | 0x26fd364 | row builder, range only, called at 0x251cc9c | 621 / 600 |
| 0x4ce19c0 | 0x4ce3354 | row builder, range only, called at 0x476bb71 | 622 / 601 |
| 0x4ce3360 | 0x4ce4cf4 | row builder, range only, +0xa80 state offsets, called at 0x47679c1 | 622 / 601 |
| 0x3425a20 | 0x3425cb0 | sum of a day tree over the days before a date | 159 / 155 |

Pieces are in `evidence.json` under `functions`. A builder range stops at 0x26fc542, 0x4ce2452 or 0x4ce3df2, the first instruction after the selected rates are stored. That stop is decoded, not executed. The next packet range, `fees-staking-link-94`, starts at the same address. Builder ranges have 3 pieces: entry to stop, the early return, and the block from jump table entry 0 to the FDE end. Instructions not executed are listed under `unexecuted` with a reason.

The jump table is entered once with index 0 and walks entries 0, 1, 2, 3. Tables and entries are in `evidence.json` under `jump_tables`. It is a loop over 4 array slots unrolled by the compiler, not a data-dependent switch.

### Order of the head

Argument registers: rdi result vector, rsi exchange state, rdx user address, r8 pool word, r9 and ecx kept for later stages, first stack word kept for later stages.

1. If the map at state +0x3810 (stride 0x28, hasher +0x3830, count +0x3828) has the user as key, the function returns an empty vector (cap 0, pointer 8, length 0). A count of 0 skips the hash.
2. Slot 0x57748f8 holds 0x3743df0, the rate row helper of the trade fee path. It is called with state +0x5d0 and the user, and its result is not read in the range.
3. The date dword is state +0x60.
4. The owner list is the user, then the 20-byte address at +0x18 of each 0x40-byte row of the vector stored under the user in the map at state +0x37e0 (stride 0x30, vector at entry +0x18). A linked owner is not filtered: the user can appear twice.
5. For each owner, `first` and `second` are summed as below and added to the totals. Every add saturates at 2^64 - 1 and calls the overflow recorder at slot 0x5773190 with Location `l1/src/qtys/impl_ntl.rs:664:1`.
6. VIP step, then MM step, then the rates are stored and the stake stage starts.

### Sums of one owner

- Slot 0x5773170 holds 0x371b3a0, which takes state +0x80 and the owner and returns a row. Its tree is at row +0x28. `0x3425a20(tree, date, 14)` returns the first sum in rax and the second in rdx.
- Byte state +0x68c non-zero doubles both, saturating.
- For each 0x2f0-byte row of the list at state +0x5c0, if byte +0x8f2 == 2 the row counts only when word +0x30 is one of 0, 18, 44, 53, 55, 58, 59, 108, 109. The test is the mask 0xca0100000040001 for words up to 59, then word - 108 < 2. Other mode values read no word.
- A counted row looks the owner up in its map at +0xf8 (stride 0x78, hasher +0x118, count +0x110). The tree is at entry +0x40. A missing owner, or a count of 0, uses the tree at +0x28 of the lazy default row 0x57862a0.
- The lazy cell is tested on every counted row, hit or miss: Once word 0x5786300 non-zero calls slot 0x576e8b8 with the vtable 0x56f2288.
- Dex sums are not doubled. The double applies only to the sum from state +0x80.

### Day sum 0x3425a20

Arguments: tree (root, height), date dword, count. For k from 1 to count, inclusive:

- k is range-tested as `TimeDelta::days`: k up to 2^31 passes, 2^31 + 1 and above panics. The test has 2 copies, one per loop.
- Slot 0x576e8b0 adds -k to the date. A result of 0 panics with the Location at 0x566aa98, text ``NaiveDate - TimeDelta` overflowed`.
- Keys are i32 at node +0xb8, compared signed, count at node +0xe6, children at node +0xe8, values 16 bytes at node +0. Key equal to the date adds both words, saturating and recording, value word 0 to the first sum and word 1 to the second.

So the window is date - 1 to date - 14. The current day is left out. A null root still runs every date add, so the date panic does not depend on the tree.

### VIP step

The list is at state +0x5d8, rows of 0x30 bytes, read from last to first. Row layout: 4 f64 rates at +0, +8, +0x10, +0x18, a u64 cutoff at +0x20, an f64 at +0x28. `.rodata` holds `ntl_cutoff`, `rates`, `staking_keep_frac_for_referrer`, `struct VipFees with 3 elements`, which fits the 3 fields (`names` in `evidence.json`).

`both` = first + second, saturating. Its own recorder Location is `l1/src/scaled_vlm.rs:15:21`, and it is called once per row visited when the add overflowed. The first row from the end with `both >= cutoff / 10000` (integer division by multiply and shift) is taken; equal counts as reached.

A taken row sets each of the 4 base rates at state +0x618, +0x620, +0x628, +0x630 to `min(row rate, base rate)` with Rust `f64::min` behaviour: a not-a-number side gives the other side. Row +0x28 is stored in stack slot +0x18, which stays live past the stop. No row taken gives 1.0 in that slot and leaves the rates.

### MM step

The list is at state +0x5f0, rows of 0x10 bytes, last to first: f64 at +0, f64 at +8. `.rodata` holds `maker_fraction_cutoff`, `add`, `struct MmFees with 2 elements`.

The pool word becomes f64 through the unsigned conversion, then `bound = row[0] * pool`. A product that is not finite gives bound 0. Below 0 gives 0, 2^64 or more gives 2^64 - 1, the rest truncates. Clamping before the convert is dead for the outcome: the 2 `ja` branches at 0x26fc4d0 and 0x26fc4d6 are equivalent mutants.

The first row from the end with `first >= bound` is taken. It lowers rate 1 and rate 3 only, by the same `min`, on top of the VIP result. Rate 0 and rate 2 never see an MM row, and a not-a-number row[0] gives bound 0 and so takes the last row.

### Names read from .rodata

`struct FeeTiers with 2 elements` follows `vip`, `mm`. `stake_discount_tiers`, `weigh_spot_volume_double`, `aligned_quote_token_config` come just before `struct FeeSchedule with 9 elements`. This range does not prove which name owns which offset.

## Implementation and comparison

not yet implemented. Comparison here is between decoded ELF bytes and a separate closed-form Python model, not a Rust build.

The evaluator interprets the decoded instructions with strict arenas: a read of an unset byte faults, so a shifted field read fails. The address hash 0x399c7a0, the row lookup slot 0x5773170, the tracker slot 0x57748f8, the date add, the panic, the Once call and the overflow recorder are stubs that check their arguments and spoil caller-saved registers. Hash tables are real hashbrown layouts with mirrored control bytes, tombstones, decoys differing in one key byte and probe walls of up to 3 groups. Day trees are real node layouts up to height 4.

The default row itself is not built: the Once stub fills a chosen tree. The date stub is a plain add on the dword.

## Results and limitations

- 2193 vectors over 3 copies and the direct day sum, 0 mismatches. Outcomes and groups are in `evidence.json`.
- 349 mutants on 0x26fbab0 and 0x3425a20: 330 killed, 19 equivalent, each with a reason in `mutations.tsv`. Copies 0x4ce19c0 and 0x4ce3360 run every vector but are not mutated.
- `reference-diff.tsv`: 5 rows. `references/can1357-hl` has no tier selection and no MM list.

Unresolved:

- Which sum is maker and which is taker. `first` alone meets `maker_fraction_cutoff`, so `first` is maker volume by inference.
- What the pool word is. By the same inference it is a total volume, but the caller closure was not read.
- The unit of `ntl_cutoff`. The tool shows the division by 10000, nothing more.
- What the map at state +0x3810 means, and what the 0x37e0 owner vectors are.
- The rate order. Only slots 1 and 3 take an MM `add`, which fits cross, add, spot cross, spot add in the reference `FeeTier`; that is an inference.
- Whether byte +0x68c is `weigh_spot_volume_double`, and so whether state +0x80 is the spot side. That is an inference from the name and the double.
- What each word +0x30 value in the allow list stands for, and what byte +0x8f2 == 2 means.
- Which fill code reads row +0x28 as `staking_keep_frac_for_referrer`.
- Sequences of calls are not evaluated. The equivalence of the survivors is an argument, not a proof.

Next question: which writer fills the two value words of a day tree entry, and does it confirm that word 0 is maker volume?
