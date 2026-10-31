# RE-004: what node #94 stores as the mark of a deployed outcome side

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, nothing copied)
- Claim status: observation for the bytes, the stored values, the ordered checks, the record layout, the texts and the Locations; inference for the words mark, primary, linked and quote; unresolved items are listed under limits
- Scope included and excluded: included are the deploy copies `0x274c9f0`, `0x4d6c760`, `0x4d6d570`, the validator `0x3728d20`, the side builder `0x3c014b0` and the value lookup `0x372b4b0`, all run as real bytes. Stubbed as edges: the resolver `0x37288b0`, token and liquidity deployment, the book batch, hashing, the balance B-tree lookup, the quote predicate at slot `0x5775e58`. `0x37288b0` is read only for its result shape.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12.3, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/outcome_deploy_mark.py --out research/work-items/RE-004-outcome-deploy-mark-94
python3 -m unittest tests.test_outcome_deploy_mark
```

The tool refuses any input whose SHA-256 differs. It uses `tools/elf_index.py` for sections and `tools/fde_extents.py` for FDE records. Output is byte-identical between runs.

## Evidence

Addresses are virtual addresses.

### Boundaries and reach

`evidence.json` gives the FDEs: `0x274c9f0..0x274daf5`, `0x4d6c760..0x4d6d563`, `0x4d6d570..0x4d6e373`, each with two direct callers. The last two have 620 instructions each. `copy-differences.tsv` lists the 5 rows where they differ, all state offsets: `+0x3388`/`+0x3390` against `+0x3e08`/`+0x3e10`, and `+0x8b8` against `+0x1338`. The first copy has another size because it clones four strings inline. It is not compared row by row. All three run the same named cases against the same specification.

Slots `0x5774c78` (`0x3728d20`), `0x5774c80` (`0x37288b0`) each have 3 callers, one per copy. Slot `0x5774788` (`0x372b4b0`) has 16 callers; 6 are the sites below.

### The stored value

`mark-sites.tsv` lists 6 sites, one for each side in each copy. Each is the same 8 rows, checked by exact shape, then a store:

```
movsd   slot,%xmm1         u64 v
unpcklps [0x203e80],%xmm1  words 0x43300000 0x45300000
subpd   [0x202ea0],%xmm1   2^52 2^84
movapd, unpckhpd, addsd    low lane + high lane
mulsd   [0x20a940],%xmm0   0.5
call    *0x576f6d8         0x565f410, round
```

These rows are the usual u64 to f64 conversion. Each lane holds one 32-bit half of a single `v`. The tail after round is `maxsd 0`, a test for infinity that yields 0, a clamp at 2^64, a truncating conversion that saturates at `u64::MAX`, then `cmp $1; adc $0`, which floors at 1. The result goes to `[state+T] + row*0xd8 + 0x78`, with `T` `0x3388` or `0x3e08`, after a bounds check against the word at `T+8`.

So for every u64 `v`, with `F` the correctly rounded f64 of `v`:

```
mark(v) = max(1, round(F * 0.5)) = max(1, (F + 1) >> 1)
```

`mark(0) = 1`, `mark(1) = 1`, `mark(2) = 1`, `mark(3) = 2`. An odd `v` below 2^53 rounds up, so `mark` is `ceil(v/2)` there. Saturation cannot happen, since `F * 0.5 <= 2^63`. `mark-examples.tsv` has real byte runs.

### Where v comes from

`0x372b4b0(out, meta, pair, meta)` with `meta = state+0x90`:

1. `pair` must be below `meta+0x170`, else a bounds panic (Location `spot_meta.rs:113:33`).
2. `token = [meta+0x168 + pair*0x20]`.
3. A hash table at `meta+0x70`, stride 0x10, maps token to outcome id. Missing gives error 3.
4. A hash table at `meta+0xd0`, stride 0x90, maps id to a record. Missing gives error 4.
5. If record `+0x28` equals the token, the value is record `+0x20`. Else if `+0x50` equals it, the value is `+0x48`. Else error 2.

`0x3728d20` builds that record. `validator-outcomes.tsv` shows every field of an accepted record:

| Offset | Field |
| --- | --- |
| +0x00 | outcome id, the counter at `meta+0x130` |
| +0x08, +0x10, +0x18 | first side string: capacity, pointer, length |
| +0x20 | first side value |
| +0x28 | first side token |
| +0x30, +0x38, +0x40 | second side string |
| +0x48 | second side value |
| +0x50 | second side token |
| +0x58..+0x70, +0x70..+0x88 | two strings from the second parameter |
| +0x88 | constant 1000 |

Both values come from `0x3c014b0`, which has only two callers, both in `0x3728d20`. Its only store to that output field is `movq $0x5f5e100,0x20(%r15)` at `0x3c01853`. So on this path `v` is always 100000000, and `mark(v)` is 50000000 for both sides.

### Ordered checks

`0x3c014b0` for one side (`side-outcomes.tsv`), all reached with real bytes:

1. token below the table length, else tag 0xea `Invalid token`
2. name length at most 100, else tag 0x143 with the length
3. token byte `+0x48` is 0 and `+0x49` is 5, else tag 0x17b `outcome token invalid decimals`
4. token in the table at `meta+0x40`, else tag 0x17b `token is not outcome token`
5. token not in the table at `meta+0x70`, else tag 0x17b `outcome token already deployed`
6. the address `0x32`, 11 zero bytes, big-endian token has a balance row with `total - reserved == u64::MAX`, else tag 0x17b `token is not valid`. With `total < reserved` the Wei recorder runs first (`impl_wei.rs:6:1`), and the check still fails.
7. predicate at slot `0x5775e58`, else tag 0xef `Invalid quote token`

`0x3728d20` (`validator-outcomes.tsv`): the quote must be in the tree at `spot+0x260` with flag byte 0, else tag 0xef. Both sides are always built. The first error wins, and a second error is dropped. Then come three text errors in tag 0x17b: `outcome tokens must be distinct`, `limit exceeded` when the id is above 19999, and `outcome unexpected` when the id is already in the table.

### The deploy copies

`deploy-outcomes.tsv` lists every end and the calls in order:

1. A validator error (niche `1 << 63` in the capacity word) is copied to the output and returned, with no dirty flag.
2. The resolver gives a failure flag or two token rows. The word primary and linked below are my labels for the two rows.
3. For each row: a row past `state+0x218` panics (`books.rs:19:47`). If the list at row `+0x58` is not empty, its first entry is the pair, a pair past `state+0x200` panics, and pair `+8` must equal the quote argument, else error 0xea. If the list is empty, a Decimal 0.5 is built, the pair is deployed with it, and text `1.0` goes twice to the liquidity call. The two sides build the same 0.5 differently: `0x4eac740` with mantissa 2^52 and scale -53 for the first, and slot `0x5774c20` from f64 for the second. This path has no quote test.
4. The lookup and the store above run for that pair. A pair past the mark table panics (`spot_meta.rs:565:25`).
5. After both sides, the book batch runs and the output is tag 0x186 with the id.

Any failure after step 1 ends the same way. The error is dropped through the error drop function, `state+0x1e8` becomes 1, the recorder gets Location `impl_outcome.rs:347:50`, a nonzero user goes into the set at `+0x8b8` or `+0x1338`, and the output is tag 0x140 `Invalid input`. A first side stored before the second side fails stays stored.

### Comparison with the reference

- `l1/exchange/impl_outcome.rs` `rounded_mid_mark` adds two u64 fields `low` and `high` of an `OutcomeScalar`. The bytes load one u64. The two terms are the lanes of the conversion, and the record has no such pair. `mark-examples.tsv` shows the formula gives the right number only when fed the two 32-bit halves. Fed `low = high = 100000000`, it gives twice the value (test `test_two_word_form_needs_the_lanes`).
- `fail_deploy` returns the side's own code when it is not OK. The bytes always give 0x140. The code of the failed side is only dropped.
- The mismatch check names an asset and a market. The bytes test only pair `+8` against the quote argument.
- `ONE_DOT_ZERO`, 0x140, 0xea, and the store at `+0x78` agree.

## Implementation and comparison

Not yet implemented. A separately written specification in the tool (`spec_deploy`, `spec_side`, `spec_validate`, `spec_lookup`, `spec_mark`) predicts every run of the real bytes.

## Results and limitations

- Named cases on real bytes, all equal to the specification: 40 deploy cases on each of 3 copies, 39 side, 34 validator, 17 lookup.
- `v` in 3 copies: 858 values, 2574 whole-function runs, 5148 runs of the 8 conversion rows.
- Tail: `tail-pieces.tsv`, 14 pieces at each of 6 sites, 8280 decision runs, covering all 2^64 f64 bit patterns. Each piece has one decision record, and both ends and 8 interior points are held to the closed form.
- Mutants: 458, 442 killed, 16 survivors explained one by one in `mutations.tsv`.
- Constants: `evidence.json` pins 8 words and 7 texts by bytes.

Limits:

- The conversion rows are proved by vectors plus the exact row shape and constants, not by enumeration of 2^64 values. The tail is whole-domain.
- Round is run as real bytes, but `0x565f410` is an edge here, covered only through these vectors.
- `0x379c3c0`, which `0x37288b0` uses, has 4 other callers (`0x3660d70`, `0x368a270`, `0x36b4a00`, `0x36d2650`), and they were not read. If any of them fills the same table, for example from a snapshot, the value there need not be 100000000. The formula still holds for any `v`.
- `0x37288b0` and its helpers are stubbed, so how it picks the two rows is not claimed.
- The name mark for row `+0x78` comes from the reference. Row readers and the sibling writers at `0x4d61e9d`, `0x27470ed`, `0x4d6177d` were not read.
- Reachability of the panics and the meaning of the `u64::MAX` balance rule were not traced.
- The first copy's inline string clones run with empty strings only.

No progress gate is requested.

## Next question

What does the sibling writer at `0x4d61e9d` store at row `+0x78`, and which code reads it back? Which of the four other callers of `0x379c3c0` touch the outcome table?
