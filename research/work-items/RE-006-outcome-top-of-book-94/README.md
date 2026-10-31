# RE-006: top of book of a two-sided record: own book, sibling complement, merge, mid, post-insert gate

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inference and unresolved items are marked.
- Scope included and excluded: included are seven whole functions: merged top `0x37270e0`, one leg `0x3c01010`, sibling record `0x37272c0`, spot class `0x3728670`, plain top pair `0x3c18b70`, mid `0x3730b40` and post-insert gate `0x372a0f0`, plus the hash `0x399c4a0` and `0x3a00700`, which run as helpers. Excluded are the writers of the three maps, the bodies of the mid and gate hosts, and the meaning of the byte codes. The only stubs are the panics and the recorder behind slot `0x5773190`, whose arguments are compared.

## Reproduce

From the repository root:

```
python3 tools/outcome_top_of_book.py --out research/work-items/RE-006-outcome-top-of-book-94
python3 -m unittest tests.test_outcome_top_of_book
```

The tool takes about 110 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `turn.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`). Field maps are in `fields`.

### Layout

One owner block `O` holds three SipHash-1-3 hash tables, a spot list and token rows. Spot words are `u64` keys.

| Offset of `O` | Content |
| --- | --- |
| `+0x40` | first map, stride `0x20`, key the spot word |
| `+0x70` | second map, stride `0x10`: spot word to id, entry `+8` |
| `+0xd0` | third map, stride `0x90`: id to entry |
| `+0x168`/`+0x170` | spot list, stride `0x20`, word at `+0` |
| `+0x180`/`+0x188` | token rows, stride `0xe8`, book list at `+0x58`/`+0x60` |

A third map entry holds the id and two records of `0x28` bytes at `+0x08` and `+0x30`. Record `+0x18` is a value and `+0x20` is a token. The hash `0x399c4a0` equals a separately written SipHash-1-3 on 4 key sets (`hash_check`).

### One leg, `0x3c01010`

Arguments: `rdi` result, `rsi` a block of (table, slab view, pointer to a flag and a wanted book, owner), `dl` the side, `rcx` the record.

1. Token past the rows: panic at `l1/src/spot_meta.rs:113`. Book list length other than 1: error byte 0.
2. The list's one book past the slab: bounds panic at `l1/src/books.rs:14`.
3. Bid is the first key of the tree at book `+0x80`, ask of the tree at `+0x98`, each as an absolute value. An absent root or a length of 0 gives 0.
4. Turn or not: with the flag byte nonzero, turn when the wanted book differs from this book. With the flag byte 0, turn when `dl == 1`.
5. Not turned: `(bid, ask)`.
6. Turned: `(value - ask, value - bid)`, with `value` from the sibling record of this book. A price of 0 stays 0 and needs no lookup. `value < price` gives error 8 and `value == price` gives error 9. `bid` is turned first and its error wins (`turn.tsv`).

### Sibling record, `0x37272c0`

The book index reads the spot list (past it: panic at `spot_meta.rs:565`). The word goes through the second map (miss or empty: error 3) and the third (error 4). The result is the first record whose token differs from the word, else error 1.

So the value subtracted is the other side's record, in both records' cases. When the two values differ, the one on the sibling is used (`test_flip_of_first_leg_uses_second_value`).

### Merge, `0x37270e0`

Id absent: error 4. Otherwise both legs always run, side 0 first, so a panic in the second beats an error in the first. Then the first error is returned. Bid is the higher nonzero bid and ask the lower nonzero ask. No test compares them: with values of `1e8`, books 0.60/0.65 and 0.30/0.34 merge on a side flag to bid `66000000` and ask `65000000`, which is crossed (`worked_example`).

### Mid, `0x3730b40`

Class from `0x3728670`: 1 for a word in the first map, 0 for a word in neither of the first two maps, 2 when the id has an entry, 1 when it has none.

| Class | Result |
| --- | --- |
| 0 | `(bid & ask) + ((bid ^ ask) >> 1)` of the spot's own book through `0x3c18b70`, 0 when a side is empty |
| 1 | 0. The top pair still runs and is dropped, so a bad book index still panics |
| 2 | Same mean of the merge, with the flag set and wanted book = the spot. Any error, or a zero side, gives 0 |

The three hosts load `1.03` (`0x20a770`) or `0.97` (`0x20ac58`) right after the call (`mid_sites`).

### Post-insert gate, `0x372a0f0`

Arguments: `rdi` owner, `rsi` order, `rdx` insert result, `rcx` slab view, `r8` table. The byte `0x27` means carry on.

1. Spot `order+0x28` past the list: panic. Word not in the second map: byte 3. So every spot with no id stops here with 3.
2. Result word other than `0x186`: merge with the flag clear. A rejected insert still runs it.
3. Word `0x186`: fills at result `+0x10`, count `+0x18`, stride `0x228`. Amounts at `+0x200` are summed with saturation, each carry calling the recorder with `l1/src/qtys/mod.rs:827`. The sum is dropped.
4. Order dword `+0` other than 1: byte 5. This comes before the merge, so it beats a missing entry.
5. Merge, with the flag set and wanted book `fills[0]+0x1f8` when there is a fill, else with the flag clear.
6. Merge ok: `0x27`. Error: its byte.

The result of the merge is not used, only whether it failed. All 3 hosts compare the byte with `0x27` (`gate_sites`). At `0x4d14e05` and `0x4d17695` the arm stores word `0x187` with the byte at `+2`, in place of the insert result. At `0x26d5b28` the byte stays in `ebx`, and that arm's store is not read here.

### Tree walk

`0x3c18b70` and the leg walk first edges from the root at `+0x1c8` for `height` levels, in single steps for `height & 7` and then in steps of 8. An empty leaf climbs by parent `+0x160` and index `+0x1c0` until the index is below the length `+0x1c2`. A walk past the root panics at `library/alloc/src/collections/btree/navigate.rs:534`. Node keys start at `+0x168`. Heights 0 to 17 run on both sides, through both functions.

### Results

| Measure | Value |
| --- | --- |
| Cases | 632 |
| Mismatches | 0 |
| Instructions stepped | 559,571 |
| Stepped / total: merged top | 128 / 128 |
| Stepped / total: one leg | 274 / 280 |
| Stepped / total: sibling record | 134 / 134 |
| Stepped / total: spot class | 151 / 151 |
| Stepped / total: plain top pair | 118 / 124 |
| Stepped / total: mid | 143 / 143 |
| Stepped / total: post-insert gate | 149 / 149 |
| Stepped / total: SipHash of one u64 | 86 / 86 |
| Stepped / total: hasher write | 56 / 141 |
| Mutants killed / survived / unreached | 462 / 14 / 0 |

Unstepped instructions of `0x3c01010` and `0x3c18b70` are panic tails and `ud2` padding. `hasher write` runs one input length.

### Reference comparison

`reference_claims` in `evidence.json` lists each row. `mid_px` in `l1/books.rs:613` has class 0's formula. The reference has no turn, no merge, no class and no gate.

## Inferences

Kept apart from the observations:

- The records are the two sides of an outcome question and the value is 1 in price units (`1e8`). So a leg turned is the price of the other side as a complement. The tests use `1e8` and `1e8 + 3` as chosen numbers. This packet does not read a writer.
- `order+0` is the tag of an optional limit price. `0x42fe970` reads the same record shape, with `+0x08` as the value when the tag is nonzero. So byte 5 would mean a fill with no limit price on a spot of this kind.
- `0x186` is a success word in this result. Other packets name it so.
- The hosts with 1.03 and 0.97 are slice limits of TWAP steps. Those factors match earlier work, but the hosts are not read here.

## Implementation and comparison

not yet implemented. The evaluator runs the real bytes against a separate Python specification. A mutant survives only with a stated reason in `mutations.tsv`.

## Results and limitations

- Tables, trees and rows are built by the harness from shapes read in the code. Live state was not read.
- Byte codes 0, 1, 3, 4, 5, 8, 9 are numbers here. `0x27` being a None niche means the type has at least 39 values, so it is not the 10-value text table at `0x59b088`. Their names are unresolved.
- Whether a resting price can reach `value`, so that errors 8 and 9 can occur on a live book, is not shown.
- What the first map holds, and why its spots have mid 0, is unresolved.
- The second arm of `0x26d5b28` is not read.
- Every surviving or unreached mutant has a stated reason in `mutations.tsv`.
- No Rust code, and no progress gate is requested.

Next question: who fills the first map at `O+0x40`, and which price gate decides whether a resting price can reach the record value?
