# RE-007: setMarginTableIds path: gate `0x273c140`, apply loop `0x273bf80`, per-user rewrite `0x3704680`

This packet shows what a margin table id change does to open positions, so a reconstruction can write that step: the asset row always takes the new id, every holder's leverage is capped by the new table's first tier, and a position moves to the new table only when that table is strictly more permissive than the one it already uses.

- Component ID: RE-007 (risk, oracles, liquidation), margin table reassignment
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for bytes, layout, order and results; inference for action names and field names; unresolved items are listed under Results and limitations
- Scope included and excluded: included are the 3 gate copies, the 2 apply loop copies, the rewrite `0x3704680`, the table compare `0x3333920`, the memo helpers `0x33980d0` and `0x33bd620`, the table getter `0x3759880` and the position entry `0x33bd420`. Excluded are all callees stubbed at the edge (listed below) and the inline gate in the vote dispatcher before `0x235b14a`.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned binary in place:

```
python3 tools/artifacts.py verify
python3 tools/margin_table_ids.py --out research/work-items/RE-007-margin-table-ids-94
python3 -m unittest tests.test_margin_table_ids
sha256sum -c MANIFEST.sha256   # inside the folder
```

The tool takes about 140 s on an idle machine and checks the input SHA-256 first. It reads ELF bytes in Python through `tools/elf_index.py` and `tools/fde_extents.py`, with no objdump or readelf output, and it never runs the binary. Selected function bytes are interpreted by a Python evaluator. All numbers below come from `evidence.json` and `mutations.tsv`.

## Evidence

Coordinates are virtual addresses.

### Boundaries and callers

| Function | Role | FDE start | Bytes | Reached by |
|---|---|---|---|---|
| `0x273c140`, `0x4d4c5a0`, `0x4d4ca90` | gate, 3 copies | exact | 1264 each | direct calls at `0x273fe64`, `0x4d51fa6`, `0x4d579c6` |
| `0x273bf80`, `0x4d4c3e0` | apply loop, 2 copies | exact | 440, 438 | `0x235b14a`, `0x273c429`; `0x4cafa40`, `0x4cb83d0`, `0x4d4c897`, `0x4d4cd87` |
| `0x3704680` | per-user rewrite | exact | 3105 | data slot `0x5774b88`, indirect calls at `0x273c030`, `0x4d4c48e` |
| `0x3333920` | table compare | exact | 2294 | `0x3704984`, `0x33bd6a4` |

The rewrite has no direct E8 caller. An E8 scan alone reports none. Gate copy 3 reads the dex list at +0x1038, and copies 1 and 2 read it at +0x5b8 (`dex_list_reads` in the evidence). Loop copy 2 takes the row pointer and count as arguments, where copy 1 takes the owner struct.

### Gate order

Input is a map from coin string to `u32` id, walked in key order. For each entry:

1. A coin longer than 100 bytes gives tag `0x143` (100 passes).
2. Resolver slots `0x5773ec8` and `0x5773318` give the clearinghouse and asset, and their error is copied out as is.
3. An id below 50 is accepted without a lookup. An id of 50 or more must be in the map at clearinghouse +0x38, else tag `0x154`.
4. The pair `(asset, id)` goes into a vector.

Nothing is applied until every entry passes. Then the apply loop runs and the gate returns `0x186`.

The word at out+4 of tag `0x154` is not the failing id. It comes from stack slot +0xc, which is written only after an entry is accepted:

| Input | Tag | Word at out+4 |
|---|---|---|
| missing id first, nothing accepted | `0x154` | slot never written (`0xa5a5a5a5` is the evaluator stack fill) |
| 51 accepted, then missing 99 | `0x154` | `0x33` (51) |
| 7 and 51 accepted, then missing 99 | `0x154` | `0x33` (51) |

### Apply loop

`dex = asset / 10000`, and a dex at or above the list length panics through the bounds slot `0x576e048`. The clearinghouse is at list base + `0x2f0 * dex`. Any result other than `0x186` goes to a recorder, but the rewrite only ever returns `0x186`, so that arm is dead.

### Rewrite `0x3704680`

1. `asset / 10000` must equal clearinghouse +0x30 and `asset % 10000` must be below the row count, else panic at `l1/src/perp_meta.rs:194:38`.
2. The new id is stored at row +0x18 before either table is resolved. A missing custom id then panics at `l1/src/perp_meta.rs:279:86` with the row already written.
3. Table `r = compare(new, old)` is stored in a per-call memo keyed by table id.
4. `first` is the leverage byte of the new table's first tier, or 3 when that tier list is empty.
5. Users are walked in sorted address order. For each user that holds the asset:
   - the address joins the set at +0x188
   - `position.leverage = min(position.leverage, first)`
   - the position's own table is compared with the new one through the memo
   - only compare result 1 sets `position.table = new`
   - `0x36f7350` gets the same size twice, so its totals and count do not change
   - `0x370e6a0` runs only if the leverage changed

Compare result, from both tier lists at each lower bound:

| Result | Meaning |
|---|---|
| 0 | new is never above the other table |
| 1 | new is above somewhere and never below |
| 2 | above and below |

Worked rows from the real bytes:

| Change | Leverage | Position table after |
|---|---|---|
| 50 to 51, lower everywhere | 33 to 20 | stays 50 |
| 51 to 50, higher everywhere | 33 stays | moves to 50 |
| 50 to 53, tiers cross | 33 to 30 | stays 50 |
| 50 to 55, equal tiers | 33 stays | stays 50 |
| 10 to 50, built-in to custom | 7 stays | moves to 50 |
| 50 to 5, custom to built-in | 33 to 5 | stays 50 |

So after a stricter change the asset row and the position hold different ids, and the position stays on the old table.

### Layout read from the same code

The `fields` list in `evidence.json` gives every offset used. Main ones: asset row stride 0x30 with table id at +0x18, position stride 0x40 with leverage +0x04, size +0x10, table +0x38, and tier stride 0x20 with leverage at +0x18.

### Stubbed edges

Built-in table builder `0x3398f50`, tier lookup slot target `0x33331a0`, user walk `0x3bb2290` and `0x33b1e80`, user row `0x3596940`, set updates `0x339b590` and `0x33acfe0`, `0x36f7350`, `0x370e6a0`, memo leaf insert `0x2f85640`, key walk `0x2869350` and `0x494a910`, coin resolvers, vector growth, allocator and frees. Argument values of the state-changing stubs are compared with the specification.

### Reference

`evidence.json` lists the claims. The reference names `SetMarginTableIds` (`l1/action/vote_global.rs:75`) but has no apply code, and `l1/perp_meta.rs:298` treats a table change as one field write. `relation_to` in `l1/clearinghouse/margin_table.rs:198` agrees with `0x3333920`.

## Implementation and comparison

Rust implementation: not yet implemented. Comparison here is between the interpreted real bytes and a separately written Python specification in the same tool, which predicts panics, output tags, stub arguments, asset rows and all 16 words of each position. That specification was written from reading the code, so it is a cross-check and not independent proof.

## Results and limitations

| Metric | Value |
|---|---|
| Cases | 253 |
| Mismatches | 0 |
| Instructions stepped | 173,624 |
| Stepped / total: gate, copy 1 | 207 / 273 |
| Stepped / total: gate, copy 2 | 209 / 275 |
| Stepped / total: gate, copy 3 | 209 / 275 |
| Stepped / total: apply loop, copy 1 | 66 / 97 |
| Stepped / total: apply loop, copy 2 | 65 / 97 |
| Stepped / total: per-user rewrite | 495 / 617 |
| Stepped / total: table compare | 200 / 520 |
| Stepped / total: memo first insert | 35 / 90 |
| Stepped / total: memo miss closure | 96 / 134 |
| Stepped / total: table getter | 63 / 73 |
| Stepped / total: position entry | 17 / 104 |
| Mutants killed / survived / unreached | 471 / 152 / 319 |

Outcomes per case kind are in `evidence.json`. The 152 survivors and 319 unreached mutants each have a reason in `mutations.tsv`, by function or address range rather than one by one. Most are setup read only by stubs, free paths, panic tails and tree depths the cases do not build. Gate table search limits have no stale-key case, which is a real test gap.

Unknown or not shown:

- Which gate copy serves which action variant, and what the third layout at +0x1038 is. The name `setMarginTableIds` is at `0x5a687c` and `0x5b50bd`, but no byte link from those strings to a gate was read.
- The inline gate in dispatcher `0x2355f40` before `0x235b14a` was not read, so its checks may differ from the gate above.
- Tier trees deeper than one leaf and memos above 11 keys are not modelled.
- `0x33331a0` is modelled as the last tier at or below the bound, and packet folder `RE-007-margin-path-94` covers it.
- The set at +0x188 and the index at +0x128 have no named meaning here.

No progress gate is requested.

Next question: which later step reads the set at +0x188, and does a position left on a stricter asset's old table keep that old table through `0x3717480` until it closes?
