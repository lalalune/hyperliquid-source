# RE-006: one cancel from the wire list to the status: records, book map by client id, removal, closing row, status

This packet gives a reconstruction the body of a cancel on node #94: the two wire shapes, the 0x20 byte record, the per item order of route, book, map lookup, removal with reason 2, closing row, flush and status, the map from client id to oid at book `+0x48`, and the text of status `0xc5` with its wire asset. The reference declares `cancel_perp` and `cancel_spot` with no body, so these functions can now be written from tables, and it shows the spot path has a gate (`0xf9`) the reference does not have.

- Component ID: RE-006 (book state transitions), one cancel path from the action core to the per item status
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants are preparers `0x2518ad0`, `0x251a940`, `0x47f8410`, `0x47f7070`, workers `0x251a180`, `0x47f65d0`, `0x47f66e0`, closures `0x24bbcf0`, `0x4447770`, `0x4449010`, items `0x275a380`, `0x4d85940`, `0x4d85290`, spot arms `0x2726af0`, `0x4d2e640`, `0x4d2e810`, and map lookup `0x342a430`. Real bytes with no mutants: the six action cores (`0x2721120` and `0x2725010` are the subject of #607; the other four are their copies), and hash helpers `0x399c7a0`, `0x399c650`, `0x3a00700`. Stubbed at the edge: resolver `0x3c0cc70` (wire asset codec #72), removal `0x26de150`, `0x26de280`, `0x42f7420`, `0x42f7590`, `0x42f7290`, `0x42f7700` (cascade family, #108), flushes `0x24fb610`, `0x24fc8a0`, `0x4329870`, `0x432b440`, `0x432a100`, `0x432a990`, spot wire form `0x3c0cea0`, predicates `0x37e4fb0`, `0x37e4e50`, sampler `0x13c9e20`, clock `0x4ee3800`, elapsed `0x4ee3730`, vector growth, allocator, memcpy. Excluded: the bodies of those stubs, the order of removal inside a book, and the JSON writer of the results.

## Reproduce

From the repository root:

```
python3 tools/cancel_item_path.py --out research/work-items/RE-006-cancel-item-path-94
python3 -m unittest tests.test_cancel_item_path
```

The tool takes about 40 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### Path map

| Step | First | Second | Third |
| --- | --- | --- | --- |
| Core, oid | `0x2721120` | `0x4d25e40` | `0x4d25f80` |
| Core, client id | `0x2725010` | `0x4d2b140` | `0x4d2b280` |
| Preparer, oid | `0x2518ad0` | `0x47f8410` | `0x47f8410` |
| Preparer, client id | `0x251a940` | `0x47f7070` | `0x47f7070` |
| Worker | `0x251a180` | `0x47f65d0` | `0x47f66e0` |
| Closure | `0x24bbcf0` | `0x4447770` | `0x4449010` |
| Item | `0x275a380` | `0x4d85940` | `0x4d85290` |
| Spot arm | `0x2726af0` | `0x4d2e640` | `0x4d2e810` |
| Removal, perp and spot | `0x26de150`, `0x26de280` | `0x42f7590`, `0x42f7290` | `0x42f7420`, `0x42f7700` |
| Flush, perp and spot | `0x24fb610`, `0x24fc8a0` | `0x4329870`, `0x432b440` | `0x432a100`, `0x432a990` |

The first handlers are `0x22be610` and `0x21dff60`, which clone the list and call the cores. Second and third closures, workers and items are equal once call and rip displacements are masked, except rows naming a state field (`copies`). Third state fields sit `0xa80` above the second ones, for example `+0x880` and `+0x1300`. The first item and spot arm have another size (`pairs_of_other_size`), so those are compared by running one specification on all three. All sites are in `call_sites.tsv`. The only caller of each item is its closure. Slot `0x5774aa0` of map lookup has 12 sites in 9 functions, and `0x271c490`, `0x4d1c1c0`, `0x4d1dff0` (batch modify) are among them.

### Wire rows and records

| Form | Size | Fields |
| --- | --- | --- |
| Wire, oid | 0x10 | `+0x00` oid, `+0x08` asset dword |
| Wire, client id | 0x14 | `+0x00` client id, `+0x10` asset dword |
| Record | 0x20 | `+0x00` asset dword, `+0x08` byte 0 oid or 1 client id, `+0x09` client id, `+0x10` oid |
| Result | 0x60 | `+0x00` status word, `+0x02` error bytes, `+0x04` wire asset of `0xc5` |

Each preparer emits one record for each wire row and drops none, so the returned count at core stack `+0x20` always equals the input length. This closes the question #607 left open. The source buffer is freed with its own capacity. The worker allocates `len * 0x60`, the closure runs items in list order and frees the records at the end.

### One item

Item arguments: `rdi` result, `rsi` state, `dl`, `cl` gate bytes, `r8` a tuple of pointers to user, asset and record.

1. Gate. `clock` runs at once when `dl == 0` and `cl` is above `0xe` or not in mask `0x501d` (bits 0, 2, 3, 4, 12, 14). Else sampler `0x13c9e20(50)` decides. The cores pass `dl = 2` (oid) or `3` (client id), so on this path the sampler always decides and `cl` is never read.
2. A second clock read, always. Its value goes to the hook.
3. Resolver `0x3c0cc70(asset, state + names, state + 0x90)`. A status other than `0x186` is the item result, all 0x60 bytes. No hook, no counter.
4. Kind dword 1 is spot. Any other kind is perp.
5. Spot: if state byte `+0x3ac8` is nonzero, status `0xf9` `Spot disabled`, no hook, no counter. Else the spot arm.
6. Perp: `dex = index / 10000`, `local = index % 10000`. `dex >= rows length` panics at `l1/src/dex_registry/perp_dex.rs:30`, `local >= book count` panics at `l1/src/books.rs:19`. Book = row `+0x08` + `local * 0xd8`.
7. Client id record: map lookup. Not found skips the removal and counts as missing.
8. Removal with reason 2. It returns 1 when the oid is not in the book.
9. Always: one closing row with words 3, 4 (stride 0x278 perp, 0x268 spot), even when nothing was removed, then the flush.
10. Status: `0x186`, or `0xc5` with the wire asset. Perp checks `dex < dex length` first and panics at `l1/src/dex_registry/clearinghouses.rs:11`. That second bound is only read here, after the flush.
11. Hook: when state `+0x3a88` is set, method at table `+0x38` gets user, `status != 0x186` and the second clock read. Then on `0x186`, `+0x880` rises by one, stopping at `u64::MAX`.
12. When timed, a last clock read and `0x4ee3730(later, earlier)`. Its result is not read.

### Wire asset in `0xc5`

| Packed asset | Wire |
| --- | --- |
| up to 9999 | same |
| 10000 to 99899999 | packed + 100000 |
| above 99899999 | `0xffffffff` |

The spot arm takes it from `0x3c0cea0(1, index, state + 0x90)`. Status `0xc5` prints formatter `0x3998370`, `Order was never placed, already canceled, or filled.`, then template `0x1fa53a`, ` asset=`, then the dword. The `0xc5` arm reads no field for the text, so nothing else in the result matters.

### Book map at `+0x48`

`0x342a430(map, user, client id)` returns `al` and the oid in `rdx`. The book serde writers name this field `user_trackers` (#750).

| Layer | Header | Bucket |
| --- | --- | --- |
| By user | `+0x00` control, `+0x08` mask, `+0x18` items, `+0x20` two keys | 0x78: user at `+0x00`, inner map at `+0x48` |
| By client id | bucket `+0x48` control, `+0x50` mask, `+0x60` items, `+0x68` two keys | 0x18: client id, oid at `+0x10` |

Both layers use plain SipHash 1-3 over the raw bytes with no length prefix: 20 bytes through `0x399c7a0`, 16 bytes through `0x399c650`. Items 0 at either layer returns not found before any hash of that layer. Tests build tables from a Python SipHash and the real probe finds them, so the hash statement is checked by the real bytes.

### Status words

| Word | Text | Source |
| --- | --- | --- |
| `0x186` | none | removed |
| `0xc5` | `Order was never placed, already canceled, or filled. asset=<wire>` | nothing removed |
| `0xf9` | `Spot disabled` | spot route with the state byte set |
| `0x143` | `Invalid input length` | core, list of 10001 or more, #607 |

### Reference labels

`reference_claims` holds the checks. `cancel_perp` and `cancel_spot` in `l1/exchange/handlers/03_cancel.rs` have no body. `CancelItemResult` with target, route, user, asset and effects does not match the 0x60 byte result. The spot path has no `0xf9` gate there. The zero control byte comment agrees.

### Inferences

- Marked as inference: reason 2 is `canceled`, from the status serializer table cited in #161. The state byte at `+0x3ac8` is a global spot switch. The hook is a tracing or metrics object, because its result is unused and it is optional. `+0x880` counts successful cancels and is a sibling of the list counter `+0x878`. Words 3, 4 close the rows of one action; the flush body is not read here.
- Status `0xc5` after a removal that found nothing still costs the row and the flush, so an absent oid is not free: inference from the order of steps, nothing is measured.

### Unresolved

- What sampler `0x13c9e20(50)` returns, and who reads the elapsed time.
- Why the gate tests `cl` when this path always passes a nonzero `dl`. The items have no other direct caller.
- The resolver kind dword: only 0 and 1 are named. A kind of 2 runs as perp; whether the resolver ever returns it is not checked here.
- The removal cascade and the flush body are stubs.

## Implementation and comparison

not yet implemented. The file carries a specification in Python only as a check of the bytes.

## Results and limitations

| Cases | 446 |
| Mismatches | 0 |
| Instructions stepped | 141,049 |
| Stepped / total: first worker: result vector | 48 / 71 |
| Stepped / total: first closure: one item per record | 99 / 115 |
| Stepped / total: first item: gate, route, book, status | 286 / 329 |
| Stepped / total: first spot arm | 97 / 114 |
| Stepped / total: second worker: result vector | 48 / 71 |
| Stepped / total: second closure: one item per record | 99 / 115 |
| Stepped / total: second item: gate, route, book, status | 278 / 321 |
| Stepped / total: second spot arm | 89 / 106 |
| Stepped / total: third worker: result vector | 48 / 71 |
| Stepped / total: third closure: one item per record | 99 / 115 |
| Stepped / total: third item: gate, route, book, status | 278 / 321 |
| Stepped / total: third spot arm | 89 / 106 |
| Stepped / total: first oid preparer | 75 / 93 |
| Stepped / total: first client id preparer | 81 / 98 |
| Stepped / total: second oid preparer | 76 / 94 |
| Stepped / total: second client id preparer | 81 / 98 |
| Stepped / total: book map: user and client id to oid | 120 / 120 |
| Stepped / total: first oid core, run with no mutants | 77 / 77 |
| Stepped / total: first client id core, run with no mutants | 78 / 78 |
| Stepped / total: second oid core, run with no mutants | 77 / 77 |
| Stepped / total: second client id core, run with no mutants | 78 / 78 |
| Stepped / total: third oid core, run with no mutants | 77 / 77 |
| Stepped / total: third client id core, run with no mutants | 78 / 78 |
| Mutants killed / survived / unreached | 646 / 59 / 51 |

Every surviving or unreached row has its reason in `mutations.tsv`. Survivors were probed by class: fresh lists have buffer equal to the iterator start, list size limits above 2^58 bytes, dead first writes of the empty vector in the second and third copies, a zero start index, gate byte `cl` never read, bit 15 of the mask being 0, and two shuffle bits on equal dwords. Unreached rows are allocator failure, panic or unwind arms.

Limits: every case uses fake state. List lengths reach 5, since items are independent. A list of 10000 is not run, the cost is one full pass per item. The real hash runs on real bytes with no mutants, since it has more than 300 callers. A mutant counts as killed only if a run differs in the log, results, counters, mark or live allocations.
