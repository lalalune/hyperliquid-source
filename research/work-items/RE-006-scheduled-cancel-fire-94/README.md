# RE-006: how a scheduled cancel fires on node #94, from the due test to the per-user order sweep

- Component ID: `orderbook` (task RE-006, book transitions)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (labels used as leads only, nothing copied)
- Claim status: observation for every offset, branch, constant and count below; inference where the text says so; unresolved items are listed at the end
- Scope included and excluded: included are the firing walk and its day reset, the market selector, the two closures of the first copy, the spot TWAP sweep, and the two per-user sweeps with their collectors. Excluded are the arming gate (open PR #117, which leaves out "the code that fires a scheduled cancel"), the removal of one order (`0x26df430`, `0x26de3d0`, stubs here), the closures of the second and third copies (`0x4c63f20`, `0x4c641c0`, `0x4c64300`, `0x4c64080`, which open PR #161 lists, named here only as call targets), the event flush and the row builders.

## Reproduce

Run from the repository root. The tool starts no external program and never runs the binary. A full run takes about 110 s, and the unit file about 40 s because `test_static_files_regenerate` runs a reduced pass.
Author environment: Python 3.12.3, Linux x86-64. Section and FDE parsing come from `tools/elf_index.py` and `tools/fde_extents.py`.

```sh
python3 tools/artifacts.py verify
python3 tools/scheduled_cancel_fire.py --out work/scheduled-cancel-check
diff -r work/scheduled-cancel-check research/work-items/RE-006-scheduled-cancel-fire-94 -x README.md -x MANIFEST.sha256
python3 -m unittest tests.test_scheduled_cancel_fire
```

Generated files: `evidence.json`, `call_sites.tsv`, `mutations.tsv`. Every number there comes from `struct` reads of the ELF or from the evaluator in the tool. The excerpt below is for reading only and is not an input to anything.

## Evidence

Coordinates are virtual addresses. `+` offsets are from the named structure's start. Each function was decoded to its exact FDE end; `functions` in `evidence.json` gives the extents and how many instructions ran. The rest are unwind paths and arms listed in `mutations.tsv`.

### Call path

```text
block host 0x22297c0 / 0x470e9a0 / 0x47162d0
  firing walk 0x2702760 / 0x4cef8f0 / 0x4cef2f0 (state, pointer to a date)
    every map entry in key order: if due, count + 1, date = 0, remember the user
    every remembered user: selector (state, user, 2, -, reason 0xf, flag 0)
      perp dexes in metadata order: closure, then flush
      then all spot books: closure, then flush
        closure: per-user sweep on each book
                 flag set: terminate the user's TWAPs
    if the passed date is below the state date: retain step over the same map
```

| Copy | Firing walk | Selector | Retain step | Map field | Perp, spot closure | Flush dex, flush spot |
| --- | --- | --- | --- | --- | --- | --- |
| first | `0x2702760` | `0x270f1c0` | `0x27e8ad0` | `+0x39a8` | `0x27031b0`, `0x2703080` | `0x24fb610`, `0x24fc8a0` |
| second | `0x4cef8f0` | `0x4d005d0` | `0x4898630` | `+0x39a8` | `0x4c63f20`, `0x4c641c0` | `0x4329870`, `0x432b440` |
| third | `0x4cef2f0` | `0x4d000a0` | `0x489aec0` | `+0x4428` | `0x4c64300`, `0x4c64080` | `0x432a100`, `0x432a990` |

Across `copy_diff`, each copy has the same instruction count as the first, with 0 shape differences. The second copy has no field differences. The third differs in 3 field offsets of the firing walk and 6 of the selector, all by `0xa80`. The retain steps have none. The cases of the firing walk and selector ran on all three copies with the same results.

### Map value

Keys are the 20-byte user. Values are 24 bytes: u64 count at `+0`, date dword at `+8`, seconds at `+0xc`, nanoseconds at `+0x10`. Node layout: parent `+0`, values `+8`, keys `+0x110`, parent index `+0x1ec`, length `+0x1ee`, edges `+0x1f0`, leaf size `0x1f0`, inner size `0x250`.

### Firing walk

State time is three dwords at `+0x60`: date, seconds, nanoseconds.

1. The walk visits `+0x39b8` entries in key order. Root null or length 0 means no visit.
2. A date dword of 0 is skipped: that is the disarmed state.
3. Date is compared signed. On equal dates, seconds then nanoseconds are compared unsigned. An entry is due when its time is at or before the state time. A deadline equal to now fires.
4. A due entry gets count + 1, saturating at `u64::MAX`, and date 0. Seconds and nanoseconds stay. This is the only writer of that count on this path, and the count is what the arming gate compares with 9.
5. Due users go into a local vector of 20-byte rows, and the map is not touched again until all of them are done.
6. Each user goes to the selector with `edx` 2, `r8d` 0xf, `r9d` 0.
7. Two clock calls and the helper `0x4ee3730` bracket the firing. The helper's result is not read again in this function. When something fired and the word at `0x577ab98` is nonzero, slot `0x576e8b8` initialises the static at `0x577ab80`.

The state is changed before the first order is removed, so a user's entry is disarmed and counted even if nothing rests in any book.

### Day reset

After the firing, the dword at `rsi` is compared signed with the state date. If it is lower, the retain step runs over the same map: each visited entry gets count 0, and an entry with date 0 is removed through the tree's own removal, lowering the map length. An armed entry stays, with its deadline.

So the limit that the arming gate reports as per day is reset here, and it is reset on the date change, not on a rolling window. An entry fired in the same call has date 0 by then and is removed. In the worked example of `evidence.json`, count 9 due, count 4 armed and count 7 disarmed become one entry: the armed one, with count 0.

### Selector

`0x270f1c0` takes (state, user, selector, asset, reason byte, flag byte). The record it builds for a closure holds selector word, asset, collection, TWAP tracker, state, event vector, the user at `+0x30`, flag at `+0x44`, reason at `+0x45`.

| `rdx` | Books | Collection and tracker |
| --- | --- | --- |
| 2 | each dex in the list made from metadata `+0x30` (stride `0x2f0`, vector `+0x5c0`, length `+0x5c8`), then all spot | collection `+0x3370 + dex * 0x138`, tracker `+0x18` further; spot `+0x3380`, `+0x34e0` |
| odd | one spot book, the asset as it stands | as above |
| other even | dex = asset / 10000, one book | as above |

A dex at or past `+0x3378` panics with error word `0x141`, at `l1/src/dex_registry/perp_dex.rs:30:33`. Each dex gets its own event vector, flushed before the next dex (`0x24fb610`, dex, state), and spot flushes with `0x24fc8a0`.

### Three callers, one selector

Each copy has exactly three call sites of its selector, with these byte patterns before the call (`selector_sites`):

| Kind | First copy site | Function | Reason byte | Name in the status table | Flag |
| --- | --- | --- | --- | --- | --- |
| Scheduled cancel | `0x2702b4f` | `0x2702760` | 0xf | `scheduledCancel` | 0 |
| Liquidation | `0x2731153` | `0x2731030` | 0xd | `liquidatedCanceled` | 0 |
| Vote | `0x2359b3d` | `0x2355f40` | 0x10 | `internalCancel` | 1 |

The status names are read through the serializer table `0x7038dc`. The vote site is case 27 of table `0x3dd1b8`. A zero byte at payload `+0x08` sets `edx` 2 at `0x2359b22`; otherwise slot `0x5773950` resolves the selector and asset. The liquidation and vote selector values are read here only from these bytes, and those two callers are not run.

So only the vote path terminates TWAPs. A scheduled cancel and a liquidation leave them running.

### Closures of the first copy

Spot `0x2703080`: selector word 1 picks book `asset` with no reduction, and any other value walks all books. Perp `0x27031b0`: the same with asset % 10000. An index past the collection panics with `l1/src/books.rs:19:47`. Book stride is `0xd8`. Each book gets the sweep with the record's reason.

### TWAP termination

With the flag set, the perp closure does this inline, and the spot closure calls `0x26ddbe0`, which is the same walk.

1. The tracker's map at `+0x18` is searched for the user. Not found: nothing happens.
2. The collector `0x2574b40` / `0x2569980` lists ids from the user's map. By the bytes pinned in `pins`, with selector word 1 it keeps only ids whose first value word equals the asset. The collector is a stub here and that test was read, not run.
3. For each id the user is searched again, since an earlier step may have removed it, and the id is taken out. A miss drops error word `0xce` and goes on.
4. When the user's map is empty, the user is removed.
5. Perp only: first word of the taken row / 10000 is a dex, checked against `+0x5c8`, with panic at `l1/src/dex_registry/clearinghouses.rs:11:29`.
6. A row is pushed: tag 4 at `+0`, the built status at `+8` for `0x58` bytes, status word `0x8000000000000001` at `+0x60`, id at `+0x78`, state time at `+0x80`, user at `+0x8c`. Stride is `0x278` for perp and `0x268` for spot.

Inference: tag 4 with that word is a TWAP status row marked terminated. The word's meaning comes from the TWAP status serializer, not from this path.

### Per-user sweep

`0x26e3ef0` (perp) and `0x26e4240` (spot) look up the user in the map at book `+0xb8`. Node keys at `+0x378`, values at `+0`, stride `0x50`, length `+0x456`, edges `+0x458`. Absent user: no call at all.

| Input | Perp | Spot, flag 1 | Spot, flag 0 |
| --- | --- | --- | --- |
| First tree (entry `+0x20`), keys are slab indexes | read | read | read, slots with byte `+0xb0` equal to 1 skipped |
| Second tree (entry `+0x38`) | read | read | not read |
| Index past the slab, or low tag dword 2 | skipped | skipped | skipped |
| Removal | `0x26df430` | `0x26de3d0` | `0x26de3d0` |
| Map removal after the loop | `0x2866f90` | `0x2865ca0` | none |

Keys are slot word `+0xd8` for the first tree and the tree key for the second. They are sorted and made unique, and the removals run in ascending order on the fixed list. The real collectors, sort and set code ran. The flag is `edx` for spot and is fixed in the perp function. Each `spot` closure call passes 1.

These are the first-copy siblings of the sweep family in open PR #161. The two extra functions and their removal routines are not in that packet's table.

### Against the reference

`reference_claims` in `evidence.json` has the rows.

- `l1/books.rs:242` and `:247` call `0x2703080` and `0x27031b0` snapshot and user book updates. No snapshot is read: they are the closures above.
- `l1/exchange/handlers/18_schedule_cancel.rs` has the arming path only, calls the count `aux_word`, and has no firing or day reset.

## Implementation and comparison

not yet implemented. No Rust was written and nothing is compared to a build. The evaluator runs the original bytes against a Python specification written from a read of the code, so it tests that reading, not a reconstruction.

Real bytes ran for: the firing walk and retain step with the tree removal they call, on all three copies; the selector on all three; the two closures, spot TWAP sweep, and both per-user sweeps with collectors and set code on the first copy. Stubs: removals, map removals, entry drops, flushes, clocks, TWAP collectors and take functions, row builders, allocation, memcpy, memcmp, grow.

## Results and limitations

| Metric | Value |
| --- | --- |
| Cases | 190 (first copy 190, second 67, third 67) |
| Mismatches, all runs | 0 |
| Outcomes | closure perp: panic panic 1, closure perp: panic unwrap 1, closure perp: returned 39, closure spot: panic panic 2, closure spot: returned 8, fire: returned 48, select: panic alloc failed 1, select: panic unwrap 3, select: returned 15, sweep perp: returned 17, sweep spot: returned 33, twap spot: returned 22 |
| Instructions stepped | 535,353 |
| Stepped / total: firing, retain, selector | 302 / 333, 107 / 110, 235 / 272 |
| Stepped / total: spot, perp closure, spot TWAP sweep | 77 / 77, 363 / 389, 258 / 277 |
| Stepped / total: perp, spot sweep | 162 / 175, 194 / 207 |
| Mutants killed / survived / unreached | 583 / 22 / 13 |
| Selector sites read | 9 |

Corruption controls in the unit file: wrong hash, offset inside a function, NOBITS read, wrong status table, wrong reason site, wrong host, absent byte pin, and flips of the due branch, the day branch, the reason immediate and the retain branch.

Of the 22 surviving and 13 unreached mutants, each row has its reason in `mutations.tsv`: unwind paths, a 2^64 counter, the height 8 and 16 descent limits, dead stores, unread outputs and a back handle.

Unresolved:

- What the passed date is. It is the first dword of a 12-byte value copied from `0x10(arg)` of the host. The name "previous block time" is an inference from the lower-than test. It was not proved.
- The body of the removal routines, and which event rows they make for each reason.
- Whether scheduled cancel reaches a dex missing from the metadata list.
- What the static at `0x577ab80` holds. It was not traced.
- What slot `0x5773950` returns on the vote path when the payload byte is nonzero.
- The other three direct calls of `0x26df430`, at `0x26edac2`, `0x271cca1` and `0x26de244`.

This packet requests no progress gate.

Next question: what does `0x26df430` emit for reason 0xf, and does it differ from reasons 0xd and 0x10?
