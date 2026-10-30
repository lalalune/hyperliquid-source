# RE-006: node #94 hyperliquidity order refresh and its level cursor

- Component ID: orderbook (task RE-006)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / can1357 `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observation for everything under Evidence; inference only where the Inferences section says so; open points are listed under Results and limitations
- Scope included and excluded: included are the refresh `0x26cb280` (whole function), the cursor `0x3263760` (whole function) and the same cases run through the two other copies of the refresh, `0x42d2790` and `0x42d3d50`. Excluded are the insides of every other callee: the book cancels, the order path, the result map drop steps, the user lookup, the vector growth, and whatever writes the ladder tree. In the two copies the end of the result map drop is excluded too. `0x3263760` is one holder of the `10^(wei - sz)` ladder in the merged `RE-004-spot-wei-scale-family-94`; that packet pins the scale, and this one asks a different question: what the function returns and how the refresh uses it.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned artifact in place:

```sh
python3 tools/hyperliquidity_refresh.py --out research/work-items/RE-006-hyperliquidity-refresh-94
python3 -m unittest tests.test_hyperliquidity_refresh
```

In `research/work-items/RE-006-hyperliquidity-refresh-94`, `sha256sum -c MANIFEST.sha256` checks the files. The tool checks the binary digest first and fails on any other input. It reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`. It parses no objdump or readelf output, calls no external program and never executes the binary. It took about 190 s here, most of it in the mutation pass. Only the standard library is used.

Generated files: `evidence.json`, `call_sites.tsv`, `mutations.tsv`.

## Evidence

Coordinates are virtual addresses in node #94. Function bounds are FDE extents.

### Path

| Step | Address | Note |
| --- | --- | --- |
| Block step, direct call, flag 1 path | `0x26fef91` in `0x26fed00` | Passes the ladder holder `+0x38d0`, the spot books `+0x3380`, the exchange and an event vector |
| Span wrapper, direct call | `0x2229404` in `0x22293c0` | Span name `hyperliquidity_ensure_orders` at `0x3ef968` |
| Refresh | `0x26cb280` | 5292 bytes |
| Cursor, through the slot `0x5774750` | `0x3263760` | 601 bytes |
| Second copy of the refresh | `0x42d2790` | Calls `0x43038b0`, `0x42f7290`, `0x42d5310` |
| Third copy of the refresh | `0x42d3d50` | Calls `0x4303b30`, `0x42f7700`, `0x42d5650` |

`call_sites.tsv` lists every direct call of the three copies and of three callees. A scan of every `call [rip+rel32]` in `.text` finds three reads of slot `0x5774750`, one in each copy (`evidence.json` key `callers`).

### Ladder state

The holder keeps a B-tree at `+0x10` (root), `+0x18` (height) and `+0x20` (length). It uses the same node shape as a book side tree: values at `+0x00` with stride `0x20`, parent `+0x160`, u64 keys `+0x168`, parent index `+0x1c0`, length `+0x1c2`, edges `+0x1c8`. The key is both the book index, against a bound that panics at `l1/src/books.rs:19`, and the index into the pair array, against a bound at `l1/src/spot_meta.rs:565`.

| Ladder field | Type | Meaning |
| --- | --- | --- |
| `+0x00` | u64 | level vector capacity; `1 << 63` is the niche for no ladder, which is skipped |
| `+0x08` | pointer | level vector, stride `0x18` |
| `+0x10` | u64 | level count |
| `+0x18` | u64 | order size |

| Level field | Type | Meaning |
| --- | --- | --- |
| `+0x00` | u64, read as a dword | tag: 1 means `+0x08` holds a resting order id |
| `+0x08` | u64 | order id, written from the place result |
| `+0x10` | u64 | price, never written here |

### Cursor `0x3263760`

Output: index, partial flag, remainder.

1. The pair array at exchange `+0x1f8` gives the base token (`spot_meta.rs:565` on a bad index).
2. The user map gives user `0xff` * 20. A balance tree search for the token gives the balance, 0 if no row. The tree has keys at `+0x08`, values at `+0x60` with stride `0x18`, length at `+0x16a`, edges at `+0x170`.
3. Token bound (`spot_meta.rs:113`). Token `+0x49` minus `+0x48` is the decimal difference. A negative difference panics at `spot_meta.rs:1199`. So does any difference of 32 or more, and any power that overflows u64, so 19 works and 20 panics.
4. An order size of 0 returns the level count with flag 0.
5. Otherwise `units = balance / 10^difference` (floored), and `whole, rem = divmod(units, order size)`.
6. With `rem == 0` the index is `max(count - whole, 0)` and the flag is 0. With `rem != 0` the index is `count - whole - 1` if `count > whole`, else 0, and the flag is 1.

With `whole >= count` and a remainder the index is 0, so level 0 gets the remainder as its size, not a full order, and the ladder shows less than the balance.

The cursor table in `evidence.json` key `worked_example` is produced by the real bytes. For 10 levels and order size 1000, a balance of 3000 units gives index 7, and 3500 gives index 6 with remainder 500.

### Refresh `0x26cb280`, per ladder

1. A ladder with `first price == last price`, which includes one level, cancels all the user's orders in the book through `0x26e4240` with flag 1, reason 2, and moves on. No cursor is read. An empty ladder skips this test.
2. The block time word becomes milliseconds, clamped at 0, and the cursor is read.
3. Two passes, side 0 then side 1. Each reads the first key of book `+0x80` and of book `+0x98` through `abs`, 0 for none. An empty leaf under a nonzero length walks up, and panics at `navigate.rs:534` past the root.
4. Side 0 walks `index - 1` downward. Its bound is book `+0x98`: with a nonzero bound, a level with `price >= bound` is skipped. Side 1 walks `index` upward. Its bound is book `+0x80`: a level with `price <= bound` is skipped. A skipped level is not counted, and its tag is not read.
5. The wanted size is the ladder's order size. On side 1 with the partial flag it is the remainder, but only if the very first level was not skipped.
6. A level with tag 1 is looked up: FxHash of the id (`id * 0xf1357aea2e62a9c5`, rotate left 20) in the table at book `+0x28`, then the slab at book `+0x08`, stride `0xf8`. It is the user's own order if the table has it, the index is inside the slab, slot tag `!= 2`, and the 20 bytes at slot `+0xe0` are `0xff`.
   - Own, same side (`+0xc2`), same size (`+0xc8`), count below 100: kept.
   - Own, otherwise: its id goes on the cancel list.
   - Anything else: left alone.
7. A new order record is built unless the order was kept, and only if the count is below 100. A level whose tag is not 1, reached with the count at 100, ends the side. Levels with tag 1 keep being walked past 100, so own orders out there are cancelled.
8. Every level that is not skipped counts, kept or new.
9. After both sides, every cancel runs first through `0x26de280`, reason 2. Then each record goes to `0x26cc730`.
10. On success the level becomes tag 1 with the id at result `+0x30`. On failure (result `+0x00` is `1 << 63`) the level is left alone, so a stale id stays.

| Order record field given to `0x26cc730` | Meaning |
| --- | --- |
| `+0x00` | 1 |
| `+0x08` | size |
| `+0x38` | 8, the dangling pointer of an empty vector; `+0x30`, `+0x40` are 0 |
| `+0x80` | level price |
| `+0x88` | block time in milliseconds |
| `+0xa2` | side |
| `+0xb8` | user `0xff` * 20 |

The whole list is in `evidence.json` key `record_map`, including the zero fields. `+0xb0` holds the cursor index, a stale word behind a zero tag at `+0xa8`.

Worked example from the real bytes: 10 levels at 1000, 1040, ... 1360, order size 1000, balance 3500, best bid key -1000, best ask key 1400. The output is 6 bids from level 5 down at size 1000, an ask of size 500 at level 6, and full asks at levels 7 to 9.

### The three copies

All three copies have the same structure. Their counts of non-stack field offsets agree except where `evidence.json` key `copies` lists a difference: one more `+0x80` (a `lea` in the copies, an `add` in the first), one fewer `+0x00`, and twice as many `+0x1f0`, the descents the copies inline for the result map. The same 192 cases, less the 19 that drop a non-empty result map, ran through each other copy against the same specification.

### Differences from the reference

`evidence.json` key `reference_claims` lists them.

- `l1/hyperliquidity.rs:53` calls the first two level words unknown. They are a tag and a resting order id.
- `l1/exchange/impl_spot_deploy.rs:180` gives a level a size and a flag. Neither is read here.
- Both reference structs add a base balance and a USDC amount to the ladder. The value here is 0x20 bytes, and the balance comes from the user's balance tree.
- The reference has no reader of the ladder tree beyond `contains_key`. The refresh, the cursor, the crossing skip and the cap of 100 are absent.

### Inferences

- Side 1 is the sell side. It starts at the cursor, its levels are the top ones, and their number follows the base balance held. So book `+0x80`, its bound, holds bids, and `+0x98` holds asks. This fits side byte 0 being a buy in `RE-006-mid-market-order-94` (open), and it answers the question left open in `RE-006-top-order-clone-94` (open).
- User `0xff` * 20 holds the ladder's inventory. No byte names the account.
- The cursor is a position on the ladder that needs no stored state: fills change the balance, the next refresh moves the cursor, and the sides swap around it.
- The remainder is what is left of a partly filled level, if slot `+0xc8` is a remaining size. That is not proved here.
- The two other copies are the same source with other type parameters. Their paths go through `0x42d2390` and `0x42d2590`, reached from `0x4ce8310` and `0x4ce8080`. Which copy runs on a live node is not shown.

## Implementation and comparison

not yet implemented. The Python specification in the tool is a comparison aid, written from reading the bytes, not a reconstruction. No Rust, no build and no binary comparison exist for this path.

Method: a byte decoder and evaluator run the real instructions of the refresh and the cursor. Stubbed edges record their arguments. A separately written specification predicts every edge call, every record field that the builder writes, every level byte and every panic Location.

The cursor also ran alone on 155 cases, which reach the decimal arms and the division widths directly.

Controls: each conditional, immediate and non-stack field offset is flipped one at a time, by bit 0 for conditions and immediates and by bit 3 for offsets. 470 were detected, 37 survived and 20 were not reached. Every survivor and unreached row has its reason in `mutations.tsv`. The mutants cover the first copy and the cursor, not the other two copies. The first pass found real gaps in the harness, which were closed: all ladders looked alike under the default book, ladder prices never reached 1, order ids were too small to show the multiplier's low bits, and no slot sat past the slab length.

## Results and limitations

| Metric | Value |
| --- | --- |
| Refresh cases | 192 |
| Cursor cases, helper alone | 155 |
| Mismatches, all runs and all three copies | 0 |
| Refresh outcomes | cancels and new orders 9, cancels only 1, flat ladder, all cancelled 2, new orders only 161, no ladder read 4, nothing to change 8, panic 7 |
| Instructions stepped | 2,025,275 |
| Stepped / total, refresh | 945 / 1058 |
| Stepped / total, cursor | 160 / 161 |
| Stepped / total, second copy | 839 / 1110 |
| Stepped / total, third copy | 839 / 1110 |
| Cases run on each other copy | 173 |
| Mutants killed / survived / unreached | 470 / 37 / 20 |

Mismatch count covers all cases on all copies. Stepped counts for the copies are lower because their inline map drop is excluded.

Limits:

- All states are harness-built. No live ladder or book state is known, and keyless spine nodes exist only to reach the long tree walks.
- `0x26e4240`, `0x26de280`, `0x26cc730`, the map drop steps, the lookup and the grow slots are stubs: their arguments and the use of their answers are pinned, their insides are not. The grow stubs double from 4, which is the harness's choice.
- Whether the order record's `+0x00` = 1 and its zero fields select a time in force or reduce-only is not resolved.
- Whether slot `+0xc8` is the remaining or the original size is not resolved.
- Which handler writes the ladder tree, and how it fills the levels, is not read.
- No progress gate is requested.

Next question: what does `0x26cc730` do with this record when the order would cross, and where does a fill update the `0xff` user's balance that the next cursor reads?
