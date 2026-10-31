# RE-006: trigger order path: which untriggered orders fire on an oracle update, and what one firing does to the book

This packet gives a reconstruction the whole life of a stored trigger order on node #94: the test that makes it fire (trigger price against a fresh mark or the book mid), the size sort that sets the firing order, the 1.1 or 0.9 limit price capped at the opposite best, the five result words, the event rows, and the removal from field `u` of `user_states`. The reference holds none of this, so the reconstruction can now write these three functions from a table instead of guessing them.

- Component ID: RE-006 (book state transitions), one path from an oracle update to `insert`
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included with mutants are the first selection `0x4321930` with its helpers `0x4913950` and `0x454cf20`, the first firing `0x42ff010`, and the first wrapper `0x4d44470`. Real bytes without mutants: `0x4320f80`, `0x4300950`, `0x4d47070`, `0x27371f0`, and the time helpers behind slots `0x576e8a8`, `0x576e8b0`. Stubbed at the edge: the top helpers `0x4a07680`, `0x4a078a0`, tick `0x42c7600`, price gate `0x3714e70`, cap test `0x3713f20`, record builder `0x43029d0`, insert `0x4311140`, relation lookup `0x430d380`, position lookup `0x36f57f0`, removal `0x4946940`, flush `0x432a100`, tree helpers, the long sort, allocator and memcmp. Excluded: the bodies of those stubs, and the margin routing in the hosts, which is read by hand below and not evaluated.

## Reproduce

From the repository root:

```
python3 tools/trigger_order_fire.py --out research/work-items/RE-006-trigger-order-fire-94
python3 -m unittest tests.test_trigger_order_fire
```

The tool takes about 190 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### Path map

| Step | First copy | Second copy | Third copy |
| --- | --- | --- | --- |
| Host for one dex | `0x4cf37f0` | `0x4cf94a0` | `0x27078a0` |
| Selection for one book | `0x4321930` | `0x4320f80` | inlined in the host |
| Wrapper: find book, fire, flush rows | `0x4d44470` | `0x4d47070` | `0x27371f0`, wrapper and firing in one function |
| Firing of one order | `0x42ff010` | `0x4300950` | as above |
| Insert | `0x4311140` | `0x4314da0` | `0x26ebdc0` |
| Row flush | `0x432a100` | `0x4329870` | `0x24fb610` |

Call sites are in `call_sites.tsv`. Selection and firing have one caller function each among the hosts. The first and second copies are equal once call and rip displacements are masked, except rows that name a state field. Each such row is listed with its two displacements in `copies`: firing 11 rows, selection 2, wrapper 2. The third firing copy has other code order, and it runs the same cases against the same specification.

### What the host does before the selection (read by hand)

`0x4cf37f0` takes a dex index. With market mode `+0x230` other than 3 it refuses an update less than 2.5 s after the stored time at dex row `+0x2e0` (seconds 2, nanos `0x1dcd6500`), status word `0x78`. It calls the open interest gate through slot `0x5774988`, stores the new time, writes one mean of the two tops per book into a list, and calls slot `0x5776b08` with it. Then it calls the selection for every book of the dex, and walks the rows. Each row goes down one of three routes, by a byte at value `+0x3c` of the user row in map state `+0x11c0`:

| Byte | State test | Route |
| --- | --- | --- |
| above 3, or exactly 3 | `+0x5b0` bit 0 clear | counter `+0x1250` and a per-user word `+0x30` go up, `0x46efb70`, wrapper, then `0x46ef4a0` or `0x46ea0b0` |
| 2 | `+0x5b1` bit 0 clear and `+0x454b` is 1 | `0x46ea0b0` around the wrapper for assets from 10000 up, the wrapper alone below |
| otherwise | | direct firing and flush with the depth word held, site `0x4cf574d` |

This routing is outside the evaluated scope. The direct site and the three wrapper sites are in `call_sites.tsv`.

### Which orders fire

For one book (`0x4321930`):

```
tops = both sides from book +0x80
if a top is 0: result None
mid = floor of the mean, by (a & b) + ((a ^ b) >> 1)
reference = mid
if asset % 10000 < mark count of the dex row:
    row = mark row, stride 0x60
    if block time <= row time + 20 s: reference = row price (+0x20)
for each user in user_states, in key order:
    for each order in field u, in oid order:
        skip if byte +0x10 is not 0
        fire if trigger == reference
        stop (byte +0xb1 == 1): fire if (trigger < reference) != side
        else:                   fire if (reference < trigger) != side
        size = order size, 0 when the size is absent
        if reduce only (+0x90): size comes from the position
sort rows by size, smallest first; equal sizes keep walk order
return (user, oid) rows, mid, reference, asset
```

The fire table with all 12 forms is `fire_table`, and each form runs on real bytes.

A reduce only order reads the signed size for this asset from the user's position map at dex row `+0xf8`. No position, a zero size, or a size on the same side as the order gives size 0. Otherwise size is the position size, cut to the order size when one is present. The row stays in the list with size 0, so such an order still fires, and it fires first.

Up to 20 rows sort through the insertion sort `0x4913950`, and from 21 rows through slot `0x57765f8` (`0x57749b0` in the second copy). Both compare the first 8 bytes as an unsigned word. `0x454cf20` then squeezes each 0x28 byte row to 0x20 bytes in place, which drops the size.

### What one firing does

`0x42ff010(out, book, user, oid, unread, mid, state, rows)`. The fifth argument, the reference price in the caller, is never read: the runs pass a poison word there. The third copy skips that word in its argument block.

```
price = float(trigger) * (1.1 for side 0, 0.9 otherwise)
price = rounded half away from 0, at least 0, saturating to u64, at least 1
step  = 0x42c7600(dex row, asset, price)
limit = floor(price / step) * step               side 0
limit = (floor(price / step) + 1) * step         side 1, saturating
limit = limit or 1
opposite = second top for side 0, first top for side 1; limit when that top is 0
sent = min(limit, opposite) for side 0, max for side 1
```

Side 1 adds a whole step even on an exact multiple. `price_table` holds worked rows.

`sent` goes to the price gate `0x3714e70` through slot `0x5774860`, together with a state byte, the side and the block time. Then:

| Word at result `+0` | When | Effect |
| --- | --- | --- |
| `0x8000000000000002` | no user, or no user tree | nothing |
| `0x8000000000000003` | user, but no order with this oid | remove call runs and finds nothing; tracker call if no resting order has the oid |
| `0x8000000000000001` | gate said no | order stays. Result holds `sent`, oid, user, side and the text `opp` when `sent` is the capped top, else `limit` |
| `0x8000000000000000` | insert error | second row with status from table `0x6f1668` (`11 12 12 05 06 15 16 16`, index 2 for a plain word), relation words cleared, order removed |
| other | insert result | sizes and notionals added up, order removed |

When the gate says yes, the firing:

1. clones the item vector of the order three times;
2. calls the cap test `0x3713f20` through slot `0x5773a48`;
3. builds the 0xa8 byte open order record with `0x43029d0`, and appends a 0x278 byte row with words 3 and 2 and status 3;
4. builds the insert request (`fields`, `insert_request`) and calls insert with flag 0. The price field is `limit` when byte +0xb0 is set, else the stored limit +0x80. Note the request takes `limit`, not `sent`. Word +0x88 is replaced by block time in ms. Byte +0xcc is 2 minus the cap flag.

After an insert result with fills, the firing adds fills `+0x210` and `+0x218` (stride 0x238), saturating, with a recorder call on overflow. If mid times the first total is above 0 and at most `0x7ffffffffffffffe`, it computes second total / product - 1, negated for side 1. Above 0.01 it calls slot `0x576f488`, whose target `0x14385c0` only runs a lazy static. A second total at or above 2^63 reaches a panic arm first. The ratio changes no state on this path.

The removal, on every path that found the user:

```
0x4946940 removes the oid from field u
if no resting order has the oid (hash table at book +0x28): 0x342a600(book +0x48, user)
if the remove found an order:
    per-user word +0x20 in map state +0x11c0 falls by 1, stopping at 0
    0x4935be0(changed map value for the user, 0, asset); the entry is inserted first if absent
    the removed item vector is freed
```

After an insert error, `0x430d380` looks up the order's relation record and zeroes its word `+0x20`. If the tag was 1, it looks up the parent oid at `+0x28` and zeroes that word too.

The wrapper adds the book lookup `asset / 10000` and `asset % 10000` with strides 0x138 and 0xd8, a depth word at state `+0x58` raised and lowered around the run, both saturating, and one flush of the rows.

### Order value

The 0xb8 byte value of field `u`, keyed by oid (`fields`, `order_value`). Node shape: parent `+0x000`, keys `+0x008`, values `+0x060`, parent index `+0x848`, length `+0x84a`, edges `+0x850`.

| Offset | Meaning |
| --- | --- |
| `+0x00/+0x08` | optional size |
| `+0x10` | byte, nonzero skips selection |
| `+0x30/+0x38/+0x40` | item vector |
| `+0x48/+0x50` | tag dword, 0x20 bytes |
| `+0x70` | 0x10 bytes |
| `+0x80` | stored limit price |
| `+0x90` | reduce only byte |
| `+0x91/+0x92` | tag byte, 0x10 bytes |
| `+0xa2` | side byte |
| `+0xa8` | trigger price |
| `+0xb0` | market byte |
| `+0xb1` | stop byte |

### Against the reference

| Reference | Claim | Observed | Verdict |
| --- | --- | --- | --- |
| `l1/` (whole tree) | no `user_states`, no `untriggered_orders`; `l1/book/book/mod.rs:130` only has an `is_trigger` flag | selection and firing read field `u` of `user_states` | missing in the reference |
| `l1/books.rs` | no step from a mark update to a stored order | `0x4cf37f0` runs the selection per book after the update | missing in the reference |

### Inferences

- Side 0 is buy and side 1 is sell: a buy limit above the trigger, a position that is long closes with side 1.
- Byte `+0xb1` 1 is stop, from the fire test and from the view packet's reading of the same byte. Byte `+0xb0` is market: it replaces a stored limit.
- The host is the oracle update of one dex: it holds a minimum 2.5 s gap per dex and runs before the selection. The name is not in the binary at this site.
- The ratio above 0.01 looks like a slippage log whose text was compiled out.

### Unresolved

- What sets byte `+0x10`. Firing does not read it, so only selection honours it.
- The meaning of the user byte `+0x3c` and the state bytes `+0x5b0`, `+0x5b1`, `+0x454b`.
- What the set at state `+0x1320` is used for.
- Why insert gets `limit` while the gate saw `sent`. The two differ only when the opposite best is inside the limit.

## Implementation and comparison

Rust implementation: not yet implemented.

The comparison here is the real bytes against a separately written Python specification (`selection`, `firing`, `wrapped`). Each run compares the ordered log of every edge call with its arguments, the result words and text, the insert request fields, each event row, relation words, the count word, the depth word, and a leak check over all allocations. A stub raises on a wrong book, state or field address.

## Results and limitations

| Metric | Value |
| --- | --- |
| Cases | 1097 |
| Mismatches | 0 |
| Instructions stepped | 710,744 |
| Stepped / total: selection: which orders fire | 442 / 542 |
| Stepped / total: selection: short sort by size | 45 / 47 |
| Stepped / total: selection: rows shrink to 0x20 bytes | 98 / 122 |
| Stepped / total: firing of one order | 1057 / 1217 |
| Stepped / total: wrapper: book lookup, depth word, flush | 109 / 138 |
| Stepped / total: second copy of the selection | 442 / 542 |
| Stepped / total: second copy of the firing | 1057 / 1217 |
| Stepped / total: second copy of the wrapper | 109 / 138 |
| Stepped / total: third copy: wrapper and firing in one function | 1140 / 1336 |
| Mutants killed / survived / unreached | 612 / 46 / 92 |

Each surviving or unreached row has its reason in `mutations.tsv`. Unreached rows are allocator failure arms, panic arms, unwind pads and the 8 step descent loops. Three rounds of survivors drove the case list: rows that hid a size behind the dropped sort key, spare keys that stopped a mutated scan, and date rows that a sample missed. Rows marked "not probed one by one" have no reason beyond the failed attempt to show a difference.

Limits:

- `0x3714e70` (rows in #184 and #697), `0x4311140` (#47, #763 and others), `0x43029d0` (#486, #491), `0x42c7600` (#36 and others), `0x4a07680`, `0x4a078a0`, `0x430d380`, `0x3713f20`, `0x36f57f0` are stubbed. `0x4946940` and the map helpers are stubbed although they have no row in any PR: tree removal is not checked here.
- Mutants run on first copies only, at most 150 reached cases each. A row that survives may be killed by a case that was not picked.
- `0x42ff010`, `0x4d44470`, `0x4cf37f0`, `0x27371f0` and their siblings appear in inventory or caller rows of other packets, for other questions. No packet states this rule.
- Years up to a date word step of one day inside a year are built. A mark row at a year boundary is not run.
- The side byte is run with 0 and 1 only. Other values take odd arms that the type should not allow.

No progress gate is requested.

Next question: what do the routes by user byte `+0x3c` reserve around a firing (`0x46efb70`, `0x46ef4a0`, `0x46ea0b0`), and who sets that byte?
