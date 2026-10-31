# RE-006: order request to open order record: type word, time, child rows, spot and perp

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inference and unresolved items are marked.
- Scope included and excluded: included are four whole functions: request builders `0x42fe970` (spot) and `0x42fe2d0` (perp), and child row maps `0x47f6950` and `0x47f7960`. The record builders below them (`0x42fbcb0`, `0x42fc2f0`, `0x4302380`, `0x43029d0`), the type text `0x327b890` and the outcome walk `0x3729660` run as real helpers with no mutants. Excluded are the hosts in `call_sites.tsv` and the writers of a request. Stubs are allocation, free, copy, compare, `alloc::fmt::format`, vector growth and the panics; their arguments are compared.

## Reproduce

From the repository root:

```
python3 tools/order_request_view.py --out research/work-items/RE-006-order-request-view-94
python3 -m unittest tests.test_order_request_view
```

The tool takes about 140 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `order_types.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`). The output is the `0xa8` record that the builders return; field names below are the names in the writer `0x2a2c240`.

### The request

`rdi` result, `rsi` book, `rdx` request:

| Offset | Content |
| --- | --- |
| `+0x00`/`+0x08` | size option: tag, value |
| `+0x10` | word |
| `+0x18` | byte m |
| `+0x19` | byte k |
| `+0x20` | limit price |
| `+0x30`, `+0x31` | side, reduceOnly |
| `+0x32` | cloid, 17 bytes |
| `+0x48` | 0x28 bytes given to each child and not read here |
| `+0x70`/`+0x78`/`+0x80` | child rows: capacity, pointer, count; stride `0x48` |
| `+0x88` | meta block |
| `+0x90` | oid |
| `+0x98`/`+0x9c`/`+0xa0` | date word, seconds, nanoseconds |
| `+0xa4` | user, 20 bytes |

### Two arms

`k == 2` builds the slab order shape and calls the resting builder. Any other `k` builds the trigger shape and calls the trigger builder (`cmp al, 2` at `0x42fea71`).

| | `k == 2` | `k` not 2 |
| --- | --- | --- |
| Type word | 1 if `word & 7 == 3`, else 0 | `(2k + 3) ^ m` |
| `tif` | low byte of `word` | constant 5, from the builder |
| Trigger price | none | `word` |
| `m` | not read | type word, then kept at `+0xb0` |
| `k` | | kept at `+0xb1`, the byte the above and below test reads |
| Size | value if the tag is nonzero, else 0 | tag and value as they are |
| `isPositionTpsl` | low byte of tag, xor 1 | low byte of tag, xor 1 |

So real runs give (`order_types.tsv`):

| k | m | `orderType` |
| --- | --- | --- |
| 0 | 0 | Take Profit Limit |
| 0 | 1 | Take Profit Market |
| 1 | 0 | Stop Limit |
| 1 | 1 | Stop Market |
| 2 | any | Market for `word & 7 == 3`, else Limit |

This settles the byte the builders compare with the side: 0 is take profit and 1 is stop. With side 0 as `B`, a buy take profit reads `Price below`, and a buy stop `Price above`.

### Time

Both arms turn the date, seconds and nanoseconds into `timestamp` in milliseconds:

```
year = date >> 13 (signed), ordinal = (date >> 4) & 0x1ff
days = days from common era - 719163
t = (days * 86400 + seconds) * 1000 + floor(nanos / 1000000)
timestamp = t if t > 0 else 0
```

That is, 1970 day 1 at 0 gives 0, and anything before gives 0 too. Nanoseconds up to `1999999999` run, so a leap second adds up to 1999 ms (`test_leap_second_nanos`). The calendar is checked for 25 years, from `-262143` to `262142`.

### Child rows

`0x47f6950` and `0x47f7960` map the rows to a vector of records, with exact capacity. Each row is only the first `0x48` bytes of a request. The other bytes come from the parent: note block, meta, oid, date, seconds, nanoseconds, user. So:

- A child's `oid` and `timestamp` are the parent's.
- A child has no children of its own: its child vector is empty.
- A child row with `k == 2` and one with `k` not 2 can sit under the same parent.

The vector built by the record builder is replaced by this one. The row buffer is then freed by capacity, not count (`test_room_is_freed_by_capacity`), even with no rows.

### Twins

`0x42fe2d0` matches `0x42fe970`, and `0x47f7960` matches `0x47f6950`, instruction for instruction, apart from call targets (`twins`).

### Results

| Measure | Value |
| --- | --- |
| Cases | 284 |
| Mismatches | 0 |
| Instructions stepped | 209,624 |
| Stepped / total: spot request builder | 284 / 333 |
| Stepped / total: perp request builder | 284 / 333 |
| Stepped / total: spot child row map | 133 / 166 |
| Stepped / total: perp child row map | 133 / 166 |
| Stepped / total: spot resting builder, helper | 239 / 320 |
| Stepped / total: perp resting builder, helper | 198 / 238 |
| Stepped / total: spot trigger builder, helper | 237 / 318 |
| Stepped / total: perp trigger builder, helper | 249 / 286 |
| Mutants killed / survived / unreached | 198 / 96 / 34 |

Unstepped instructions are unwind pads, allocation failure arms and a drop loop for a vector that is always empty here.

A large share of the survivors have one cause: a child has no children, so the user it is given is never read, and the note block is never read at all. `mutations.tsv` has the reason for each row.

### Reference comparison

`reference_claims` in `evidence.json` lists the row. The reference has no path from a request to these records.

## Inferences

Kept apart from the observations:

- The request is a parsed order action with its grouped orders: child rows look like the TP and SL legs of an order. A writer of a request is not read here.
- `word & 7 == 3` is the frontend market tif, by the reference's raw list in `l1/book/book/impl_insert_order.rs:77`, where 3 is `FrontendMarket`. That list has 5 values, and the mask keeps 3 bits.
- `m` is a market flag, by the text it selects.

## Implementation and comparison

not yet implemented. The evaluator runs the real bytes against a separate Python specification. A mutant survives only with a stated reason in `mutations.tsv`.

## Results and limitations

- Worlds and requests are built by the harness from shapes read in the code. Live requests were not read.
- `k` above 2 is not run: its type word would leave the 10 row table, and no writer is read.
- What the note block holds is unresolved.
- Float digits in `triggerCondition` come from a Python stub; doubles are compared by bits.
- Every surviving or unreached mutant has a stated reason in `mutations.tsv`.
- No Rust code, and no progress gate is requested.

Next question: what do the hosts `0x4308460`, `0x430abf0`, `0x4309700` and `0x430be90` do with these records?
