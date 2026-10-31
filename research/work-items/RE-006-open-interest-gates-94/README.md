# RE-006: open interest gates on a price update: book total_sz in the row test, fixed limit, total gate drops the Mark list

- Component ID: RE-006 (book state transitions), through the book row read at `l1/src/books.rs:14`
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included, whole and with mutants, are the update gate `0x3709040`, the three list retain `0x3bfd3c0`, the row closure `0x3bc3630`, the size times price check `0x3708e80`, the total fold `0x3be6420` and the Mark list clear `0x3bfd1d0`. Stubbed at the edge, with arguments compared: price parser `0x3bfd7a0`, map builder `0x33167e0`, map drop `0x33f4660`, formatter, list growth, overflow recorder, free and the panic calls. Excluded: the bodies of those helpers, the six callers past their call sites, and what the price lists do after the gate.

## Reproduce

From the repository root:

```
python3 tools/open_interest_gates.py --out research/work-items/RE-006-open-interest-gates-94
python3 -m unittest tests.test_open_interest_gates
```

The tool takes about 20 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### What book field `+0xd0` is

Book rows have stride `0xd8` (`0x3bc3717`). The reference `Book` has no running size field. The book writers `0x431ea20`, `0x431eee0`, `0x431f200`, `0x431f6c0` load `+0xd0` and pass it to a field writer whose name bytes spell `total_sz`, and `+0x78` to one that spells `last_trade_px` (`serde_fields`). Both book row readers store `+0xd0` as the last field (`0x4848afa`, `0x484a9dc`).

`0x49e4f20` takes a pointer in `r8`, reads the old slot size at `+0xc8`, writes the new one, and adds new minus old to the word behind the pointer, with saturating recorders (`host_bytes`).

### The gate

`0x3709040` is reached only through slot `0x5774988`, from six call sites (`call_sites.tsv`). Arguments: `rdi` result, `rsi` owner, `rdx` wire list, `rcx` book list, `r8b` flag. Three sites pass flag 1, three pass 0.

| # | Step | Result |
| --- | --- | --- |
| 1 | Wire list length must equal owner `+0x10` | error tag `0x76`, both lengths, wire list freed |
| 2 | Parser `0x3bfd7a0` builds three price lists | a parser error is passed through |
| 3 | Run the row test on every row of the three lists, in order | failing rows leave their list, order kept |
| 4 | Stop here when owner `+0x230` is 3 | |
| 5 | Sum the notional of all assets | none: Mark list cleared, no total text |
| 6 | `0.1 * sum`, as `i64`, compared with the total cap at owner `+0x1b0` | above the cap: one total text, Mark list cleared |
| 7 | Result: the lists and the text list | |

A negative cap panics at `l1/src/qtys/mod.rs:843:1` in step 6. When step 5 gives none, the cap is not read.

### Row test

`0x3bc3630` looks the asset up in the map at owner `+0x170` (0 when absent) and reads book `total_sz` at `asset % 10000` (`l1/src/books.rs:14:16` bounds it). Then `0x3708e80` runs:

```
if book < 0 as i64: panic at l1/src/qtys/mod.rs:844:1
sum = stored + book, saturating at i64 max with record(0, impl_sz.rs:35)
fits = price >= 0 and price * sum fits i64
if mode == 3 and not (fits and product < 0x28f5c28f5c28f5d): record(1, clearinghouse.rs:554)
if fits and product < 0x199999999999999a: pass
else: text with asset, kind, product / 1e6 (0.0 when it does not fit)
```

Both limits are `2^64 / 10^n` rounded up, for `n` 1 and 2. The second limit only records, and only in mode 3. So a row with a negative price fails.

A failing row pushes two strings onto the text list: `Asset open interest exceeded cap asset={} kind={}, oi={}` and `Missing price, keeping old {} price asset={} oracle_kind={}`. Its price is then gone from that list.

The kind byte is the list number, shown by `0x3818cf0` as `Spot`, `Mark` and `External`. The source byte at list `+0x48` is shown by `0x3bddf10` as `oracle`, or `reference` for any other value.

Asset ids in texts: below 10000 as they are, up to 99899999 plus 100000, above that `0xffffffff`.

`worked_example` shows a book total at the limit dropping one asset from all three lists with zero stored size.

### Total gate

`0x3be6420` walks `dex * 10000 + index` for index up to owner `+0x10`. The price is the new Mark price when the list has one, else the signed word `+0x20` of asset row `index`, stride `0x60`, at owner `+0x68`, bound `l1/src/clearinghouse/oracle/oracle.rs:197:18`. It adds `price * stored`. A negative price, a product overflow or a sum overflow gives none. Book `total_sz` is not part of this sum.

The Mark list clear `0x3bfd1d0` pushes one `Missing price` text per row with kind 1, frees the rows and leaves an empty list. Spot and External lists are not touched.

### Layouts

`fields` in `evidence.json` lists every offset. Map node: keys at `+0x08`, values at `+0x60`, length at `+0xba`, edges at `+0xc0`.

## Inferences

- `total_sz` is the running sum of resting slot sizes in a book. This rests on `0x49e4f20` and its field name. I did not prove that every size change goes through that function, nor that the pointer is always book `+0xd0`.
- The map at owner `+0x170` is open interest by asset: the text calls the product `oi`, and the total fold multiplies the same map by price.
- If both hold, the row test is `(open interest + resting size) * price`, so resting orders can make a price row fail.
- The 1e6 divisor reads like a notional scale, which makes the row limit about 1.8e12 in notional. The binary does not name the unit.
- The flag from the call site goes only to the parser. Whether it decides the source byte (`oracle` or `reference`) is not read here.
- Mode 3 is not named here. The same byte value skips other checks in the callers (`0x4cf386b`).

## Implementation and comparison

Not yet implemented in Rust. The comparison here is byte evaluator against a written specification. The specification was written from a full instruction read and kept apart from the evaluator.

The reference labels `retain_if_under_open_interest_cap` differ from the bytes in rule and text (`reference_claims`): the bytes read no per asset cap map and have no side flag. The first full run had 0 mismatches. The first mutation pass then found harness gaps: filler keys that hid node length mutants, an unread iterator word, an unread Mark list head. These were closed with more cases and two more compared values. A unit test then showed that the total gate edge cases stopped at the length check, because their wire length was left at a default. They now reach the gate, and a test on the real bytes pins that edge.

Mutants flip each branch, `set`, `cmov`, immediate and field offset, one at a time, over the cases that reach them.

| Metric | Value |
| --- | --- |
| Cases | 328 |
| Mismatches | 0 |
| Instructions stepped | 92,769 |
| Stepped / total: update gate | 218 / 242 |
| Stepped / total: three list retain | 208 / 253 |
| Stepped / total: row closure | 156 / 172 |
| Stepped / total: size times price check | 104 / 104 |
| Stepped / total: total notional fold | 138 / 144 |
| Stepped / total: Mark list clear | 96 / 115 |
| Mutants killed / survived / unreached | 285 / 10 / 16 |

## Results and limitations

- The result is exact only for the stubbed edges. The parser, the map builder and the formatter are stubbed, so their rules are not claimed.
- The evaluator keys rows by the stub's own map. A duplicate Mark row uses the last price there, which is an assumption about `0x33167e0`.
- The 16 unreached rows are unwind landing pads. The 10 survivors each have a reason in `mutations.tsv`: finite input guards and clamp arms in step 6, the saturated sum word, and four repeated range tests in the wire step of `0x3bfd1d0`.
- Open #149 lists `0x3708e80` as one recorder site, for its add guard at `0x3708eb2`. Open #72 lists `0x3bfd1d0` for its wire step. #184 lists `0x3be6420` in an inventory. Each is a different question from the gate pinned here, and this packet does not restate those results.
- The six callers are not read past their call sites. Open #383 covers other oracle functions and no function here.
- No progress gate is requested.

Next question: which callers of `0x49e4f20` hold book `+0xd0`, and is there a size change that skips it?
