# RE-006: queued rows after a second insert: drivers, row tests, fill turn, leg update, fill totals

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inference and unresolved items are marked.
- Scope included and excluded: included are 14 whole functions: drivers `0x24f8f80`, `0x43292e0`, `0x4329560`, row walks `0x47f4fc0`, `0x47f50d0`, row tests `0x24f92e0`, `0x47d6f80`, `0x47d7150`, fill gate `0x4472550`, leg copy `0x47c39b0`, fill turn `0x3790200`, leg update `0x3c18540`, fill totals `0x24f8d90`, `0x47d6d90`. Excluded are the hosts `0x26d2560`, `0x4d12e80`, `0x4d15710` and the inserts they call, read here only by hand for context. Stubs, with their arguments compared: record builders `0x26e16f0`, `0x42fe970`, record clones and drops, row drops, sibling record `0x37272c0` (open #475), class `0x3728670`, the amount function behind slot `0x5774768`, the recorder behind slot `0x5773190`, copy and the panics.

Some subject functions have one call site row in other packets on other questions: `0x24f92e0`, `0x3790200` and `0x4472550` in #475 as callers of `0x37272c0`, `0x24f8d90` and `0x3c18540` in #234 as recorder sites, `0x43292e0` and `0x4329560` in #491 as callers of the request builder. Those packets do not read them.

## Reproduce

From the repository root:

```
python3 tools/queued_row_rewrite.py --out research/work-items/RE-006-queued-row-rewrite-94
python3 -m unittest tests.test_queued_row_rewrite
```

The tool takes about 30 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `row_actions.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`). Field maps are in `fields`. `call_sites.tsv` comes from E8, E9 and FF 15 byte scans.

### Where the drivers run

Each driver has one site: `0x26d574b` in `0x26d2560`, `0x4d14828` in `0x4d12e80`, `0x4d170b8` in `0x4d15710`. Read by hand in the first host:

```
26d472f  call 26e5760            first insert; rows go to the vector at rsp+0x4c0
26d527a  call 26e5760            second insert, book index rsp+0xd0
26d5385  xor eax,eax             nothing rests: no new id
26d56a5  mov eax,0x1             new id present
26d56b4  cmp [rsp+0x28],rcx      skip the driver if the first insert gave the None word
26d574b  call 24f8f80            rewrite the first vector
26d577f  call 24fc8a0            flush the first vector
26d57b1  call 24fc8a0            flush the second vector
```

`host_bytes` in `evidence.json` pins the bytes of the three tests.

### Driver block

`rdi` row vector (capacity, pointer, length), `rsi` block:

| Offset | Content |
| --- | --- |
| `+0x00`/`+0x08` | new id option: tag, value |
| `+0x10` | request, the shape in open #491 |
| `+0x18` | state |
| `+0x20` | 16 bytes, handed on by address |
| `+0x30` | old id |
| `+0x38` | `f64` to add |
| `+0x40` | user, 20 bytes |

Steps:

1. Book index is request `+0x28`. At or past the book count: bounds panic at `l1/src/books.rs:14`. Books have stride `0xd8` at state `+0x3388`/`+0x3390` in the first and third copies, and `+0x3e08`/`+0x3e10` in the second.
2. Chosen id: the new id if the qword tag is nonzero, else the old id.
3. A new `0xa8` record is built by the request builder. Its block copies the request, with an empty child list (capacity 0, pointer 8, length 0), meta at state `+0x90`, the chosen id, 12 bytes of time from state `+0x60` and the user.
4. Every row is tested in order. A row that fails is dropped and later rows move down. The length is written only if a row went.
5. The new record is dropped.

### What each row kind does

Kind is word `+0x00` minus 2, and 7 for words 0 and 1. Real runs of all three copies, with the old id at every field read (`row_actions.tsv`):

| Word | Kind | Action |
| --- | --- | --- |
| 0, 1, 2, 4, 5, 6, 7, 9, 10 | 7, 0, 2 to 5, 7, 8 | Kept, unchanged |
| 3 | 1 | Order row |
| 8, and 11 up | 6, and 9 up | Fill row |

The mask `0x1bd` at `0x24f9307` is the kept list.

### Order rows

Inner word `+0x08`, minus 2, or 1 for words 0 and 1: inner 0 has a record at `+0x38` and flag `+0x100`, inner 1 a record at `+0x30` and flag `+0x119`. Other inner words are kept as they are.

1. If record `+0x70` (`oid` in open #486) is the old id: the new record is cloned over it, the old record is dropped, and `+0x68` (`sz`) becomes the old `sz` plus the block's `f64`.
2. Then, if the low **byte** of the new id tag is nonzero, and record `+0x70` is the new id, and the flag byte is 1: the row goes. So a row that took the new record goes on the same pass, and so does a row that already had the new id.

A flag of 2 stays. A tag of `0x100` picks the new id in step 2 of the driver and skips the removal here (`test_low_byte_of_the_tag_decides_the_removal`).

### Fill rows

Byte `+0x23a` against request `+0x30`:

- Equal: no turn.
- Different: with amount `+0x230` nonzero, the sibling record of spot `+0x1f8` is read. An error, a token list length other than 1, or `value <= amount` leaves the row as it is. A token past the rows panics at `l1/src/spot_meta.rs:113`. Otherwise the row goes through `0x3790200` with a turned amount of `value - amount`, or 0 for a zero amount. Options in the two legs are made regular on the way: `image_view` lists what is handed on.

A result tag below 2 replaces the two legs and these fields, and flips the side:

| Row | Result |
| --- | --- |
| `+0x1f8` | `+0x1f8`, new spot |
| `+0x200` | `+0x1f0`, turned price |
| `+0x208`, `+0x210` | `+0x200`, `+0x208` |
| `+0x218` | `+0x210`, zero |
| `+0x220`, `+0x228`, `+0x22c` | `+0x218`, `+0x220`, `+0x224` |
| `+0x230` | turned amount |
| `+0x23a` | side xor 1 |

Then, turned or not, on either side: words `+0xd0` and `+0x1c8` (leg `+0xc8`) that equal the old id take the chosen id. Result tags 2 and 3 leave the row, and these ids still move.

`0x24f92e0` holds all this inline. `0x47d6f80` and `0x47d7150` reach it through `0x4472550` and `0x47c39b0`. Both give the same rows on all cases, except padding bytes `+0x22d..0x22f` and from `+0x25c`, which a stack copy leaves stale.

### Fill turn, `0x3790200`

`rdi` result, `rsi` spot meta, `rdx` fill image (the row from `+0x08`), `rcx` the 16 byte pair or 0. Image `+0x1f0` spot, `+0x1f8` price, `+0x200` size, `+0x224` side. The result is tag 2 for no turn, tag 3 with a code byte at `+0x08`, or a turned image.

| Order | Test | Result |
| --- | --- | --- |
| 1 | price 0 | code 9 |
| 2 | spot past the list | bounds panic `spot_meta.rs:565` |
| 3 | class of the spot word below 2 | tag 2 |
| 4 | sibling record error | that code |
| 5 | token past the rows | panic `spot_meta.rs:113` |
| 6 | token book list length not 1 | code 0 |
| 7 | `value < price`, `value == price` | code 8, code 9 |
| 8 | book in the list past the spot list | bounds panic `spot_meta.rs:565` |
| 9 | leg update stopped, first leg then second | its code |
| 10 | `turned * size` overflows or exceeds `2^63 - 2`, or second tag 2 | code `0x11` |

The turned image swaps the two legs, and has price `value - price`, spot = the book from the token list, size unchanged, `+0x208` = `turned * size`, `+0x210` = 0, `+0x218..+0x223` copied, side xor 1. For `value 10^8`, price `6 * 10^7`, size 25 and side 1 it gives price `4 * 10^7`, notional `10^9` and side 0 (`worked_examples`).

The bound at step 8 uses the same Location as step 2. All four FF 15 sites are in `call_sites.tsv`. At the two row test sites `rcx` is an address, so the `rcx == 0` arm is not reached from them. Cases run it directly.

### Leg update, `0x3c18540`

Called only from `0x3790200`. Side byte 0 updates the first leg and keeps the second. Any other side updates the second and keeps the first. The update, with the pair `(p0, p1)`:

1. `amount` comes from slot `0x5774768` on (meta, sibling word, size). Flag bit 0 clear: the leg gets tag 2, code `0xb`.
2. Flipped side nonzero: `p0 -= amount`, and if that would go below 0 then `p0` stays, with nothing recorded. Flipped side 0: `p0 += amount`, saturating, with a recorder call.
3. `size * price` overflowing or above `2^63 - 2`: tag 2, code `0xc`. `p0` has already moved.
4. Side 1: `p1 -= product`, kept on a borrow. Other sides: `p1 += product`, saturating. The side 1 test is byte `== 1`, so side 2 updates the second leg but adds.
5. The leg gets tag 1, and its byte `+8` and next 15 bytes take the pair as it was **before** the update. The rest of the leg is kept.

### Fill totals, `0x24f8d90`, `0x47d6d90`

`rdi` result, `rsi` rows, `rdx` count, stride `0x228`. Sums of `+0x200` and `+0x208` saturate, each with a recorder call (`l1/src/qtys/mod.rs:827` and `:829`). All `+0x1f8` must match; the sums of a row are added before its key is tested. The result is none for no rows, a key mismatch, a first sum of 0, or a first sum above the second. Otherwise `(second / first, first, second, key)`, floored.

At `0x26d4d8e` the host reads this as: some gives `size - first`, floored at 0, and none gives the whole size. Hand read.

### Copies

`evidence.json` `twins`: `0x4329560` matches `0x43292e0` apart from the row walk target and two book offsets. `0x47f50d0` matches `0x47f4fc0`, `0x47d7150` matches `0x47d6f80`, and `0x47d6d90` matches `0x24f8d90`, apart from rip words.

### Reference comparison

`reference_claims` in `evidence.json` lists each row. The replace flow in `l1/exchange/handlers/12_modify.rs` has no step that rewrites queued rows. No price turn of a fill exists in the tree. The row size 616 and fill size 552 do appear there as bare sizes.

## Implementation and comparison

Rust: not yet implemented. The evaluator, the specification in the tool and the tests are the only comparison.

## Inferences

Kept apart from the observations:

- The hosts place an order on an outcome token in two steps: first on the sibling book with the side flipped (`xor r9b,1` at `0x26d2ad2`, stored into the request at `0x26d3725`), then the rest on the asked book. The driver then makes the first insert read as if it had been on the asked book. The bytes show the two inserts and the rewrite. They do not show this purpose.
- Fill row: two legs of `0xf8`, one per user, and `+0x1f8`, `+0x200`, `+0x208`, `+0x210` as spot, price, size and notional. The product in the turn is the basis. Other kinds of row are not named here.
- `value` is the sum of the two outcome prices, so `value - price` is the complement price, by the merge in open #475.
- Leg `+0xc8` is an order id, because it is compared with the old id. The pair is a running position or balance, and the leg's bytes `+8` are its value before the fill.
- In the totals, `+0x1f8` is the price, `first` size and `second` notional, by the same offsets in the image. That the `0x228` rows have the image's shape is not proved here.
- Kind 1 rows are order status rows, and the two inner shapes are their two states.

## Results and limitations

| Measure | Value |
| --- | --- |
| Cases | 913 |
| Mismatches | 0 |
| Instructions stepped | 190,514 |
| Stepped / total: driver, first copy | 166 / 188 |
| Stepped / total: row test, first copy | 450 / 457 |
| Stepped / total: driver, second copy | 124 / 130 |
| Stepped / total: row walk, second copy | 61 / 78 |
| Stepped / total: row test, second copy | 108 / 115 |
| Stepped / total: driver, third copy | 124 / 130 |
| Stepped / total: row walk, third copy | 61 / 78 |
| Stepped / total: row test, third copy | 108 / 115 |
| Stepped / total: fill gate, second and third copies | 171 / 171 |
| Stepped / total: leg copy | 105 / 105 |
| Stepped / total: fill turn | 218 / 218 |
| Stepped / total: leg update | 219 / 224 |
| Stepped / total: fill totals, first copy | 122 / 122 |
| Stepped / total: fill totals, second copy | 122 / 122 |
| Mutants killed / survived / unreached | 821 / 20 / 18 |

Unstepped instructions are unwind pads and one dead arm in `0x3c18540`: `0x3c18766` tests a side of 1 on a path that needs side 0.

- Every surviving or unreached mutant has a stated reason in `mutations.tsv`.

- Survivors fall into four causes, all in `mutations.tsv`: one more byte copied into dead space, word 2 changing to another kept kind, a 32 bit divide shortcut, an unused cursor word.
- Worlds are built by the harness from shapes read in the code. No state from a real node is used.
- Fields of the two legs other than those named are carried as bytes.
- The class function, the amount function and the sibling record are stubs here. Their values reach these functions only through the stubs.
- The hosts are read by hand, so what they pass in, and when the first vector holds which rows, is context rather than a result.
- `0x2512ad0` and `0x444d7d0` also call `0x3790200` and are not read.

No progress gate is requested.

Next question: what does `0x2512ad0` do with the first insert's fill list in the same host, and does a failed turn there stop the order?
