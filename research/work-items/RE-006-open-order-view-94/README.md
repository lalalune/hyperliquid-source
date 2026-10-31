# RE-006: the open order view record: resting and trigger builders, spot and perp, child lookup

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inference and unresolved items are marked.
- Scope included and excluded: included are ten whole functions: resting builders `0x42fbcb0` (spot) and `0x42fc2f0` (perp), trigger builders `0x4302380` (spot) and `0x43029d0` (perp), child lookups `0x4338ec0` and `0x43391a0`, child collectors `0x487b000` and `0x4870250`, the spot trigger text `0x49e7f50` and the order type text `0x327b890`. The outcome id walk `0x3729660` and the hash `0x399c4a0` run as real helpers and get no mutants. `0x3729660` is a call target row in open #320, which asks another question. The JSON writer `0x2a2c240` runs once, to name the fields. Excluded are the hosts that call the builders, the field writers below `0x2a2c240`, and the insert code that writes these orders. Stubs are allocation, copy, compare, `alloc::fmt::format`, vector growth and the panics; their arguments are compared.

## Reproduce

From the repository root:

```
python3 tools/open_order_view.py --out research/work-items/RE-006-open-order-view-94
python3 -m unittest tests.test_open_order_view
```

The tool takes about 40 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `order_types.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`). Field maps are in `fields`.

### Record names come from the writer

`0x2a2c240` is run with every field writer stubbed. In call order it gives the name, the record offset and the writer of 16 fields (`json_writer`):

| Field | Offset | | Field | Offset |
| --- | --- | --- | --- | --- |
| `coin` | `+0x00` | | `triggerPx` | `+0x80` |
| `side` | `+0x90` | | `children` | `+0x30` |
| `limitPx` | `+0x60` | | `isPositionTpsl` | `+0x92` |
| `sz` | `+0x68` | | `reduceOnly` | `+0x93` |
| `oid` | `+0x70` | | `orderType` | `+0x48` |
| `timestamp` | `+0x78` | | `origSz` | `+0x88` |
| `triggerCondition` | `+0x18` | | `tif` | `+0xa5` |
| `isTrigger` | `+0x91` | | `cloid` | `+0x94` |

The record is `0xa8` bytes, the stride of the child vector. `0x29fa870` writes `side` as `0x42 - byte` (bytes `b1 42 40 28 e9` at `0x29fa935`), so byte 0 is `B` and byte 1 is `A`.

### Builders

Each builder takes the book, the order, and the meta block. Prices and sizes are `u64` turned into `f64` and divided by one row of the table at `0x6f7470`. A zero size stays exact 0.0.

| | Spot | Perp |
| --- | --- | --- |
| Book `+0xb0` | spot index, tested against meta `+0x170`, panic `spot_meta.rs:565` | asset; `asset / 10000` must equal meta `+0x30` and `asset % 10000` be below meta `+0x10`, else panic `perp_meta.rs:194` |
| Size power | base token `+0x48` | row `+0x2a` |
| Price power | quote token `+0x49` minus base token `+0x48`; below 0 panics at `spot_meta.rs:984` | `6 - row +0x2a`; above 6 panics at `perp_meta.rs:319` |
| Rows | base or quote past meta `+0x188`: panic `spot_meta.rs:113` | row stride `0x30` |

Only base `+0x48` and quote `+0x49` are read: a base token's own `+0x49` has no effect (`spot resting own wei is not read`).

Coin text:

- Perp: a copy of the row name, `+0x08`/`+0x10`. The empty name gets pointer 1 and no allocation.
- Spot: `0x3729660` looks the base token up in the map at meta `+0x70`, then the id in the map at meta `+0xd0`. A match on the first token at entry `+0x28` gives tag 0, on the second at `+0x50` tag 1, and then the coin is `#` and `10 * id + tag`. That number saturates, and is capped at `2^64 - 1 - 10^8`.
- Otherwise spot index 0 is the 9 bytes `PURR/USDC`, an index below `10^8` is an at sign and the index (`[at]1` in `evidence.json`), and a higher index is `#` and `index - 10^8`.

An outcome match wins over index 0.

### Resting and trigger fields

| Field | Resting (slab slot) | Trigger (tree value) |
| --- | --- | --- |
| `limitPx` | `+0xa0` | `+0x80` |
| `sz` | `+0xc8` | `+0x08` if tag `+0x00` is nonzero, else 0.0 |
| `origSz` | `+0xd0` | the same value as `sz` |
| `oid` | `+0xd8`, the stored word | the id it was looked up with |
| `timestamp` | `+0xa8` | `+0x88` |
| `side` | `+0xc2` | `+0xa2` |
| `reduceOnly` | `+0xb0` | `+0x90` |
| `cloid` | `+0xb1`, 17 bytes | `+0x91`, 17 bytes |
| `isTrigger` | 0 | 1 |
| `triggerPx` | 0.0 | `+0xa8` over the price power |
| `isPositionTpsl` | `+0xf4` | low byte of tag `+0x00`, xor 1 |
| `tif` | `+0xf5` | constant 5 |
| `triggerCondition` | `N/A` for order type word 0 or 1, else `Triggered` | `Price above x` or `Price below x` |
| `orderType` | text of `+0x90` | text of `+0x70` |
| `children` | ids at `+0x58`/`+0x60`, user `+0xe0` | ids at `+0x38`/`+0x40`, the caller's user |

`below` is used when the side byte equals byte `+0xb1`, else `above`. Spot does this in `0x49e7f50`, perp inline at `0x4302c28`, both with the template `Price {} {}` at `0x1e5332`. `x` is the same double as `triggerPx`, through `0x38033f0`, which forwards to `0x1571d50`.

Order type words (`0x327b890`, table `0x581f98`, 10 arms, `order_types.tsv`): 0 Limit, 1 Market, 2 Take Profit Market, 3 Take Profit Limit, 4 Stop Market, 5 Stop Limit, 6 Vault Close, 7 Spot Dust Conversion, 8 Borrow Liquidation, 9 Twap Slice. The word after it at the slab or tree (`+0x98`, `+0x78`) is passed in `rdx` and never read.

So a resting Twap Slice, Vault Close or Spot Dust Conversion also says `Triggered`. Words of any type above 1 do, because the test is the dword against 2.

### The power table

`0x6f7470` holds 256 `f64` rows, `10^0` to `10^255`, and the next word is not a power (`powers`). The spot difference is a `u8`, so it needs no bound check, and the code has none. Rows 0 to 24 are the nearest doubles to their powers. Row 25 is `0x45208b2a2c280290`, which is not, and 61 of the 256 rows are. A row that high needs token decimals 25 apart, and this packet does not show that any token has them.

### Child lookup

`0x487b000` and `0x4870250` walk a slice of ids, call their lookup for each, skip a missing one, and keep order. First allocation `0x2a0`, four rows; then growth at a full vector. A list with no match gives the empty vector (cap 0, pointer 8).

The lookups `0x4338ec0` and `0x43391a0` are called only by these collectors, and the collectors only by the builders (`call_sites.tsv`). Steps:

1. Search book `+0xb8` for the user: keys of 20 bytes at node `+0x378`, length `+0x456`, edges `+0x458`, compared by memcmp.
2. In that user's tree, search for the id: `u64` keys at node `+0x08`, values of `0xb8` bytes at `+0x60`, length `+0x84a`, edges `+0x850`. A hit goes to the trigger builder.
3. Otherwise, if book `+0x40` is not 0, probe the table at book `+0x28`. The hash is `rol(id * 0xf1357aea2e62a9c5, 20)`. The entry gives a slot.
4. A slot at or past book `+0x10`, or with dword 2, gives none. Otherwise the resting builder runs on the slot at stride `0xf8`.
5. None is the first word `0x8000000000000000`, with nothing else written.

So a trigger wins over a slab order with the same id. A resting parent looks children up with the user stored in the parent, a trigger parent with the user it was given (`test_stored_user_reads_the_child`).

### Twins

`0x43391a0` matches `0x4338ec0` and `0x4870250` matches `0x487b000`, instruction for instruction, apart from call targets (`twins`). So both pairs are one source for two markets.

### Results

| Measure | Value |
| --- | --- |
| Cases | 600 |
| Mismatches | 0 |
| Instructions stepped | 349,199 |
| Stepped / total: spot resting builder | 274 / 320 |
| Stepped / total: perp resting builder | 209 / 238 |
| Stepped / total: spot trigger builder | 273 / 318 |
| Stepped / total: perp trigger builder | 252 / 286 |
| Stepped / total: spot child lookup | 177 / 179 |
| Stepped / total: perp child lookup | 177 / 179 |
| Stepped / total: spot child collector | 103 / 122 |
| Stepped / total: perp child collector | 103 / 122 |
| Stepped / total: spot trigger condition text | 53 / 61 |
| Stepped / total: order type text | 103 / 124 |
| Stepped / total: outcome id of a token, helper | 124 / 125 |
| Stepped / total: SipHash of one u64, helper | 86 / 86 |
| Stepped / total: hasher write, helper | 56 / 141 |
| Mutants killed / survived / unreached | 618 / 32 / 35 |

Unstepped instructions are allocation failure arms, unwind pads and padding.

### Reference comparison

`reference_claims` in `evidence.json` lists each row. The reference has `RestingOrder` names without these offsets, no order type names, and no record or text of this kind.

## Inferences

Kept apart from the observations:

- The 16 names are the open order view that info clients see, and word 5 in `tif` means no value for a trigger. The writer is proved, the reader outside the node is not.
- Trigger byte `+0xb1` is 0 for a take profit and 1 for a stop: with side 0 as buy, that gives a buy take profit below and a buy stop above. `0x49e8090` writes the same shape of byte as `tp` or `sl`, read as one byte, but this packet does not prove that the same field reaches it.
- `0x1571d50` is `Display for f64`. It reads the double, tests a precision flag, and passes minimum precision 0. The evaluator's stub prints shortest digits with no exponent on that basis, so the text in tests assumes it. The double itself is compared by its bits.
- `#` numbers are the outcome coin names.

## Implementation and comparison

not yet implemented. The evaluator runs the real bytes against a separate Python specification. A mutant survives only with a stated reason in `mutations.tsv`.

## Results and limitations

- Worlds are built by the harness from shapes read in the code. Live state was not read.
- `alloc::fmt::format` is stubbed: template bytes and argument functions are read and checked, but the float digits come from the Python stub.
- The field writers below `0x2a2c240` were not read, so JSON text shapes are not shown, nor is the meaning of `tif` 5.
- The hosts in `call_sites.tsv` were not read. Sites inside the 8 insert functions pinned by open #47 are counted, not listed.
- Every surviving or unreached mutant has a stated reason in `mutations.tsv`.
- No Rust code, and no progress gate is requested.

Next question: what do the builders' hosts `0x42ff010` and `0x4300950` return, and is the record the one `0x29f4fd0` writes for an info reply?
