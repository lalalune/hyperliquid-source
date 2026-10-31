# RE-006: price band and size for the spot sell path: 0.98 high, a stepped low factor, tick rounding, account words

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included is the whole function `0x37344a0`, with mutants, and the real round `0x565f410` it calls, with no mutants. Stubbed at the edge, with arguments compared: price `0x3594ec0`, tick `0x36f3350`, scale `0x333e310`, rescale `0x32813d0` and the 128-bit divide. Excluded: those helpers' bodies, and what the second path does with the result.

## Reproduce

From the repository root:

```
python3 tools/spot_sell_price_band.py --out research/work-items/RE-006-spot-sell-price-band-94
python3 -m unittest tests.test_spot_sell_price_band
```

The tool takes about 20 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. The function end comes from its FDE. `0x37344a0` is reached only through slot `0x5774778`, from three call sites, in the spot order functions `0x4c21720`, `0x4c21230`, `0x26d2070` (`call_sites.tsv`). Those functions use its five result words; this packet shows how the words are made.

Arguments: `rdi` result, `rsi` account, `rdx` spot, `rcx` base token, `r8` quote token, `r9` a map, first stack word meta. The result is: tag, x, low, high, last.

### Order of the steps

The first step that stops decides the result. Tag 2 means nothing to do. Tag 3 has a code in the byte at `+8`.

| # | Step | Stop |
| --- | --- | --- |
| 1 | base and quote rows exist in the map (`[r9+8]` root, `[r9+0x10]` height, value stride `0xb0`) | tag 3, code 9 |
| 2 | base row byte `+0` is nonzero | tag 2 |
| 3 | `p = 0x3594ec0(base +0x10, quote +0x10, quote, meta)` is nonzero | tag 2 |
| 4 | high price, low price | none |
| 5 | quote entry exists in the account tree (`+0x18`, `+0x20`, stride `0x20`) | tag 2 |
| 6 | `c = ceil(entry +8 * quote row +0x58 / 1e14)` fits a word | tag 3, code 3 |
| 7 | base entry exists in the same tree | tag 2 |
| 8 | first scale call succeeds | tag 3, code 3 |
| 9 | base row `+0x78` is nonzero | tag 3, code 6 |
| 10 | `need = ceil(v * 1e14 / row +0x78)` fits a word | tag 3, code 3 |
| 11 | `(entry +0x18 - need, floored at 0) * row +0x78 / 1e14` fits a word | tag 3, code 3 |

The base entry's `+0x18` and the quote entry's `+8` are the two account words read. The map row is read in `0xb0` steps and the account tree in `0x20` steps (`fields`).

### Prices

```
high word = round(0.98 * f64(p)), cast to u64, 1 if that gives 0
high      = (floor(word / tick) + 1) * tick, capped at u64::MAX

r(u) = floor(3e14 * u / (1e14 + 2u))    for u < 5e13
r(u) = floor((u + 2e14) / 3)            for u >= 5e13
low factor = (r(u) / -1e14 + 1) * -0.9 + 1
low word  = round(low factor * f64(p)), cast the same way
low       = min((floor(word / tick) + 1) * tick, high)
```

`u` is base row `+8`. `tick = 0x36f3350(meta, spot, word)` is asked once per word. Round is half away from zero, by adding `0.49999999999999994` with the sign of the value, then truncating. The cast saturates, and only an infinity gives 0.

An exact multiple of the tick still moves up one tick. So with price 1000 and tick 10, the high word 980 gives 990. `low` is never above `high`.

The low factor at round words (`curve`):

| u / 1e14 | r / 1e14 | low factor |
| --- | --- | --- |
| 0 | 0 | 0.1 |
| 0.1 | 0.25 | 0.325 |
| 0.25 | 0.5 | 0.55 |
| just below 0.5 | just below 0.75 | 0.775 |
| 0.5 | 0.8333 | 0.85 |
| 0.75 | 0.9167 | 0.925 |
| 1 | 1 | 1 |

The factor is `0.1 + 0.9 * r / 1e14`. It steps up at `u = 5e13`, because the two arms do not meet there (`test_kink_is_a_step`). `r` above `2^63` is read as signed by `cvtsi2sd`.

With price 2000000000, u 4e13, ticks 100 and 10: `low` is 1400000010 and `high` is 1960000100 (`worked_example`).

### Words

```
last = (entry +0x18 - need, floored at 0) * row +0x78 / 1e14, floor
k = 0x333e310(c, base, low, 1, meta)
if k has its flag: last = min(last, k value), x = 0x32813d0(k value, base, meta), tag 1
else: tag 0, x is the flag word
```

`v` of step 10 comes from `0x333e310(1e8, base, row +0x10, 1, meta)`. So a tag 0 result still has low, high and last.

### Results

| Measure | Value |
| --- | --- |
| Cases | 117 |
| Mismatches | 0 |
| Instructions stepped | 48,890 |
| Stepped / total: band | 436 / 438 |
| Stepped / total: round, real, no mutants | 24 / 24 |
| Mutants killed / survived / unreached | 157 / 11 / 0 |

### Comparison with the reference

A search of `l1` for `0.98` and `0.9` finds nothing, and no body of this function is there. This packet is new against it.

### Overlap

`0x37344a0` is a pair of caller rows in #403, for its use of `0x333e310`. `0x3594ec0` is a helper row in `RE-004-spot-wei-scale-family-94`. Neither reads this function.

### Inferences

These are readings of the observations above, not observations.

- `u` is the token's `ltv` in units of 1e14: the binary has the keys `ltv`, `borrow`, `supply` and text on borrows and LTV, and `1e14` is the unit here.
- `p` is the token price in quote, and `c` is the user's quote debt: `entry +8` times a quote row index.
- So the band sells between a floor that depends on the LTV, and 0.98 of the price. That shape fits a forced repay sale, not a user price choice. The text `Use market orders to repay borrows when portfolio health would fall below LTV` is in the binary, but no link to it is shown.

## Implementation and comparison

Not yet implemented in Rust. The comparison is real bytes against a specification written from an instruction read. Every stub argument and all `0x28` result bytes are compared. Tree spare key slots hold a tempting key, and filler is a non-periodic ramp. The first run had no mismatch against the specification apart from two fixtures of mine.

## Results and limitations

- Every surviving or unreached mutant has a stated reason in `mutations.tsv`.
- Survivors: each has its reason in `mutations.tsv`. They are arms that no input reaches, and masks with the same effect on every value.
- Constants in `.rodata` are not mutated; `constants` pins their bytes and they run real.
- A tick of 0 would fault in `div`. Whether `0x36f3350` can return 0 is not read.
- Stubs give words a real helper may not. Names `c`, `need`, `last`, `x` are only names here.
- Tree fixtures have height 0 and 1.

Next question: what does the second path do with low, high, last and x, and how does `0x48cac10` get the room word?
