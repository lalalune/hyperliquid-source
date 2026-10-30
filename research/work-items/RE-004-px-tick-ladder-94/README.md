# RE-004: the five-significant-figure price tick ladder of node #94

- Component ID: RE-004 (quantities and rounding: `l1/qtys/impl_px.rs`, `l1/qtys/impl_sz.rs`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
- Source commit / reference commit: 6fb86319763b30860f92b9da746cbe4f9b637573 /
  references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23 (a lead only)
- Claim status: observation for the ladder, the tick functions, the panics, the status table and the
  call-site classes; inference for the price scale and the names; unresolved items are listed below.
- Scope included: the 11 functions that hold the ladder, the 54 direct calls to the 5 tick functions, and
  the status text those calls can reach. Scope excluded: what each caller does with the rounded value,
  node #115, the visor, and any Rust implementation.

## Reproduce

Working directory: repository root. Python 3 standard library and GNU objdump. The binary is never
executed; a Python evaluator interprets objdump text and stops on an unmodelled mnemonic, an unset
register, flag or memory byte, an unknown call target, or a write outside its RAM.

```
python3 tools/artifacts.py verify
python3 tools/px_tick_ladder.py --out research/work-items/RE-004-px-tick-ladder-94
python3 -m unittest discover -s tests -p 'test_px_tick_ladder.py'
(cd research/work-items/RE-004-px-tick-ladder-94 && sha256sum -c MANIFEST.sha256)
objdump -d -M intel --start-address=0x230b390 --stop-address=0x230b584 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x36f3350 --stop-address=0x36f3601 artifacts/node/94/hl-node
rg -n -A 34 'fn visible_bucket_step' references/can1357-hl/l1/qtys/impl_sz.rs
```

The tool takes about 25 s and writes `evidence.json`, `step-intervals.tsv`, `ladder-copies.tsv`,
`exponent-table.tsv` and `call-sites.tsv`.

## Evidence

Coordinates are ELF VAs. Function extents come from FDEs. `x` is the compared u64.

**Census.** The imm32 values 0x2e90edd (10^11 >> 11) and 0x48c27395 (10^13 >> 13) each occur 11 times in
`.text`, once in each of 11 functions. The imm64 10^15-1 occurs in those 11 and in 0x4eb76c0, which
returns a decimal digit count and has no `x < 100000` ladder start; it is excluded.

| Group | Functions | Inputs | Result |
|---|---|---|---|
| perp | 0x230b390, 0x42c7600 (500 bytes) | rdi meta, rsi asset, rdx x | `min(step(x), 10^(6 - sz))` |
| spot | 0x230b590, 0x36f3350, 0x4ca6b90 (689 bytes) | rdi meta, rsi pair, rdx x | 1000 when the lookup hits, else `min(step(x), 10^k)` |
| floor | 0x2773d60, 0x27758c0, 0x4336b90, 0x43377c0, 0x4338210, 0x4339480 | inlined | `floor(x / step(x)) * step(x)` |

The ladder window has one hash in both perp copies and one hash in all three spot copies. The six floor
windows all hash differently, from registers, spill slots and cold blocks (`ladder-copies.tsv`).

**The ladder.** For all u64 x:

```
step(x) = 10^max(0, digits(x) - 5)        digits(0) = 1
```

The proof has two parts. `breakpoints()` reads each window on its reachable path and accepts only: x
copied to a scratch register and shifted right, constants moved into registers, a compare of x or the
shifted copy with a constant consumed at once by an unsigned condition, and stack spills. It rejects any
path where the step register holds a value derived from x. So the output is constant between two
neighbouring thresholds, and every window yields exactly 10^5..=10^19. Then the real instructions run at
both ends of all 16 intervals in all 11 copies: 352 runs, 0 mismatches, which covers all 2^64 inputs
(`step-intervals.tsv`). 10^10..10^13 are compared as `x >> 10..13` against 0x9502f9, 0x2e90edd,
0xe8d4a51, 0x48c27395. The top decade comes from `cmovb` selecting 10^14-1 or 10^15-1 before the shared
`inc`, so x >= 10^19 gives 10^15.

**Perp term.** The asset splits as `asset / 10000` (multiply by 0x346dc5d63886594b, shift 11) and the
remainder. The quotient must equal `[meta+0x30]` and the remainder must be below `[meta+0x10]`, else the
unwrap panic at `l1/src/perp_meta.rs:194:38`. `sz` is the byte at `[[meta+8] + 48*index + 0x2a]`.
sz 0..=6 gives `min(step(x), 10^(6-sz))`: 7 values, 32 endpoints, 2 copies, 0 mismatches. sz 7..=255
panics at `l1/src/perp_meta.rs:319:28`: 249 values in each copy, independent of x.

**Spot term.** `slot 0x5773d30` holds 0x3728550, called as `(meta, pair, meta)`. Bit 0 of its return
selects a constant 1000 for every x, with no other read (3 values with bit 0 set, 32 endpoints, 3 copies).
With bit 0 clear, the pair record is 32 bytes at `[meta+0x168]` with count `[meta+0x170]` (panic
`l1/src/spot_meta.rs:565:25`), and token records are 0xe8 bytes at `[meta+0x180]` with count
`[meta+0x188]` (panic `l1/src/spot_meta.rs:113:33`). The exponent is the byte subtraction

```
k = token[pair[1]].byte(+0x49) - token[pair[0]].byte(+0x48)
```

A borrow panics at `l1/src/spot_meta.rs:984:9` (255 cases in each copy). Every k in 0..=255 was run at all
32 endpoints in 3 copies: k < 20 gives `min(step(x), 10^k)`, and k >= 20 skips the min and returns
`step(x)`. The evaluator tracks unset memory, and only the two named bytes were written, so these are the
only token bytes read. Because step(x) never exceeds 10^15, every k >= 15 returns `step(x)`, so the None
arm is not observable in the result.

**Floor copies.** The inlined tail divides by the step, multiplies and stores back into x. 242 inputs
per copy, 6 copies, 0 mismatches. The `jo` after the multiply was never taken, as expected, since the
product cannot exceed x.

**Callers.** There are 54 direct `e8` calls. Every one uses the return value as a divisor
(`call-sites.tsv`):

| Class | Count | After the division |
|---|---|---|
| REM | 25 | `test rdx,rdx`: the price must be an exact multiple |
| NEXT | 24 | quotient + 1 saturated, then a product; 19 gated by a test, 5 unconditional |
| FLOOR | 5 | quotient times tick |

22 of the 25 REM sites have the imm64 10^15 within 0x40 bytes before the call; no NEXT or FLOOR site does.
At 0x21f8144 that value is a `ja` into the same failing path.

The real tail at 0x2774197 ran on 2254 cases: rounding down gives `max(q*t, 1)`, and rounding up gives
`max((q+1)*t, 1)` with both steps saturating at u64::MAX. An exact multiple still moves up one tick: x=1000,
t=10 gives 1010. x=0 rounds down to 1.

**Status words.** The Display at 0x3a008e0 uses `word ^ 2^63` as an index into the i32 table at 0x5a572c
when the word has its top bit set. Index 0 is "Price must be divisible by tick size." (0x5a8838) and
index 9 is "Invalid TP/SL price." (0x5a8987). Error tag 0xc4 prints `{status} asset={n}`: its Display arm
at 0x3802bad passes +8 through wrapper 0x3998450 and slot 0x57748e0 to 0x3a008e0, and passes +4 as the
asset. On the failing path of the REM sites, the stored top-bit words are:

| Words stored | Sites | Examples |
|---|---|---|
| 0x8000000000000000 | 9 | 0x21f82fa, 0x26ec560, 0x430dc8f |
| 0x8000000000000009 | 3 | 0x21f8158, 0x4c18778, 0x4c19058 |
| both | 3 | 0x26e6c33, 0x4309911, 0x430c0a1 |
| none found in 24 rows | 10 | 0x21f8900, 0x3262348 |

0x21f7c40 and its copies 0x4c18260 and 0x4c18b40 have both forms: the first tick test fails with index 9
and the second with index 0, both under tag 0xc4.

**Reference comparison.** `visible_bucket_step` in `impl_sz.rs` agrees with the binary in 12 of 16 decades
and differs in 4:

| x | Binary | Reference |
|---|---|---|
| 10^11..10^12-1 | 10^7 | 10^6 |
| 10^12..10^13-1 | 10^8 | 10^7 |
| 10^13..10^14-1 | 10^9 | 10^8 |
| >= 10^19 | 10^15 | 10^9 |

The reference puts this ladder on `Sz` as a size bucket and has no term like `10^(6-sz)`. `Px::fits_wire`
counts significant figures with no exception, so it rejects raw 123456000000, which the binary accepts at
sz=0 (`worked_examples` in `evidence.json`). Its `ceil_to_tick` keeps an exact multiple, which the NEXT arm
does not. Its `wire_decimals` uses a fixed base of 8 for spot; the binary uses the quote token's byte.

Raw listings are reproduced by the commands above. Analysis was complete for the listed scope.

## Implementation and comparison

Not yet implemented. No Rust path, Cargo.lock or build comparison exists for this item. The closed forms
are `step_model`, `perp_model`, `spot_model`, `next_model` and `floor_model` in the tool.

Controls in `tests/test_px_tick_ladder.py`: a tampered digest, out-of-range VAs, a threshold off by one, a
flipped top-decade `cmovb`, a moved panic bound, a flipped min, a changed flag constant, a changed exponent
multiplier, a changed token offset, a broken store, a broken increment, a step register fed from x, a
compare on another register, an arithmetic step, a write to x, a wrong divisor, and a wrong status sentence.
Each changes a result or raises.

## Results and limitations

Metrics from `evidence.json`: 30729 evaluator runs (352 windows, 946 perp, 25725 spot, 1452 floor, 2254
rounding), 0 mismatches. All 684 instructions of the 5 tick functions ran.

Inferences, not observations:

- x in the perp and spot groups is a raw price, from the two status sentences and the REM test.
- `10^(6-sz)` and `10^k` are one whole unit of price in raw units, so the raw price scale is `10^(6-sz)` for
  perps and `10^(quote wei - base sz)` for spot, and sz raw times px raw is in quote units. The `min` then
  means a whole price is always a valid tick. With sz=0, x=123456000000 (123456.0) has step 10^7 but tick
  10^6 and passes, while x=12345600000 (12345.6) leaves remainder 600000. This matches the public rule
  that integer prices are always allowed, as recalled by the author and not checked against a source here.
- +0x48 and +0x49 are szDecimals and weiDecimals, from the RE-004-spot-wei-scale-family-94 packet, and
  pair word 0 and 1 are base and quote.

Unresolved:

- What x is in the six floor copies. It is computed from float and integer terms in the same function
  and it is not a tick-function input, but no text names it.
- What set 0x3728550 reads. It hashes pair word 0 against a table at `[meta+0x70]`, and answers 0 when
  `[meta+0x88]` is 0. The lookup is stubbed here, so the fixed tick of 1000 is pinned only as a return path.
- Which status the 3 two-word sites report (they store the index 9 word at +8 of the index 0 word, the
  same offset tag 0xc4 uses, so index 9 is likely). Of the 10 sites without a literal, 6 call 0x3c0cea0, 3
  use `lea rax,[rbx+9]` with rbx set earlier, and 0x3262348 fails with the string at 0x584738, length 0x1f,
  "Hyperliquidity price is invalid".
- The floor and NEXT forms are sampled, not whole-domain. The step is proved; the rest follows from `div`
  and `mul`. Only one NEXT tail ran; the other 23 are classified by pattern.
- The asset split was run on 3 assets only.

No progress gate is requested.

Next question: what fills the set at `[meta+0x70]` that forces a tick of 1000, and which spot pairs does
it hold?
