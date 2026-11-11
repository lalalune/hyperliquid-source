# RE-006: node #115 TWAP slice step, from one due record to an order slice or a hand-off

The four slice bodies of node #115 (`0x5a305e0`, `0x5a33760`, `0x5a31640`, `0x5a32be0`) can now be rebuilt as an executable Python specification that predicts every stub call and every byte of the 0x70-byte order slice for 11,488 generated cases with 0 mismatches, so the limit price, the slice size rule, the jitter, the five-figure rounding and the hand-off to the advance function are fixed from #115 bytes, and the places where the earlier node #94 clue disagrees with #115 are measured instead of assumed.

- Component ID: orderbook (task RE-006)
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6` / no reference source is used
- Claim status: observation for the byte-level facts and the comparison counts; inference where the Inferences paragraph says so; unresolved points are listed under Results and limitations
- Scope included and excluded: included are the four slice bodies, the `round` helper `0x63efe40` and the `floor` helper `0x63effe0` (both run as real bytes through their GOT slots `0x64e1890` and `0x64e8680`), and the vec-form record lookup arms. Excluded are the lookup helpers `0x57f4ac0` and `0x57f36b0` and the B-tree arms they stand beside, the advance functions `0x5a145d0`, `0x5a13910`, `0x5a13f70`, `0x5a14c30`, the book top `0x46df820`, the tick lookups `0x5a01110` and `0x5a01310`, the spot mid `0x3c11290`, the fused multiply-add `0x63f0210`, the call-once `0x5c87d50`, the recorder `0x4524e40`, the drains and heap, and the third family of slice-like bodies `0x2dd34f0` / `0x2dd4530` (they load 1.03 and 0.97 and use thresholds 12,000,000 and 1,200,000,000 too, but call other lookups: `0x24c55a0`, `0x24cd630`, `0x269d520`, `0x2891f50`, `0x2892150`).

## Reproduce

From the repository root, on Linux with Python 3 and the pinned artifact in place:

```sh
python3 tools/twap_slice_115.py --out research/work-items/RE-006-twap-slice-115
python3 -m unittest tests.test_twap_slice_115
cd research/work-items/RE-006-twap-slice-115 && sha256sum -c MANIFEST.sha256
```

The tool checks the binary digest first and fails on any other input. It reads ELF bytes through `tools/elf_index.py` and `tools/fde_extents.py`, parses no disassembler or ELF dump text, calls no external program and never executes the binary. It takes about 90 s and under 0.5 GB. `--cases` (default 2800 per copy), `--sample` (every Nth case is kept in `cases.tsv`, default 3) and `--mutants` (condition flips per representative copy) scale the proof. Two runs with different hash seeds and time zones give identical bytes.

Generated files: `evidence.json`, `measure.json`, `cases.tsv`, `outcomes.tsv`, `copies.tsv`, `copy_differences.tsv`, `mutants.tsv`, `variants.tsv`, `controls.tsv`. `measure.json` holds the counts quoted below.

## Evidence

Coordinates are virtual addresses in node #115. Function bounds are FDE extents read from `.eh_frame`; `exact_fde` refuses any address that is not an FDE start.

### The four bodies

| Copy | Family | Bytes | Instructions | Stepped by the proof | Advance callee | Market table / count |
| --- | --- | --- | --- | --- | --- | --- |
| `0x5a305e0` | perp | 3202 | 714 | 609 | `0x5a145d0` | `+0x7c8` / `+0x7d0` |
| `0x5a33760` | perp | 3202 | 714 | 609 | `0x5a13910` | `+0x1338` / `+0x1340` |
| `0x5a31640` | spot | 2937 | 666 | 568 | `0x5a13f70` | none |
| `0x5a32be0` | spot | 2937 | 666 | 568 | `0x5a14c30` | none |

`copy_differences.tsv` lists every decoded instruction where a pair differs: the two perp copies differ in two displacements (`+0x7c8`/`+0x7d0` against `+0x1338`/`+0x1340`) and the advance call, the two spot copies only in the advance call. A test makes the second perp copy read the first copy's offsets and the proof fails, so the offsets are not interchangeable. Fixtures write decoy values at the offsets the copy must not read.

The unstepped instructions are the B-tree arms (a record map whose first word is `0x8000000000000000`), the unwind landing pads and the panic cold blocks.

### Records

Observations from the bytes of `0x5a305e0`; the other copies read the same offsets.

- Capture, read through the second argument: tracker, now (date word, seconds, nanoseconds as three u32), flag byte pointer, books vector (`+8` buffer, `+0x10` length), outer state, output vector. The third argument holds the user key (20 bytes) and the order id at `+0x18`.
- User map and order map, vec form: a ring `{capacity, buffer, head, length}`. The user ring sits at tracker `+0x18` with 0x38-byte entries whose `+0x18` is the order ring; order entries are 0x70 bytes, the key first and the 0x68-byte value at `+8`. The position is `(index + head)` minus the capacity when not below it. The searches themselves are the stubbed helpers.
- Order value: `+0x00` asset, `+0x08` total, `+0x10` duration (f64), `+0x20` byte copied to slice `+0x31`, `+0x21` jitter switch, `+0x22` side, `+0x30` executed, `+0x40` step counter, `+0x54` owner (20 bytes).
- Slice output, 0x70 bytes: tag 1, `+0x08` size, `+0x10` byte 3, `+0x19` byte 2, `+0x20` limit price, `+0x28` and `+0x48` asset, `+0x30` side, `+0x31` the `+0x20` order byte, `+0x32` zero, `+0x50` order id, `+0x58` owner. Tag 2 means no order. Every other byte is left alone; the comparison checks the 0xa5 fill.
- Perp tables: market `asset / 10000` at stride 0x510, bound by the count word, panic text 0x2b bytes at `0x7d3212`; books by `asset % 10000` at stride 0x120 with the pair at `+0xa8`. Spot: the mid slot `0x64e8690` (target `0x3c11290`) takes the outer state `+0x80`, the asset and the books vector, the tick helper takes the outer state `+0x90`.

### Path

1. Find the user (stub), then the order (stub). An absent user, an absent order or a position at or beyond the length ends with tag 2.
2. `N = 2 * saturate(duration / 60) + 1`, saturating. There is no assertion: a negative, NaN or infinite duration counts as 0 and N is 1.
3. A set flag byte skips to the advance. If the call-once state word `0x64f01d8` is non-zero, `0x5c87d50` is called first with the state, 1, the vtable `0x63fe250`, the location `0x63fe278` and the value `0x64f01c0`.
4. Perp: dex bound (panic), the 0x156 error word dropped through `0x44e0810`, book bound (panic), the book top gives two prices. Either being 0 hands off to the advance; the mid is their carry-free average. Spot: the mid slot answers; 0 hands off.
5. Limit: `1.03 * mid` for side 0, `0.97 * mid` otherwise, round half away, clamped and cast, at least 1. The tick helper gets the market (perp) or outer `+0x90` (spot), the asset and the limit. Side 0 floors to a tick, side 1 floors and adds one tick (saturating). The price is at least 1.
6. Target: `even = total / N`. A counter equal to N targets the total. Otherwise `floor(counter * even)`; with the jitter byte set `floor(fma(even, counter, jitter * even))` and `jitter = (ms % 40) / 100 - 0.2`, `ms` the Unix milliseconds computed inline from the date word (negative values taken as 0).
7. A target below the executed size hands off. The remainder is `total - executed`, recorded at `0x64b7fc8` and 0 on underflow. If `price * remainder` does not exceed 30,000,000 (perp) or 3,000,000,000 (spot) the slice is the whole remainder.
8. Otherwise `floor = ceil(12,000,000 / price)` (perp) or `ceil(1,200,000,000 / price)` (spot), and 1 when the price is above the unit; `cap = 3 * saturate(even) + 1`, saturating; `size = max(min(cap, target - executed), floor)`, then the minimum with the unexecuted total (recorded again on underflow), then, below the last step, rounding down to five significant figures. A size of 0 hands off.
9. The hand-off calls the advance function with the tracker, the 20-byte owner copy, the order id, the outer state and the output vector, and returns tag 2.

### Differences from the node #94 clue

The deleted node #94 packet (git history of this repository, a clue only, not rechecked against any #94 binary here) described a different rule set. `variants.tsv` runs each earlier rule as a wrong specification against the #115 bytes: the assertion on a negative or NaN duration (389 disagreeing cases in the first run), the minimum size `floor(unit / price)` with 0 above the unit (107), and `min(cap, max(want, floor))` (203) all disagree with #115. Layout also moved: market stride 0x510 (was 0x2f0), book stride 0x120 (was 0xd8) and top at `+0xa8` (was `+0x80`), order fields side `+0x22`, jitter `+0x21`, executed `+0x30`, counter `+0x40`, owner `+0x54`, and the perp copies' market fields `+0x7c8`/`+0x1338`.

## Implementation and comparison

Rust implementation: not yet implemented. Raw and normalized body comparison: not yet measured. The comparison is real #115 bytes against a separately written Python specification.

The evaluator is a concrete x86-64 subset interpreter that stops on any instruction it does not model. It runs the bytes of the four bodies plus `round` and `floor`. Stubs record their arguments, and the recorded list is compared event by event with the specification: user search, order search, error drop, book top, tick, spot mid, recorder, call-once, advance, and the two panics. The whole 0x70-byte slice is compared byte by byte, unwritten bytes included. The fused multiply-add is modelled exactly with fractions.

Cases: 2800 seeded cases per copy plus 72 fixed edge cases per copy. The fixed ones sit on the exact whole-remainder thresholds, on saturating counters with a huge duration, on the negative jitter band at counter 0 and on extreme mids. Rings use capacity 1 to 9 with any head, and the lookups cover absent user, absent order and a position beyond the length.

Negative controls (121, all detected):

- 106 flipped conditions caught of 110 tried: every Nth reached conditional jump of one perp and one spot copy, patched one bit in the bytes, then run against 300 cases and, when not caught, 1200 more. The 4 that survived are not counted here.
- 12 wrong specifications (`variants.tsv`).
- 3 structural controls: a wrong digest, an address outside every FDE, an address that is not an FDE start.

## Results and limitations

| Metric | Result |
| --- | --- |
| Cases | 11,488 (4 copies) |
| Mismatches | 0 |
| Outcomes, all copies | order 3,510, reschedule 5,361, none 1,102, panic 1,515 |
| Instructions stepped / total | 609 / 714 (perp), 568 / 666 (spot) |
| Negative controls detected / run | 121 / 121 |
| Flips tried / caught / survived | 110 / 106 / 4 |
| Unit tests | 21, no skips (includes 23 hand-checked scenarios with literal results on all four copies) |
| Tool run | about 90 s, peak 358 MB resident |

The 4 survivors (`0x5a30d8d`, `0x5a30d9b` in the first perp copy and `0x5a31d50`, `0x5a31d5e` in the first spot copy) are the two clamp tests after the jitter floor; swapping their sense changes the intermediate value but the later zero and top clamps give the same result, so they are inferred to be equivalent mutants and are not counted as controls.

Limits:

- The lookup helpers, the book top, the tick lookups, the spot mid, the advance functions, the call-once and the recorder are stubs. Only their arguments and results at the call are checked.
- Only the vec form of the two record maps is exercised. The B-tree form (first word `0x8000000000000000`) and the memcmp-based walk are not run.
- Date arithmetic is the inline chrono code reached through the jitter; dates are limited to years 1999 to 2030.
- The fused multiply-add target `0x63f0210` is a stub modelled as exact fused arithmetic; the CPU-dependent choice behind it is not examined.
- Which caller sets the flag byte is not settled. The third family `0x2dd34f0` / `0x2dd4530` is not covered. Tick lookups and the book top are only pinned as callees.
- No progress gate is requested.

Next question: the advance functions `0x5a145d0`, `0x5a13910`, `0x5a13f70` and `0x5a14c30` (reschedule by 30 s, counter bump, finish record), and the lookup helper `0x57f4ac0`.
