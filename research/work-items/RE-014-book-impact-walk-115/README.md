# RE-014: reconstruct the node #115 order-book impact walk 0x46a6370, its B-tree step 0x37c5dd0 and the x100 record scaler 0x46a6860

- Component ID: RE-014 (funding premium inputs; sibling of the funding premium body 0x44d9060, whose two book walks call this function)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace at 7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6; the evaluator engine is imported from the merged `tools/mid_market_order_builder_115.py`; no #94 material is used
- Claim status: observation (byte-compared behaviour of three bodies) with inference (names, meaning of the fields) kept separate below
- Scope included and excluded: included are the walk body (1,260 bytes), the B-tree iterator step (548 bytes) and the scaling helper (367 bytes), run from their original bytes; excluded are the premium body that calls the walk, the hash/probe helpers, the owner builder and the writers of the arena, the book containers and the log flag. No progress gate is requested.

This packet makes it possible to rebuild the book-impact price used by the funding premium: walk one side of a book from its best level, sum resting size per level through a linked order list, stop at the level that reaches a target notional, and return floor(total notional / total size) with the last level taken only partially (or 0), including every overflow, saturation, fault and log path. The same bytes also give the exact B-tree node layout (key, level and edge slots) and the fee-record x100 scaler with its overflow panic.

## Reproduce

From the repository root (Linux, Python 3 standard library only; the binary is never executed, no objdump or readelf output is parsed):

```
python3 tools/artifacts.py verify
python3 tools/re014_book_impact_walk_115.py --out research/work-items/RE-014-book-impact-walk-115
python3 -m unittest tests.test_re014_book_impact_walk_115
(cd research/work-items/RE-014-book-impact-walk-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the binary SHA-256 first, takes about 20 s and 0.4 GB (peak 380 MB), and writes every `.tsv` and `measure.json` file in this folder byte for byte (checked twice with different hash seeds and time zones). `MANIFEST.sha256` lists every other file in the folder.

## Evidence

Coordinates are virtual addresses. Function bounds are exact FDE rows (`pins.tsv`): walk 0x46a6370..0x46a685c, scaler 0x46a6860..0x46a69cf, B-tree step 0x37c5dd0..0x37c5ff4. Direct call sites (E8/E9 scan of .text): the walk has exactly two, 0x44d91ec and 0x44d9201, both inside the premium body 0x44d9060; the scaler has one, 0x4489d52; the B-tree step has 18 (all listed). `branches.tsv` lists all 64 conditional branches, `field-offsets.tsv` every base-register displacement the bodies read, `locations.tsv` the five panic/overflow Location records decoded from .rela.dyn RELATIVE rows (paths cut below `src/`): size_sum `src/qtys/mod.rs:831`, notional_sum `src/qtys/impl_ntl.rs:26`, partial_sum `mod.rs:833`, fill_sum `mod.rs:831`, scaler multiply `src/fees/compute.rs:45:42`. `coverage.tsv` lists the 118 instructions no case executed.

Observed behaviour of the walk (arguments rdi = object with the arena base at +0x88 and entry count at +0x90, rsi = pointer to the target notional, rdx = book container):

1. Container word 0 equal to 0x8000000000000000 selects a B-tree map (root +8, height +0x10, length +0x18); anything else is a ring buffer (capacity, pointer, head, length) of 0x88-byte (key, level) elements walked front slice then wrapped slice. The B-tree is stepped by the real 0x37c5dd0.
2. Per level: price = |key| as u64 (i64::MIN stays 0x8000000000000000); level dword at +0 must be 1 and the first arena index at +8 must be below the entry count, else the exit that tests the flag word 0x64f01d8 (non-zero: one call through slot 0x64df9f0 with esi = 1) and returns 0.
3. Size of a level = sum of arena +0xe0 along a chain of 0x110-byte entries; entry dword +0 equal to 2 ends the chain, +0x10 equal to 0 ends it after counting, next index +0x18 must be below the count. Sum overflow reports through slot 0x64e4ea8 (rdi 0, Location size_sum) and saturates at u64::MAX. Size 0 behaves like a bad level.
4. notional = price * size; a carry or a value above 0x7ffffffffffffffe returns 0 with no log. Running notional adds with a report (notional_sum) and saturation; below the target the level is taken whole and the fill count grows with a report (fill_sum).
5. At the level that reaches the target (>=): q = (target - previous) / price (price 0 is a hardware divide fault), p = price * q must not exceed 0x7ffffffffffffffe, total = p + previous (report partial_sum), count = q + fill (report fill_sum); if count - 1 >= total the result is 0, else floor(total / count). A book that never reaches the target returns 0.

The scaler writes a 0x78-byte record: +0x60, +0x68, +0x70 always times 100, +8 times 100 when the tag at +0 is 1, +0x40 times 100 unless the word at +0x28 is i64::MIN; any carry panics at `src/fees/compute.rs:45:42`. Other fields are copied; some output words are unspecified padding (only the low dword of +0x20 and +0x58 is written) and are masked in the comparison.

Inferences (not proven by bytes): the value is a volume-weighted impact price (mid-versus-impact premium); negative keys are the bid side; the arena is an order slab with next links; the scaler turns percent-style fields into hundredths.

## Implementation and comparison

`tools/re014_book_impact_walk_115.py` (pure Python) has two independent parts. The evaluator (engine imported from the merged mid-market builder tool, same shared ELF/FDE parser) runs the original bytes of all three bodies with only the overflow callback, the log slot and the panic slot stubbed (they record their arguments). The reconstruction `spec_walk`, `spec_scale` and the in-order tree model predict return value, every callback with its Location, faults and panics, and for the B-tree step the exact key/level pointers of every yield. Cases are laid out in the heap exactly as the bytes read them (ring buffers with wrapped heads, B-trees of height 0..2 with up to 40 nodes, 24-entry arenas) and generated from four magnitude profiles plus byte-derived specials (0x7ffffffffffffffe, i64::MIN, u64::MAX/100 and neighbours); targets sit on, below and above each level's cumulative notional.

Rust is not written yet ("not yet implemented"); this packet fixes the behaviour a Rust port must meet.

## Results and limitations

Measured (`measure.json`): 14,000 cases, 0 mismatches (10,400 walks: 5,200 ring buffer and 5,200 B-tree, 1,600 B-tree step runs, 2,000 scaler records); outcome classes in `outcome-classes.tsv` (prices, zero by exhaustion/overflow/log, divide faults, scaler panics all populated). Negative controls: 118 of 118 detected = 18 wrong walk reconstructions, 2 wrong B-tree models, 2 wrong scaler models, 6 refused inputs (flipped binary byte, wrong digest, address outside sections, non-FDE start, address past the last FDE, section start), 4 damaged case rows, 1 short length counter, plus 85 flipped branches/conditions/immediates caught by the comparison. Another 17 byte mutants survived (reported in `mutants.tsv`, not counted: 32-bit versus 64-bit divide selection and saturation constants are equivalent in outcome) and 21 sit in instructions no case reaches. The case table digest is in `measure.json`; `cases-*-sample.tsv` keeps every third case, data is about 80% of the lines because every case is reproducible from the tool.

Limits: the walk is not tied to its caller beyond the two call sites, the owners of the arena and containers are unresolved, and the unexecuted blocks (the target-below-previous underflow report and a second partial-sum report after saturation) look unreachable but are not proven so. Whether the unspecified scaler padding is ever read is unknown. No gate is requested.

Next question: the premium body's use of the two results (which side gets which target), and the writer of the arena entries read at +0xe0.
