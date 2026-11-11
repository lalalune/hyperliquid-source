# RE-007: reconstruct the node #115 position update body 0x448bc30 (qtys saturating arithmetic) and verify it on 10,144 byte-level cases

This packet lets the reconstruction replace the 3,317-byte position update body at 0x448bc30 with executable rules: given a 0x40 byte position record, a price, a signed size delta, a running balance, a floor and a price cap, `tools/risk_position_update115.py` computes the new record, the new balance, the overflow reports and the error, panic or fault outcome, and the real instruction bytes (run in an interpreter, never the node) agree with those rules on every case. It fixes the record layout (mode word, fee divisor, accumulator, size, two cleared fields), the six arms of the body (copy, plain fill, open, close by share, close by value, flip), the exact saturation sites and the six `l1/src/qtys` source locations behind them.

- Component ID: risk (RE-007 clearinghouse); helper under the position margin test 0x469b990 and the function at 0x42040f0
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`)
- Source commit / reference commit: repository commit 0781ce04826eeefd89fe336cb8ea073be0c1de30; no reference source is copied, the rule list is written from the bytes
- Claim status: observation (addresses, layout, constants, call sites, per-case agreement); inference (field names, the meaning of the accumulator and of the floor) is marked as such below
- Scope: the whole function 0x448bc30..0x448c925 and its two external slots (a report slot and a panic slot, served by recording stubs). Excluded: the two callers' own logic, the report routine 0x4524e40 and the panic routine 0x1680c30 (only their arguments are checked), any Rust implementation, any progress gate.

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/risk_position_update115.py --out research/work-items/RE-007-position-update-115
python3 -m unittest tests.test_risk_position_update115
```

The tool checks the node SHA-256 first, reads only ELF bytes (through `tools/elf_index.py` and `tools/fde_extents.py`), runs no external program and never executes the binary. The interpreter inside the tool is the one used by the merged staking and funding tools. Regeneration takes about 15 seconds and under 400 MB; the 49 tests take about 15 seconds. Two regenerations into different folders are byte identical. Every table below is rebuilt by that command; `MANIFEST.sha256` lists the files.

## Evidence

Coordinates are virtual addresses of the ELF image; the function is the FDE `0x448bc30..0x448c925` (3,317 bytes, 804 instructions, decoded to exactly the FDE end).

Calling form (observation, from the prologue and the uses of each register):

| register | meaning |
| --- | --- |
| rdi | 0x48 byte result block; also returned in rax |
| rsi | 0x40 byte position record, updated in place |
| rdx | price, an unsigned word that must be non-negative as an i64 |
| rcx | signed size delta; zero skips everything |
| r8 | signed running balance |
| r9 | signed floor for the returned balance |
| first stack word | unsigned price cap |

Record layout (offsets read from the loads and stores): +0 u32 mode (only the value 1 selects the full rules), +4 u32 fee divisor, +8 i64 accumulator, +0x10 i64 size, +0x18 and +0x30 and +0x38 never touched, +0x20 i64 set to zero when the size changes sign, +0x28 i64 set to zero on every non-zero delta. The result block is a copy of the final record with the new balance at +0x40; an error writes only the tag word 2 at +0 (the rest of the block stays as it was, checked with a sentinel fill).

Control flow in rule form (observation of every branch, names are inferences):

1. delta 0: copy the record, balance in +0x40, nothing else changes.
2. clear the +0x28 field; add size and delta with a checked add (overflow reports `impl_sz.rs:39`); if the saturated sum has a different sign from the old size, clear the +0x20 field.
3. mode other than 1: size becomes the (saturating) sum, a negative price or a price times delta outside i64 is the error outcome, the balance is `balance - price*delta` with a reported saturating subtract.
4. mode 1 with size 0, or a delta in the size's direction: the open arm (below).
5. mode 1 with a delta against the size: closed = min(|size|, |delta|), signed like the delta (a closed amount of 2^63 would panic at 0x448c900, which no input reaches). Then `value = price*closed` (error on overflow) and the arm is picked by the sign of `acc + price*size` (an overflowing product counts as the sign of the size):
   - not negative (share arm): ratio = closed/|size| in double, `share = trunc(acc*ratio)` saturating (NaN is 0, 2^63 is i64 max); acc -= share; balance = balance + share - value (each step reported on overflow, and the share minus value overflow is reported once more).
   - negative (value arm): acc -= value; when the delta is larger than the size (a flip) and the size becomes zero, the balance gets the whole accumulator and the accumulator is zeroed.
   Then rest = delta - closed and size = size + closed. A zero size with a non-zero rest runs the open arm again (the flip); a non-zero size with the rest in its direction also runs it.
6. open arm: the effective price is `min(cap, price)` for a positive rest and `max(cap, price)` for a negative rest (unsigned compares; a result with the top bit set is the error outcome); worth = effective price * rest (error on overflow); fee = |worth| / divisor, a 32 bit divide when |worth| fits 32 bits, else a 64 bit divide (divisor 0 is a processor fault, a quotient of 2^63 or more is the panic at `qtys/mod.rs:847`); acc += fee; balance -= fee; a negative price or price*rest overflow is the error outcome; balance -= price*rest; size += rest; acc -= worth; balance += worth.
7. settle: if balance >= floor (signed) it is the result, else the result is the floor and acc -= (floor - balance). When the size ended at zero by an exact close (or an open that summed to zero) the whole accumulator is folded into the result and zeroed.

Every checked add, subtract and the one compare-only subtract calls the report slot 0x64e4ea8 (a relative relocation to 0x4524e40) with a location record and keeps the saturated value. `location-records.tsv` reads the six records: `l1/src/qtys/mod.rs` lines 834 (accumulator add), 832 (size add on the plain-fill and close arms), 848 and 847 (the two panics), `l1/src/qtys/impl_sz.rs` line 39 (delta add) and `l1/src/qtys/impl_ntl.rs` line 70 (every subtract). `location-use.tsv` gives the record used at each of the 22 report sites and 2 panic sites; `external-slots.tsv` counts them; `callers.tsv` lists the two direct callers, 0x42043b1 inside the 988-byte function 0x42040f0 and 0x469bab2 inside the margin test 0x469b990.

Constants (`constants.tsv`): the clamp bounds -2^63 and 2^63 (0x459808, 0x459360), the largest double below 2^63 (0x458e50) and the two magic words of the unsigned-to-double conversion (0x451210, 0x450170).

Coverage: `row-first-reach.tsv` names the first case that reaches each of the 804 rows. 692 rows are reached. The other 112 (`unreached-rows.tsv`) fall into six blocks that `unreachable-groups.tsv` explains by arithmetic: a clamp that the scaled accumulator never leaves, four overflow reports whose operands have opposite signs or no larger magnitude, and the negation panic that needs two magnitudes of 2^63.

## Implementation and comparison

Not a Rust implementation. The rule list (`Rules` in the tool) is executable Python written from the bytes; the interpreter runs the real bytes. 10,144 cases are compared as whole outcomes (kind, balance, all nine record words, the ordered list of report locations, the panic arguments): 64 named cases that walk each arm, 1,080 grid cases, 9,000 generated cases (60% tame sizes and prices, 40% edge-heavy words). Outcomes: 6,861 ok, 3,214 error, 68 divide faults, 1 panic; report counts per location are in `evidence.json`. Disagreement anywhere aborts the generation.

Negative controls: 224 in total, all accounted for.
- 20 deliberately wrong rule lists (wrap instead of saturate, silent overflow, rounded or floored share, cap ignored, wrong cap direction, marks kept, mode ignored, ceiling fee, no fold, no shortfall, no re-open, inverted arm test, share over delta, negative price accepted, unsigned floor, zero divisor ignored, closed by max, equal sign opens): all 20 detected.
- 10 structural controls (flipped file byte, three non-function addresses and one past the file, two slot targets swapped, an unaligned address, a moved price, a changed mode): all 10 detected.
- 194 single-byte edits of reached rows (jcc, cmov and setcc conditions, immediates, displacements): 187 detected, 7 survive and are explained in `equivalent-mutants.tsv` (the infinity threshold bit, two clamp tests that route in-range values through an idempotent clamp, and four sign-only saturation constants). Two edits that first survived (the panic message length and the saturation constants of two arms) exposed missing controls; the panic arguments were added to the outcome and three named cases were added, after which those edits are detected.

`measure.json`: cases 10,144, negative controls 224, detected 217, equivalent 7 (217 + 7 = 224).

## Results and limitations

- Observed: boundaries, layout, call sites, constants, locations, per-case agreement of rules and bytes (denominators above).
- Inferred: field names, the reading of +8 as a signed notional accumulator and of the balance/floor pair as the realized value and its lower bound, the reading of `qtys` locations as size (`sz`) and notional (`ntl`) newtypes (the file names support it, the semantics of their operators are not read here).
- Not shown: the two callers' use of the result, the bodies of the report and panic routines, behavior for a record whose untouched words matter to a caller, and any claim that this matches a source-level Rust function; no progress gate is requested.
- The interpreter covers only the instructions this function uses; the divide-by-zero case relies on its fault model (the processor raises #DE), not on a run of the node.

Next question: the 988-byte caller 0x42040f0 (the second direct caller) and the margin test 0x469b990's use of the returned balance and error tag.
