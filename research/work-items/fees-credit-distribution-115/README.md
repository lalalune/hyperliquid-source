# fees: node #115 fee credit distribution, credit and extra credit (0x3c1ae50, 0x3c1a250, 0x3c1a3f0)

This packet makes it possible to reconstruct, as executable code, how node #115 credits one scaled fee record to its ledgers: the protocol word, the gross-minus-rebate-minus-protocol word and the primary amount of the user; the primary recipient; and the split of a secondary total over a list of fraction rows (numerator over 100000, rows above 1.01 skipped, a row whose amount exceeds what is left skipped), with the remainder going to one destination. `tools/fees_credit_distribution_115.py` runs the real bytes of the three functions on 10167 generated inputs and checks every outcome against a separate closed-form model, and against a second, object-style reconstruction (`Ledger`, `FeeRecord`, bit-exact double conversions in the same tool), then shows that 103 deliberate faults are all caught.

- Component ID: fees (Fees and volume; the overflow hooks name Locations in `l1/src/qtys/mod.rs`, `impl_wei.rs` and `impl_ntl.rs`)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit: repository 0781ce04826eeefd89fe336cb8ea073be0c1de30 (origin/main when this was written); reference tree `references/can1357-hl` was not copied
- Claim status: observation for addresses, branches, constants, hook locations and every value the evaluated bytes produce; inference for names and units; unresolved items are listed at the end
- Scope included: `0x3c1ae50` (1,320 bytes, FDE `0x3c1ae50..0x3c1b378`), `0x3c1a250` (411 bytes) and `0x3c1a3f0` (283 bytes), 476 instructions, run from their real entries
- Scope excluded: the callers (`0x44896f0` is the subject of the merged `RE-004-node115-fee-scaling` observation packet, `0x46a6860` is the x100 scaler of another open pull request), the sibling caller `0x3c10000`, the bodies of the ten hash and map helpers listed below (argument-checking stubs), any build or execution of the node
- Relation to node #94: the evaluator head (table decoder, strict arenas, call stubs) descends from `tools/fees_unit_conversion.py` of the node #94 packet and was extended here with the instructions these functions need. No #94 address, layout or finding is used; every claim below was read from #115 bytes.

## Reproduce

Run from the repository root with the Python 3 standard library only. No objdump, readelf or other external program runs, and the node is never executed.

```
python3 tools/fees_credit_distribution_115.py --out research/work-items/fees-credit-distribution-115
python3 -m unittest tests.test_fees_credit_distribution_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
sha256sum -c research/work-items/fees-credit-distribution-115/MANIFEST.sha256
```

The first command takes about 60 s and 0.4 GB, and rewrites `evidence.json`, `instructions.tsv`, `vectors.tsv`, `controls.tsv` and `measure.json` byte for byte. It checks the SHA-256 of the input first, stops on any model mismatch, on an unexplained mutant survivor and on any unlisted instruction encoding. The vector list comes from a fixed-seed generator inside the tool, so it never depends on the interpreter's random module. `vectors.tsv` keeps 2 of every 7 rows (index modulo 7 equal to 0 or 3) with a digest of the final cell words; `evidence.json` holds the SHA-256 of the full row text, and the tool rebuilds all 10167 rows.


Files in this folder, all written by the command above except this README and the manifest:

- `evidence.json`: subjects, callers by byte scan, hook sites, Locations, constants, coverage, vector groups, control counts, SHA-256 of all rows.
- `instructions.tsv`: the 476 decoded instructions with address, size, bytes and the tool's own decoding.
- `vectors.tsv`: the kept rows of the 10167 vectors (see below).
- `controls.tsv`: every control and the group that caught it, or the reason it is equivalent.
- `measure.json`: case and control counts (`cases`, `negative_controls`, `negative_detected`).
- `MANIFEST.sha256`: SHA-256 of each file here.

## Evidence

Coordinates are ELF virtual addresses. Function ends are FDE ends (`.eh_frame_hdr` has 135313 entries); the decoder must land on each end. Section and FDE lookup skip SHT_NOBITS sections.

### Callers (byte scan for `call rel32`, `evidence.json`)

| callee | call sites | enclosing function |
| --- | --- | --- |
| `0x3c1ae50` | `0x4489d83`, `0x3c10bc9` | `0x44896f0`, `0x3c10000` |
| `0x3c1a3f0` | `0x4489b71` | `0x44896f0` |
| `0x3c1a250` | `0x3c1b29b`, `0x3c1b315` | `0x3c1ae50` (the two credits of the loop and of the remainder) |

### Shared lookup (all three functions)

For user address `u` (20 bytes) and key `k` (u64), arguments `rdi = state`, `rsi = &u`, `rdx = k`:

1. hash `0x4717440(state[0xe8], state[0xf0], &u)`;
2. find `0x3ee6280` on table `state+0xc8` with a probe `{&u copy, state[0xb8..0xc8)}`; a hit returns a bucket, a miss returns 0;
3. entry `0x4717c50` (occupied: tag 0, map `state+0xb0`, bucket; vacant: tag `state+0xc8`, map, hash, then the 20 key bytes at entry+0x18) returns the row; a vacant entry inserts;
4. inner map at `row+0xa0`, entry by `k` (`0x3cd7aa0`, then `0x3f14bc0`), which yields a 0x30-byte cell.

All additions below are saturating: on a carry the hook through GOT slot `0x64e4ea8` is called with `rdi = 0` and `rsi` = a source Location, then the word becomes u64::MAX. The three Locations (decoded from their RELATIVE relocations): `0x6487460` is `l1/src/qtys/mod.rs:835:1` (add), `0x6487478` is `l1/src/qtys/impl_wei.rs:6:1` (subtract), `0x6493948` is `l1/src/qtys/impl_ntl.rs:682:1` (extra credit). The nine hook call sites inside the subjects are listed in `evidence.json`.

### Credit: 0x3c1a250 (`state, &u, k, amount`)

| step | effect |
| --- | --- |
| `amount == 0` | return before any lookup (no cell is created) |
| else | lookup above, cell word +8 `+= amount` (hook `0x6487460`); then entry in the second map `state+0x138` by `u` (`0x3cd5840`, `0x3f171d0`), its inner map by `k` (`0x3cd0da0`, `0x3f14f20`), word +0 `+= amount` (hook `0x6487460`) |

### Extra credit: 0x3c1a3f0 (`state, &u, k, amount`)

There is no zero test: lookup above, cell word +0 `+= amount` (hook `0x6493948`). An amount of 0 still creates the row and the cell.

### Distribution: 0x3c1ae50 (`state, &u, k, &rec`)

`rec` is the 0x78-byte record that the x100 scaler `0x46a6860` writes in the caller (fields read here, all as u64 unless noted):

| offset | use |
| --- | --- |
| +0x00 | flag, compared as a dword with 1 |
| +0x08 | primary amount (read only when the flag is 1) |
| +0x10 | 20-byte primary recipient (flag 1 only) |
| +0x28 | `0x8000000000000000` means no list; anything else is the capacity word of a list |
| +0x30, +0x38 | list pointer, count (32-byte rows: u64 numerator at +0, 20-byte address at +8) |
| +0x40 | secondary total |
| +0x48 | 20-byte destination of the remainder |
| +0x60, +0x68, +0x70 | gross, rebate, protocol |

Order of effects, each add with the hook above:

1. Lookup for `u`; cell word +0x28 `+= protocol`.
2. If the flag is 1: `t = gross - rebate`; a borrow calls the subtract hook (`0x6487478`) and makes `t = 0`; `t - protocol`: a borrow calls the hook again and makes `t = 0`, else `t -= protocol`. Then word +0x20 `+= t`, word +0x18 `+= primary amount`; lookup for the recipient (`0x4718060`, keyed by the recipient pointer) and its cell word +8 `+= primary amount`.
3. If the list word is not the niche and the secondary total `T` is not 0: `remaining = T`; for each row in order, `f = double(numerator) / 100000.0`; a row with `f > 1.01` (or NaN) is skipped; `p = f * double(T)` is mapped to u64 by: infinity or NaN to 0, clamp at 2^64, `p > 2^64 - 2048` gives u64::MAX, else truncation (the 2^63 split conversion); if `p > remaining` the row is skipped, else the credit `0x3c1a250(row address, k, p)` runs and `remaining -= p`.
4. After the rows, `0x3c1a250(destination, k, remaining)` runs (a zero remainder returns at once).

`double(u64)` is the punpckldq/subpd/addsd sequence with constants `0x450170` (2^52, 2^84) and `0x451210`; the evaluator runs it bit for bit and the model uses Python's correctly rounded `float`. The tool checks the constants: 100000.0 at `0x459510`, 1.01 at `0x4590b8`, 2^64 at `0x459090`, 2^64 - 2048 at `0x458d58`, 2^63 at `0x459360`.

### Worked examples (`explain()` of the reconstruction; cell words start at the tool's `default_init` values, so only the deltas matter)

A record with flag 1, gross 100, rebate 30, protocol 20, primary amount 40, secondary total 1000 and rows 70000 and 20000, keyed 5, user 0, recipient 1, rows to users 3 and 4, destination user 2:

```
word +0x28 += 20     protocol on the user's cell
word +0x20 += 50     gross - rebate - protocol = 50
word +0x18 += 40     primary amount
word +0x8  += 40     the primary recipient's cell
word +0x8  += 700    row 1: 70000 / 100000 * 1000, credit: cell +8
word +0x0  += 700    row 1: second map
word +0x8  += 200    row 2
word +0x0  += 200
word +0x8  += 100    remainder 1000 - 700 - 200 to the destination
word +0x0  += 100
```

Gross 0, rebate 1, protocol 1, flag 1, no list: the first subtraction borrows (hook `0x6487478`, net becomes 0), the second borrows again (hook again), so the net word is added 0 and two subtract hooks are recorded.

Credit of 7 to a word at u64::MAX - 2: the sum carries, the hook `0x6487460` runs, and the word becomes u64::MAX; the second map word is added without a carry.

### Controls in detail (`controls.tsv` has one line per control and the group that caught it)

Wrong models, each run against the control vectors; the group that first catches each is in `controls.tsv`:

- cut-off 1.02 and cut-off 1.0 (caught by the `sweep` group)
- divisor 1e6 and divisor 1e4 (the `ledger` group)
- credit that does not skip an amount above the remainder (the `sweep` group)
- one borrow hook instead of two (the `ledger` group)
- the second map credited before the first (the `ledger` group, by the order of cell touches)
- the ledger gate taken on flag 0 instead of 1
- a remainder that is never credited
- zero amounts that create cells (the `sweep` group)
- wrapping instead of saturating adds
- the extra credit using the wrong hook Location (the `ext` group)

Byte mutants: every conditional jump and conditional move of the three functions inverted (36 sites), five immediates bumped by one, 32 memory displacements moved by 8 bytes (a moved displacement reads an unset byte and stops the strict evaluator, or reads another word), and nine constant bits flipped (a mantissa bit of each of seven constants, and one bit in the second half of each of the two 16-byte constants). Two of these are equivalent and say why.

Corrupted inputs: a flipped last byte of the file and an empty input against the digest check; an address that is not an FDE start; an address outside every section; an address in `.bss`; a relocation slot that does not exist; an unlisted opcode; a truncated ULEB128; the cut-off, divisor and clamp constants patched in the image and refused by the constant check.


### Reading `vectors.tsv`

Each row is `index, group, fn, key, secondary_total, fractions, status, hooks, cell_touches, final_cells_sha12`. `index` is the position in the generated list, so the rows kept (index modulo 7 equal to 0 or 3) can be matched to the tool's own list. `fn` is the entry that was run (`dist` for `0x3c1ae50`, `credit` for `0x3c1a250`, `ext` for `0x3c1a3f0`). `hooks` counts the overflow-hook calls and `cell_touches` the number of ledger cells that the stubs handed out, in order. `final_cells_sha12` is the first 12 hex digits of the SHA-256 of all final cell words, which the model and the reconstruction must reproduce exactly. A row alone proves nothing; the proof is that the tool rebuilds every row and compares full cell words.

## Implementation and comparison

Not yet implemented as Rust. The behaviour is reconstructed as executable Python in the tool, twice and independently, and both are compared with the evaluated bytes on every vector. This is not a build comparison, and no normalization mask exists.

- `model()` is a closed form over a scenario: it lists the final cell words, the hook Locations in order and the order of cell touches.
- `Ledger`, `FeeRecord`, `u64_to_double` and `double_to_u64` are the reconstruction: rows and cells as plain objects, the 0x78-byte record with its absent parts left unwritten (`FeeRecord.words()` is also what the evaluator writes into the record arena, and `FeeRecord.parse()` reads it back), the u64-to-double conversion as the punpckldq/subpd/addsd bit sequence, and the double-to-u64 conversion as the two `cvttsd2si` steps with the sign mask. `explain()` prints one line per ledger word written.
- Three-way agreement is required on all 10167 vectors: bytes, closed form, reconstruction. A vector on which any pair differs stops the run.

Hash, find, entry and cell helpers (`0x4717440`, `0x3ee6280`, `0x4717c50`, `0x4718060`, `0x3cd7aa0`, `0x3f14bc0`, `0x3cd5840`, `0x3f171d0`, `0x3cd0da0`, `0x3f14f20`) are stubs that check their arguments (hasher words, table and map addresses, probe contents, entry tags, key bytes), hand out cells whose words start at known values, and record the order of cell touches. The nested call from `0x3c1ae50` to `0x3c1a250` runs the real bytes.

## Results and limitations

- 10167 vectors, 0 mismatches (cell words, hook locations in order, and the order of cell touches are all compared): 1755 distribution grid, 96 ledger, 16 saturation, 168 sweep of fraction numerators near the cut-off, 995 credit, 976 extra credit, 6161 generated. Every outcome is `ok`; none of the three functions panics.
- 475 of 476 instructions executed. The one left is the `xorpd` at `0x3c1b230`, the infinity-to-0 branch of the fraction product; it cannot be reached because a fraction is at most 1.01 and the total is finite.
- Controls, all detected: 80 one-byte mutants of the subjects and constants (inverted conditions, bumped immediates, shifted displacements, flipped constant bits), 12 wrong models (cut-off 1.02 and 1.0, divisor 1e6 and 1e4, no skip above the remainder, one borrow hook, sub-map credited first, flag gate on 0, remainder not credited, zero amounts credited, wrapping adds, wrong hook location), 11 corrupted inputs (flipped digest, empty digest, non-FDE start, address outside the image, NOBITS bytes, missing relocation slot, unlisted opcode, truncated ULEB128, three patched constants). 103 of 103 detected; 2 constant-bit mutants are equivalent and listed with reasons in `controls.tsv` (the 2^64 clamp value above 2^64 - 2048, and the unread upper half of the punpckldq constant). The counts are in `measure.json`.
- 68 unit tests pass, including a table of 13 hand-worked splits and ledger updates, the cut-off at 1.01 against 101001, the double borrow, the zero-amount and zero-flag rules, bit-exact checks of the two double conversions (3000 generated values each way plus edges), the record byte round trip, the caller census and hook-site counts re-derived from bytes, and the controls above.
- Memory: peak resident size about 0.4 GB; the vectors run one at a time and only digests are kept.
- The record layout above is read from this function; whether the scaler writes the same fields in every caller is not shown. The sibling caller `0x3c10000` (4,750 bytes, call at `0x3c10bc9`) is not analysed.
- Inferences, not proven: the list rows are fractions of the secondary total (a numerator over 100000, cut-off 1.01 is a tolerance), the three cell words at +0x18, +0x20 and +0x28 are totals of primary amount, net fee and protocol fee, and the second map at `state+0x138` is a per-user total. The binary does not name them. The key `k` is `state[0x58]` in the caller `0x44896f0` per its `mov rdx,r12`; what it stands for is unresolved.
- Unresolved: the bodies of the ten helpers, the hasher, the layout of the row struct beyond the words read here, who consumes the cells, and the 0x3c10000 call.
- No progress gate is requested.

Next question: what does the sibling caller `0x3c10000` pass to `0x3c1ae50` at `0x3c10bc9`, and which of the two callers covers the spot path?
