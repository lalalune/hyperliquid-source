# RE-006: node #115 open interest gate on a price update rebuilt and proven against 10,910 cases of the real instructions

This packet lets a Rust rebuild decide, for the node #115 price-update gate `0x447ab80`, exactly which rows leave the Spot, Mark and External price lists (`size + book total_sz` times price against two fixed limits), which texts are pushed and in what order, when the Mark list is cleared, and when the second record fires. It is no longer a list of addresses: `tools/oi_price_gate_115.py` contains an executable specification of the whole path, and the same tool runs the real #115 instructions on 10,910 cases and shows that the two agree.

- Component ID: RE-006 (book state transitions), through the book row read at `l1/src/books.rs:14`; the gate hosts clearinghouse code at `l1/src/clearinghouse/clearinghouse.rs:544`
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `0781ce048` (repository main when the tool was written) / `references/can1357-hl` is only a list of labels to check and nothing is copied from it.
- Claim status: observation for everything in Evidence (ELF bytes, plus an evaluator running those bytes). Inferences and unresolved items are marked. No progress gate is requested.
- Scope included and excluded: included, run as real bytes, are the gate `0x447ab80`, the three-list retain `0x366ce20`, the row closure `0x3d987f0`, the size-times-price check `0x447c620`, the Mark list clear `0x366cc80`, the sorted-ring search `0x45547e0` and the B-tree search `0x35bd660`. Stubbed at the edge with their arguments compared: the Mark list clone `0x3dc86b0`, the price map builder `0x3cc57c0`, the total fold behind slot `0x64eaac0` (function `0x44810d0`), the text formatter, the list growth, the overflow recorder, `free` and the two panic entries. Excluded: the bodies of those stubs, the six callers of the gate past their call sites, the earlier wire-list step of the callers, and the sibling retain `0x366d200` (3,340 bytes, a different list pipeline that also calls `0x3cc57c0`).

## Reproduce

From the repository root:

```
python3 tools/oi_price_gate_115.py --out research/work-items/RE-006-open-interest-gate-115
python3 -m unittest tests.test_oi_price_gate_115
```

The tool takes about 30 s and 400 MB. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed; it is only read. The seeded cases come from `random.Random(115)`, which does not depend on the hash seed.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`, `controls.tsv`, `measure.json`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`). Every field offset below is decoded from the instruction bytes by the tool (`field_reads`), and every float constant is read from `.rodata` (`float_constants`).

### The gate `0x447ab80`

It is reached only through slot `0x64e79c0`, from six call sites (`call_sites.tsv`). Arguments: `rdi` result, `rsi` owner, `rdx` the price lists, `rcx` the optional book list. The result is the price lists moved by value (`0x68` bytes, the text list at `+0x50`).

| # | Step | Result |
| --- | --- | --- |
| 1 | `0x366ce20` retains the Spot, Mark and External lists, in that order, through the row closure | failing rows leave their list, order kept |
| 2 | If the niche word at owner `+0x378` equals `i64::MIN`, stop here | |
| 3 | Clone the Mark list (`0x3dc86b0`), build the price map (`0x3cc57c0`), fold (`0x44810d0`, slot `0x64eaac0`) | tag 1 and a total, or tag 0 |
| 4 | Tag 0: clear the Mark list (`0x366cc80`), no total text | |
| 5 | Tag 1: `r12 = [owner+0x478]`; a negative cap panics at `l1/src/qtys/mod.rs:847` | |
| 6 | `0.1 * (total as f64)` cast to `i64` (NaN 0, saturating) compared with the cap, signed `>` | not above: nothing else happens |
| 7 | Above: push one `Total open interest exceeded 10x ...` text (total / 1e6, cap / 1e6), then clear the Mark list | |

### Row closure `0x3d987f0` and check `0x447c620`

The closure reads the asset's stored size from the map at owner `+0xf0`. The word at `+0xf0` is either `i64::MIN` (B-tree: root `+0xf8`, height `+0x100`, searched by `0x35bd660`; a null root is a miss) or the capacity of a sorted ring of 16-byte `(asset, size)` rows (pointer `+0xf8`, head `+0x100`, length `+0x108`, searched by `0x45547e0`). A miss reads as 0. If a book list is present, book row `asset % 10000` (stride `0x120`, `total_sz` at `+0x118`) is read with a bounds panic at `l1/src/books.rs:14`; no book list reads as 0. Then:

```
if book < 0 as i64: panic at l1/src/qtys/mod.rs:848
sum = stored + book, saturating at i64 max with record(0, impl_sz.rs:39)
fits = price >= 0 and price * sum fits i64
if not (fits and product < 0x28f5c28f5c28f5d) and niche word at +0x378 is i64::MIN: record(1, clearinghouse.rs:544)
if fits and product < 0x199999999999999a: pass
else: text with asset, kind, product / 1e6 (0.0 when it does not fit)
```

A failing row pushes two strings onto the text list: `Asset open interest exceeded cap asset={} kind={}, oi={}` and `Missing price, keeping old {} price asset={} oracle_kind={}`, and leaves its price list. Asset ids in texts: below 10000 as they are, up to 99899999 plus 100000, above that `0xffffffff`. The text list is grown through the `grow_one` slot `0x64e0c10` when length equals capacity; the harness models that call as a doubling (minimum 4), so what is proven is where the call happens, not the new capacity.

### Mark list clear `0x366cc80`

Replaces the Mark list by an empty vector, pushes one `Missing price` text per old row with kind 1 and the list's source byte (`+0x48`), then frees the old buffer when its capacity is nonzero. Spot and External lists are not touched.

### What differs from the #94 gate

The #94 gate (`0x3709040`) parsed a wire list, stored the map as a B-tree only and summed the notional of all assets itself. In #115 the wire step is not in `0x447ab80`, the size map may be a B-tree or a sorted ring, the book stride is `0x120` (not `0xd8`), the cap sits at `+0x478`, and the "mode 3" byte is a niche word at `+0x378`. The values of the two limits did not change. This packet was built against #115 bytes only; the #94 tool served as a source for the evaluator and its method.

## Inferences

- The map at owner `+0xf0` is open interest by asset: the text calls the product `oi`. The two shapes (B-tree or sorted ring) look like one collection type that switches representation; this packet only proves what both shapes return.
- If so, the row test is `(open interest + resting size) * price`, so resting orders can make a price row fail.
- The 1e6 divisor reads like a notional scale (row limit about 1.8e12). The binary does not name the unit.
- The niche word at `+0x378` equal to `i64::MIN` is probably a `None`; the gate then skips the Mark total and the check turns its second record on. What the field holds is not read here.
- The fold behind `0x64eaac0` is probably the Mark-price-times-stored-size sum of the #94 gate; here it is stubbed, so no claim is made about it.

## Implementation and comparison

Not yet implemented in Rust. The comparison is: a pure-Python specification (`Spec` in the tool, written from a full instruction read of the seven functions and kept apart from the evaluator) against the evaluator that executes the real bytes of those seven functions. Both are run on every case and compared on the result, the three price lists, the text list, the Mark list header and the ordered events (`format`, `record`, `grow`, `free`, `clone`, `collect`, `fold`, with all arguments).

| Metric | Value |
| --- | --- |
| Cases (410 hand-written + 10,500 seeded) | 10,910 |
| By kind: check / row / retain / clear / host | 3,249 / 3,863 / 1,633 / 551 / 1,614 |
| Mismatches | 0 |
| Instructions stepped | 6,061,979 |
| Stepped / total: gate | 124 / 144 |
| Stepped / total: retain | 209 / 254 |
| Stepped / total: row closure | 187 / 202 |
| Stepped / total: check | 101 / 101 |
| Stepped / total: clear | 82 / 101 |
| Stepped / total: ring search | 92 / 92 |
| Stepped / total: B-tree search | 38 / 39 |
| Mutants killed / survived / unreached | 263 / 13 / 16 |
| Negative controls | 56 (34 wrong rules, 12 damaged bytes, 10 out-of-range inputs), 56 detected |

Mutants flip each branch, `set`, `cmov`, immediate and field offset of the seven functions, one at a time, over the cases that reach them (the 410 hand-written cases plus every 25th seeded case; the others are not re-run per mutant). Every survivor and unreached row has its reason in `mutations.tsv`: equivalent clamps and finite guards in the total step, the insertion index of a ring miss (the row treats every miss as absent), one-candidate loop entry in the ring search, the unread handle height, and unwind landing pads.

Negative controls (`controls.tsv`): 34 planted wrong rules (limits off by one, inclusive limit, ignored book or stored size, no saturation, record without the niche word, inverted niche test, wrong asset id mapping, swapped kind, dropped second text, reversed list order, clear that keeps the Mark list, free of an empty buffer, inverted gate, scale 0.125 instead of 0.1, inclusive cap and so on) must each disagree with the real run on some case; 12 damaged bytes (every few killed mutants, named by patched address) must change a result; 10 out-of-range inputs (a binary with one flipped byte, an address inside a function, addresses before and after every mapping, a decoder range cut by a byte, a missing stub, an oversize row count, an unknown template, reads and writes outside the stack and heap) must be refused.

## Results and limitations

- The result is exact only for the stubbed edges. The clone, the map builder and the fold are stubbed, so their rules are not claimed; the specification takes the fold result as an input (`fold`), and only claims that the gate passes the cloned rows, the built map and the owner to them.
- The formatter output is a text word of three words; the real string content is not produced, only the template and the arguments are compared.
- The 13 survivors and 16 unreached rows are listed with reasons; none of them rests on an unproven claim.
- Existing merged work already maps the wrapper `0x3d987f0` and the check call (`RE-001-node115-clearing-result-append`) and the cursor callers (`RE-006-node115-variant-cursor`) as observations of loads and call shapes. This packet adds behaviour: the limits, the saturation, the order of the texts, the ring and tree lookups, the clear and the cap rule.
- The six callers are not read past their call sites. No gate is requested.

Next question: the sibling retain `0x366d200` (3,340 bytes) and the fold `0x44810d0` with the iterator closure `0x37c0fd0`: is the fold the Mark price times stored size sum of the #94 gate?
