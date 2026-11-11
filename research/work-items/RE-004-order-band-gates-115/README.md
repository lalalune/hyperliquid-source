# RE-004: how far from its reference price can a node #115 order be, and what does the spot admission chain around that band do?

This packet lets the Rust reconstruction implement the node #115 order price band exactly (both edges, NaN and zero handling, the `p * 100` payload) and the spot admission chain that decides, before the band, whether a spot token is refused (`0x195`), takes the band, or is capped at `a <= 99999000` (`0x1a2` / `0x100`), because both gates were re-derived from #115 bytes, run as real instructions over 10,842 cases against a separately written specification, and checked with 118 negative controls that were all detected.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `7ff06a097` (main at run time); no reference tree text was used. A node #94 packet of ours (deleted by the migration commit, still in history) was the lead for the band shape and is **not** credited here: every address, constant and behaviour below was re-found in #115 bytes.
- Claim status: observation for the bytes, the float decision, the status words, the chain and the callers; inference for the words "order price", "reference price", "tree set" and "first/second map" on the inputs; unresolved items are listed under limits
- Scope included and excluded: included are the perp gate `0x4488300` and the spot gate `0x3c0f840`, run as whole functions. Stubbed as edges: the perp exemption test (GOT slot `0x64e5ae8`), the hash builder `0x47172c0`, the two table finders `0x3ed2180` and `0x3ed2280`, and the bounds panic slot `0x64df620`. The three other writers of status `0x63` are listed, not read. What the enclosing callers do with a refusal is not claimed. This packet requests no progress gate.

## Reproduce

Working directory is the repository root. Platform Linux x86-64, Python 3.12.3, standard library only. The binary is read as bytes and never run. No external program is called, so the binutils version cannot change a result.

```
python3 tools/artifacts.py verify
python3 tools/order_band_gates_115.py --out research/work-items/RE-004-order-band-gates-115
python3 -m unittest tests.test_order_band_gates_115
```

The tool refuses any input whose SHA-256 differs. It uses `tools/elf_index.py` for sections and `tools/fde_extents.py` for FDE records. Output is byte-identical between runs and between output folders. The tool needs about 1.0 GB resident and about 90 s. `MANIFEST.sha256` lists every file here except itself.

## Evidence

Addresses are virtual addresses; for `.text` and `.rodata` they equal file offsets, and `.data.rel.ro` records were read through the section table.

### Boundaries and reach

`targets.tsv`: spot gate `0x3c0f840..0x3c0fb01` (705 bytes, 172 instructions), perp gate `0x4488300..0x44883e3` (227 bytes, 56 instructions), both exact FDE starts.

`callers.tsv`: neither gate has a direct call. Each is held in one pointer slot (`0x64e6a88` perp, `0x64e6a90` spot, both RELATIVE relocations) and called through it from three sites: perp `0x2894e3c`, `0x517ae1e`, `0x517bf0e`; spot `0x28956bd`, `0x517b66d`, `0x517c75d`.

Status census (`evidence.json` `tag_writes`): `movw $0x63` appears at five places: the two gates (`0x3c0fa4b`, `0x44883d7`) and three more in functions `0x2d3a160`, `0x5a21510` and `0x5a21ed0` that this packet does not read.

### The decision (both gates)

Call the inputs `a` (`r8`), `b` (`r9`) and `p` (`xmm0`). Both gates convert `a` and `b` with the same unsigned sequence (`movq`, `punpckldq` with exponent pair `0x451210`, `subpd` with offset pair `0x450170`, `unpckhpd`, `addsd`), pinned by instruction order and the two constants. Then:

```
r = float(a) / float(b) - 1.0
admitted when p > |r|
else admitted when 1.0 > p and r > 0.0 and 1.0/(1.0 - p) - 1.0 >= r
else status 0x63 with payload p * 100.0
```

`paths.tsv` is the output of a symbolic walk over the real instructions from the divide to the join. It forks at each branch and stops at any instruction it does not model. Both gates give the same five paths, equal to a list written separately in the tool. This covers all `a`, `b` and all 2^64 bit patterns of `p`, NaN included, because each condition is an IEEE compare with the branch's own unordered result.

Consequences: the order side is not an input; the lower edge is strict and the upper edge inclusive (`b = 100`, `p = 0.5`: 50 refused, 51 admitted, 200 admitted, 201 refused); `b = 0` always fails; `p` NaN always fails. `band-edges.tsv` gives the first and last admitted `a` for 11 values of `b` and 8 of `p`, found by binary search on the specification and then run on the real bytes of both gates at `first-1`, `first`, `last`, `last+1` (700 runs). Next to each edge is the exact-fraction edge computed from the stored double; they differ where the stored `p` rounds (for `b = 10^8`, `p = 0.8`: 20000000 refused, 20000001 admitted) and for `b` above 2^53.

### Perp gate `0x4488300`

It calls the pointer in GOT slot `0x64e5ae8` with `rcx`. If the low byte of the result is nonzero the order is admitted at once (status `0x1a2`, `exempt=1`, `0x81` pass; only high bits set, `0x100`, does not). Otherwise the band above runs.

### Spot gate `0x3c0f840`

Inputs `rsi` = state, `rdx` = token index, `r8`/`r9`/`xmm0` as above. In order:

1. `index >= state[+0x20]` panics at record `0x6476678` (`l1/src/spot_meta.rs` line 590 column 25, `panic-records.tsv`). The token key is the first word of row `index` (stride 0x20) of the table at `state[+0x18]`.
2. The key is searched in a B-tree set rooted at `state[+0x210]` with height `state[+0x218]` (node keys at `+8`, length u16 at `+0x62`, edges at `+0x68`). A hit gives status `0x195`.
3. `state[+0x68]` is the entry count of the first map (entries of 24 bytes at `state[+0x60]`, key at `+8`, value at `+0x10`). Count 0, a miss, or a single entry with another key take the band. Count above 1 builds a hasher with `0x47172c0(state[+0x90], state[+0x98])` and finds the key with `0x3ed2180`; an index at or above the count panics at the indexmap record `0x6493b30` (vendored `indexmap` `map.rs` line 762 column 26).
4. The value `v` found is looked up in the second map (`state[+0xf8]` entries; count 0 gives `0x195`; one entry compares `+0x98` with `v`; more build a hasher from `state[+0x120]`, `state[+0x128]` and call `0x3ed2280`; a miss, an out-of-range index or a null entries pointer `state[+0xf0]` give `0x195` or the same panic).
5. A token found in both maps is admitted when `a <= 0x5f5dd18` (99,999,000 = 10^8 - 1000) with status `0x1a2`, else status `0x100`. The band is not run for such tokens.

`status-texts.tsv` gives the Display arms read from the jump table at `0x7d8c1c` (tag word indexes it): `0x63` prints `Order price cannot be more than {}% away from the reference price` (compact run at `0x435ccf`), `0x100` prints `Price too large`, `0x195` prints `Invalid spot`. `0x1a2` has no arm and is the admitted word of both gates.

Relation to the #94 lead (inference only): the #94 gates used other status numbers, called a classifier and a cap helper that returned a stored word `v` and admitted `a <= v - 1000`. In #115 the band bytes are the same but the spot chain is inlined, the statuses are renumbered, and the cap is the constant 10^8 - 1000. This packet does not claim #94 behaves the same.

## Implementation and comparison

`tools/order_band_gates_115.py` contains an x86-64 evaluator (decoder, registers, flags, SSE subset) copied from our earlier tool family and run unmodified on #115 bytes, a separately written specification (`spec`, `band_admits`, `cap_outcome`), a harness that lays out real B-tree nodes and map records in the evaluator's memory, and the symbolic walker. Nothing is run from outside the binary; the stubs check what they receive (hasher words, table pointers, key bytes) and the harness checks that a gate writes only its status word and payload.

Rust path: not yet implemented. The specification is Python and is the reference for a later Rust port.

Cases (10,842 real-byte runs, 0 mismatches): 47 named, 1,349 chain (9 trees x 7 first-map kinds x 7 second-map kinds x 3 values of `a`, plus cap edges and token extremes), 5,746 grid (13 values of `a` and `b` x 17 values of `p`, both gates), 3,000 pseudo-random, 700 band-edge runs. Outcomes: 6,692 band refusals `0x63`, 2,552 `0x1a2`, 668 `0x195`, 46 `0x100`, 184 panics.

Negative controls (118, all detected): 80 byte mutants of reached instructions in the two gates (condition, immediate, shift, displacement; 80 killed, 0 survivors), 21 wrong specifications (closed lower edge, open upper edge, no upper branch, mirrored edge, absolute-difference band, multiplicative band, cap one higher/lower/at 10^8, payload scale 10 and 1, exchanged statuses, swapped inputs, tree set ignored, second map ignored, first-map miss treated as hit, exemption never taken, cap applied to the band), 12 corrupted rodata constants (two bytes of each of the six constants), and 5 rejected inputs (wrong digest, unknown case field, address outside every section, gate start plus one, NOBITS address). `mutations.tsv`, `wrong-implementations.tsv`, `corrupted-constants.tsv` and `rejected-inputs.tsv` list them.

Run listings: `chain-runs.tsv` (all 1,349 chain runs), `edge-runs.tsv` (all 700 band-edge runs) and `grid-runs.tsv` (every fifth grid run) give the case parameters and the real-byte result; `evidence.json` holds `run_digest`, the SHA-256 over one line per real run of all 10,842, so the unlisted runs are regenerated by the tool and checked by hash. `outcomes.tsv` lists the 47 named cases.

## Results and limitations

- 49 unit tests, 0 skipped. `measure.json`: 10,842 cases, 118 negative controls, 118 detected. `evidence.json` holds the per-group counts.
- The symbolic walk starts at the divide. The conversion before it is pinned by instruction sequence and constants; the mapping of `a` and `b` onto `r8` and `r9` is shown by runs, not by the walk.
- That `a` is the order price and `b` the reference price comes from the message text, not from a traced call site. `b` was not traced to one source.
- The exemption call, hash builder and table finders are stubs: the packet shows the calls made and the arguments, not what the stubbed callees compute. Which tokens fill the tree set and the two maps, and what the first and second map are, is not established.
- A mutation on the length counter and the cap immediate survived until the `leaf_above`/`deep_above` trees and cap-edge cases were added; they are now part of the mutation set.
- Whether the perp exemption is a user test, how the vote value (`max_order_distance_from_anchor`, key string present in eight places of the binary) reaches `xmm0`, and what the three other `0x63` writers do were not traced.
- Next question: read `0x2d3a160`, `0x5a21510` and `0x5a21ed0` (the other writers of status `0x63`, also with a divide) and the three call sites of each gate, to learn which order actions reach this band.
