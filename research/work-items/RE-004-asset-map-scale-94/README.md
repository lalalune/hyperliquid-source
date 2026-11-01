# RE-004: asset-keyed million-scale values and their output builder

This packet establishes that the asset-keyed output path first converts an unsigned 64-bit value to binary64 and then divides by one million, so a reconstruction must preserve both rounding steps even when an asset lookup fails.

- Component ID: RE-004, assets and fixed-point quantities.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `d3af75257a396c85d20857f421c370ddb8cb40e5`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as an unverified lead.
- Claim status: observations for bytes, branch destinations, FDE ranges and row layout; arithmetic inference under the normal IEEE-754 round-to-nearest-even mode; value and output names remain unresolved.
- Scope included and excluded: the value projection at `0x26b3890`, its builder at `0x27ed840`, and their call at `0x27d6abd`. This is not a claim about all quantity conversions, the complete B-tree implementation, the meaning of the map, other call paths, or node #115.

## Reproduce

Run from the repository root using Python 3.12.3 or a compatible Python 3 with the standard library. The generator imports the repository ELF and FDE readers, verifies the full target SHA-256 before analysis, reads file-backed sections only, and never runs the target. It emits only the two generated files in this directory. It invokes no external program. The generator takes seconds.

```sh
python3 tools/artifacts.py verify
python3 tools/asset_map_scale94.py --out research/work-items/RE-004-asset-map-scale-94
python3 -m unittest tests.test_asset_map_scale94
python3 tools/catalogue.py --check
```

For an independent reproducibility check, generate to two different relative output directories and compare `evidence.json` and `rounding-vectors.tsv` byte for byte. `MANIFEST.sha256` records the output and README hashes. No source build or target execution is involved.

## Evidence

Coordinates are node #94 ELF virtual addresses. FDE records bound `0x26b3890..0x26b3c17` and `0x27ed840..0x27eda58`; FDE bounds establish unwind coverage, not necessarily source-level function boundaries. `evidence.json` contains the FDEs and hashes, exact anchored instruction bytes, 17 decoded conditional destinations, floating constants, two panic locations and the reciprocal proof. `rounding-vectors.tsv` contains 65 exact rational-model vectors. No objdump output is parsed or included in generated evidence.

The enclosing FDE enters the builder only after a lookup returns tag `0x186` and the returned object byte at `+0x230` differs from 3. It obtains a map object through `+0x208`, takes the root at map `+0x30` and the associated iterator words at `+0x38/+0x40`, and passes the returned object for metadata lookup. A null root selects an empty iterator. The meaning of these fields remains unproven.

The builder `0x27ed840` checks a count multiplied by 32 for allocation overflow and allocation failure. It invokes `0x26b3890` at `0x27ed8ec`; an empty result produces an empty output, one row skips the two sorting calls, 2..20 rows go through the direct sort helper at `0x2847de0`, and at least 21 go through the slot at `0x5774fc8`. The builder then passes the rows to `0x1b08430`; the detailed behavior of these helpers is not established here. The enclosing FDE calls the builder at `0x27d6abd`.

For each input entry in `0x26b3890`, the key is read at `0x26b3af7`, and its associated 64-bit value at `0x26b3afc`. The code computes `q = key / 10000` and `r = key % 10000` with multiplier `0x346dc5d63886594b`, the high product and shift 11. It compares `q` to metadata `+0x30`, and `r` to length `+0x10`. On a match it reads a row of stride 48 from pointer `+8`, copies its pointer/length fields at row `+8/+0x10`, and allocates for a nonempty string. Both lookup failures use an empty string (length 0, pointer 1), then still convert and append the value. An allocation failure takes the allocation failure path. The generated branch table captures these paths. Inconsistent iterator state reaches panic locations `alloc/src/collections/btree/navigate.rs:161:36` or `:534:47`; the mapping of inputs to those internal states is not reconstructed.

The quotient formula is proved over all u64 keys, not sampled. Let `M = 0x346dc5d63886594b`, `D = 10000`, and `B = 2^75`. The bytes give `M*D = B + 432`. For `key = q*D+r`, `0 <= r < D`, the tool verifies `(floor((2^64-1)/D)*432 + 9999*M) < B`. Thus the excess cannot advance the quotient and `(key*M)>>75 = floor(key/D)` throughout the domain. This proof applies to the integer key calculation, not to a financial unit conversion.

At `0x26b3905` the `punpckldq/subpd/addsd` sequence converts the value to binary64; `divsd` divides by the binary64 constant at `0x20ae60`, whose bytes are `0000000080842e41` (1,000,000.0). The result is stored at row `+0x18`, after the three string words, in a 32-byte output row. The instructions do not themselves set the floating-point rounding mode. Under round-to-nearest-even the target sequence has the mathematical form `RN64(RN64(x) / 1000000)`. The vector model uses integer fractions and exact tie handling; it does not execute the machine instructions or establish the runtime floating-point environment.

For example, at `x = 9007199254740993`, the first conversion rounds to the same binary64 value as `9007199254740992`. The two-step model produces `0x4200c6f7a0b5ed8d`; directly rounding the exact ratio produces `0x4200c6f7a0b5ed8e`. This is a concrete difference between the two possible reconstructions, not an observation from running the node.

The earlier `RE-006-oi-cap-aggressive-cancel-94` packet describes an object with the same `+0x230` mode gate and a map at `+0x208` whose `+0x30` tree is used as a per-asset cap against a price-times-size product. The matching offsets and key shape support the inference that the present output is a per-asset cap view and the million divisor is a notional display scale. They do not prove that both objects have the same type or establish the API name, source-language signedness, or the economic unit independently. The referenced `impl_ntl.rs` is an additional unverified lead.

## Implementation and comparison

Not yet implemented. No Rust build, lockfile, raw or normalized compiled comparison, helper closure, relocation closure, or target-execution fixture is claimed. Exact byte patterns and branch destinations are checked before records are generated. Nine local unittest cases include a bad input digest, corrupted conversion bytes, altered branch displacement, unmapped and section-crossing addresses, floating-point ties and u64 range controls, integer quotient boundaries, and a separate host binary64 cross-check for decimal boundaries. The integer/rational model is separate from the binary and is not an emulator.

## Results and limitations

The retained evidence covers 2 connected FDEs and one outer call-site FDE, 19 anchored byte sequences, 17 conditional branches, 3 floating constant byte ranges, 2 panic locations and 65 rational-model vectors. The quotient proof covers all 2^64 keys. The model vectors are sampled, not a proof that the instruction sequence executes on every state or that the process uses the assumed rounding mode. The FDEs can include cold or cleanup blocks and do not prove source boundaries. Sorting, tree traversal, aliasing and allocation behavior beyond the recorded branches remain open. No full-scope progress gate is requested.

Next question: bind the iterator's originating state field and its serialized output name to the map so the raw value's economic unit can be established from target evidence.
