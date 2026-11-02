# RE-004: node 94 blob-gas wei price and staged integer rounding

The EVM blob-gas price path uses a checked 128-bit integer series with a floor at every term and one at the end; preserving those intermediate floors, rather than rounding an ideal exponential once, changes the price for some positive inputs.

- Component ID: RE-004, quantities and rounding; EVM blob-gas wei price.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `966865f1637a29ce75b019e1bf11d5529cc6f519` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The inferred reference is used only as a lead; no source was copied.
- Claim status: observations are the ELF bytes, unwind ranges, relocation relationships, source-location suffixes and extracted constants. Equations below are a manual instruction lift; numerical cases and whole-input bounds are conditional on that lift and the modeled division helper. Blob-gas names and units are inferences, with support described below.
- Scope included and excluded: the version-dependent caller `0x4e4ad50`, fixed series helper `0x4ea1e00`, and independently compiled configurable current/parent series functions `0x134c4e0` and `0x134beb0`. Included are their arithmetic windows, guards and selected failure edges. The generic functions are companion implementations, not established callers or callees of the fixed helper. Excluded are the shared division and failure-handler bodies, the complete caller outside the selected slice, chain configuration, input reachability, runtime floating-point settings, node #115 and visor.

## Reproduce

From the repository root, with the authenticated artifact present:

```sh
python3 tools/artifacts.py verify
python3 tools/blob_wei_price.py --out research/work-items/RE-004-blob-wei-price-94
python3 -m unittest tests.test_blob_wei_price
python3 tools/catalogue.py --check
```

The generator uses the Python standard library and `tools/elf_index.py` and `tools/fde_extents.py`. It checks the whole artifact SHA-256 before analysis, resolves only file-backed sections, verifies all four FDE body hashes and 24 instruction windows, and does not invoke a disassembler or execute the artifact. Generated files are `summary.json`, `functions.tsv`, `windows.tsv`, `links.tsv`, `branches.tsv`, `handlers.tsv`, `locations.tsv`, `selector-cases.tsv`, `selector-table.tsv`, `cases.tsv`, `walk-cases.tsv`, `walk-sites.tsv`, `generic-cases.tsv`, `parent-cases.tsv`, `bounds.tsv`, `series-comparison.tsv`, and `saturation-comparison.tsv`. `MANIFEST.sha256` also covers this README.

For a determinism check, run the generator into two different output directories with different `PYTHONHASHSEED` and `TZ` values, and compare their contents before adding this README and manifest. Reproduction needs no binutils. Paths recovered from Rust Location records are reduced to crate-relative suffixes; their original prefixes are omitted.

## Evidence

All addresses are linked, unrebased ELF virtual addresses. `functions.tsv` gives FDE ranges and `windows.tsv` gives original bytes at the selected instruction windows. FDEs are unwind ranges, not proof that all functions or entry points have been found. `branches.tsv` resolves 38 selected branch displacements, including the arithmetic failures and back edges. `handlers.tsv` binds 17 handler entries to the embedded source-location records. `links.tsv` resolves eight encoded indirect-call slots; seven division sites resolve to one shared helper, whose body is not analyzed here.

### Caller and fork selector

At `0x4e4ae35`, the caller compares a version byte with 18. It selects target 393216 below 18 and 786432 at or above 18. When the two 32-bit presence tags at input `+0x10` and `+0x20` both equal 1, it adds the two u64 words at `+0x18` and `+0x28`, takes an overflow handler if the sum does not fit, and otherwise computes `max(sum - target, 0)`. If either tag is absent, version 17 calls with excess zero; other versions skip this particular call. The resulting u64 and `version >= 18` flag are passed through the relocated slot at `0x4e4ae91` to `0x4ea1e00`. The seven modeled cases cover numerical boundaries; `selector-table.tsv` enumerates all 256 version bytes and the four presence combinations for one chosen pair of words. These records do not establish what the caller does on its other paths.

The fixed callee chooses `D = 3338477` for flag zero and `D = 5007716` for a nonzero flag. Both values are instruction immediates. The source locations reached by its overflow edges have the crate-relative suffix `revm-primitives-15.1.0/src/utilities.rs`; the two generic paths have locations in `alloy-eips-0.9.2/src/eip4844/mod.rs` and `alloy-eips-0.9.2/src/eip7840.rs`. Those locations identify code provenance, not function signatures or proof of runtime use. The reference's fee-history description separately calls its blob price a fake exponential with factor 1 and denominator 3338477. Together with the target constants and caller, these are evidence for the blob-gas price interpretation, not a complete chain of API ownership.

### Fixed series

A manual lift of the fixed helper, conditional on the called shared helper implementing unsigned 128-bit quotient, is:

```text
sum = 0; term = D; i = 1
while term != 0:
    sum = checked_u128_add(sum, term)
    numerator = checked_u128_mul(term, excess_u64)
    denominator = checked_u128_mul(i, D)
    term = floor(numerator / denominator)
    i += 1
price = floor(sum / D)
```

`excess` is the incoming u64, not a value inferred from a Python fixture. The body contains separate 64-bit limb multiplies and carry checks, two copies of the loop selected by the flag, and distinct handler edges for sum, term product and denominator product. The checked operations occur in the order shown. The code tests the original numerator against the iteration denominator after the call: under the quotient assumption this is equivalent to testing whether the next term is nonzero. It writes the two 64-bit quotient limbs and retains the input excess in the result. The fixed denominator is nonzero in both arms. The lift does not characterize callee behavior for invalid machine states or prove that a particular input is reachable from a valid block.

### Generic current and parent inputs

The configurable current-excess function first tests a presence tag. An absent value returns an absent result before reading the denominator. With a present value it checks a u128 denominator for zero, computes a checked u128 initial term `factor * denominator`, and uses the same staged series. A zero factor produces zero; factor-times-denominator overflow and zero denominator follow separate handler edges. The factor and denominator each occupy two u64 limbs. `generic-cases.tsv` covers those edge conditions and compares both fixed denominators against factor 1 at six excess values each. This is a comparison of lifts, not execution of either target body.

The configurable parent path requires two presence tags. With both present, its first calculation is checked u64 `old_excess + used`; its next is checked `target_count << 17` (a target count with any bit at or above bit 47 is refused); it then uses `max(sum - shifted_target, 0)` as excess in the configurable series. The seven modeled cases include absent inputs, exact equality, one above equality, and both overflow checks. The integer 131072 comes from the instruction shift, not an assumed external constant.

### Rounding and bounds

The two paths do not perform a single final rounding of a mathematical exponential. `series-comparison.tsv` uses exact rational terms and bounds the omitted positive tail to determine the floor of the ideal exponential independently of floating-point arithmetic:

| D | excess | staged floor | floor of ideal exp(excess / D) |
|---:|---:|---:|---:|
| 3338477 | 70108017 | 1318815733 | 1318815734 |
| 5007716 | 110169752 | 3584912845 | 3584912846 |

The comparison uses the lifted model, and the corresponding staged results are among the byte-walk cases described below; neither is a captured node execution. The ideal exponential is a comparison only; it is not claimed to be a node intermediate.

For fixed positive D and factor 1, every term and accumulated sum is nondecreasing in the u64 excess until either execution terminates or a checked operation fails. This follows by induction from multiplication by a nonnegative excess and floor division by the same positive `i * D`. Therefore an input no larger than a successful input cannot fail on an earlier checked term, and any input larger than a term-product failure must encounter a failure no later than that iteration. The generator binary-searches and checks the adjacent boundary values under the lift:

| D | greatest modeled successful u64 excess | next input | first failure in next input |
|---:|---:|---:|---|
| 3338477 | 192204552 | 192204553 | term product, iteration 58 |
| 5007716 | 284284038 | 284284039 | term product, iteration 57 |

At or below the successful boundary, monotonicity also bounds the number of iterations by that boundary run; above it, some checked failure occurs no later than the first failing boundary run. On the same assumptions, every u64 input therefore finishes or reaches a failure within 168 iterations. With either observed denominator, the iteration-denominator product and iteration counter cannot overflow within that bound. The corresponding encoded failure edges remain recorded.

Thus the mathematical boundary covers the entire u64 input domain **conditional on the lift and division semantics**. It is not an instruction-level symbolic proof, a claim that those excesses are reachable, or a test against an executing node. The failure edge is reported as a checked arithmetic handler; its wider effects are outside this packet.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No reconstructed binary, byte-equivalence result, build scope, or target execution is claimed. A bounded byte walker interprets the real instructions in the two fixed loop slices, models only the shared quotient call, and compares status, iteration count and price against a separate arithmetic specification. It starts at the loop with manually reconstructed initial registers and models the final divide; the caller, prologue, generic functions and handler bodies are not interpreted. An unknown instruction or a branch leaving the selected loop fails closed. The shared quotient helper and all failure handlers remain assumptions.

The inferred reference fee-history lead aliases its `U256` name to u128 and saturates additions and multiplications. On the first denominator and excess 192204553, the lifted target takes the term-product overflow handler, while the saturating arithmetic model produces 10079295377470422497392048 (`saturation-comparison.tsv`). This compares semantics read from an unlicensed lead with a model; the reference was not compiled or copied. The lead provides only one of the two denominator choices; the target bytes select a second, and a separate target caller provides the two version-dependent target values. Neither observation establishes which version byte can occur on a deployed network.

## Results and limitations

The generator records four FDE bodies, 24 pinned windows, 38 branch destinations, 17 handler-to-location links, eight call links, 11 sanitized source locations, seven selector cases, 1024 version/presence combinations, 30 fixed-series cases, 19 generic cases, seven parent cases, two boundary rows and two exact-rational comparisons and two saturation comparisons. The byte walker covers 62 cases and 88 distinct instruction sites; all 62 match the arithmetic specification. The 22 focused tests include a wrong artifact digest, a duplicate selected FDE, a malformed ELF, a corrupted function with a recomputed digest, a corrupted pinned instruction even after substituting a new body hash, a changed branch destination, a changed indirect-call displacement, an unknown walked opcode, out-of-range and NOBITS address controls, carry and multiply boundaries, and zero/overflow/absent cases. Reduced-width multiplication is checked over 65536 pairs; this tests the arithmetic lift, not all target instructions.

Remaining gaps are the quotient helper, the omitted parts of the caller, real block and version constraints, the exact public API route, and executable comparison. No full-scope milestone is advanced. Next question: which authenticated block fields and version settings feed this caller, and can an independently authored Rust implementation reproduce these staged prices under an authorized offline harness?
