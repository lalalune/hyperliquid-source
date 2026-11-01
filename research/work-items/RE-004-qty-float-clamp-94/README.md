# RE-004: two quantity floating-point conversion paths

The two #94 quantity conversion paths differ after multiplying by a floating-point factor: one discards negative results, while the other preserves them and first replaces the factor with its complement.

- Component ID: RE-004 (quantities and rounding).
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` / `999556f6e0a474b8312db96ec3149e1c44e97c23` (reference is an unlicensed lead, not implementation).
- Claim status: byte and FDE observations; instruction interpretation and models as stated below; quantity units and caller contracts unresolved.
- Scope included and excluded: two complete FDE ranges, their conversion branches and referenced floating-point constants. Callers, semantics of the panic helper, MXCSR configuration, node #115 and execution of captured binaries are excluded.

## Reproduce

From the repository root, with Python 3 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/qty_float_clamp.py --out research/work-items/RE-004-qty-float-clamp-94
python3 -m unittest tests.test_qty_float_clamp
(cd research/work-items/RE-004-qty-float-clamp-94 && sha256sum -c MANIFEST.sha256)
```

For determinism, run the generator with `--out <first-dir>` and `--out <second-dir>` under different hash seeds and time zones, then compare the two directories. The generator checks the complete target digest, reads file-backed ELF sections through `tools/elf_index.py` and FDEs through `tools/fde_extents.py`, then checks the full bytes of both ranges. It writes `evidence.json` and `model-vectors.tsv`. No target executable or external program is launched by the generator or tests. The byte interpretation below was read using GNU objdump in Intel syntax; its output is not used by the generator.

## Evidence

All addresses are node #94 ELF virtual addresses; file offsets, exact range bytes, SHA-256 and FDE addresses are in `evidence.json`. The FDE extents are `[0x3c06160, 0x3c0620a)` and `[0x4cda1a0, 0x4cda253)`. Each starts with the input test and ends in its failure call; FDE extents are unwind ranges and do not establish all source boundaries. Both failure paths pass a location record whose relocated path ends `l1/src/qtys/mod.rs`, line 843, column 1. That association does not establish a source-level function name or unit.

The first argument is read from `rdi` as a 64-bit word; the floating-point argument is in `xmm0`. Reading the instructions gives the following complete local branch map, conditional on the floating-point environment:

| Condition | Product path at `0x3c06160` | Complement path at `0x4cda1a0` |
| --- | --- | --- |
| input top bit set | call the unwrap failure path | call the unwrap failure path |
| input top bit clear | convert the input as signed integer to binary64 and multiply by the factor | compute binary64 `1.0 - factor`, convert input to binary64 and multiply |
| product is NaN or infinity | replace the intermediate with zero | replace the intermediate with zero |
| finite product outside signed 64-bit range | clamp using binary64 endpoints | clamp using binary64 endpoints |
| conversion to integer | truncate toward zero, with the upper endpoint corrected to `i64::MAX` | same conversion |
| negative converted integer | return zero | return the signed value |

The finite test masks the sign bit and compares against the largest finite binary64 bit pattern. The conversion uses `cvttsd2si`; a comparison with the greatest binary64 below `2^63` corrects the upper endpoint. The constants in the table are read from the ELF and validated as bit patterns; they include `1.0`, `-2^63`, `2^63`, and the binary64 immediately below `2^63`. The product and complement paths each test the input before conversion, so even a zero factor does not bypass the failure path for an input with its high bit set.

The conversion tail after the product admits a full binary64 partition independent of the multiplication: for either sign, exponent fields below 1086 have magnitude below `2^63`; fields 1086 through 2046 have magnitude at least `2^63`; field 2047 is non-finite. In the first interval `cvttsd2si` truncates in range. In the second the clamp reaches an endpoint, and the upper correction changes positive `2^63` to `i64::MAX`. The final nonnegative clamp belongs only to the first path. These relationships hold for all mantissas in each interval, not only the endpoints, because the interval cannot cross either bound and the conversion truncates toward zero. The generator checks both mantissa endpoints of every finite sign/exponent class (8188 endpoint cases) and records the partition counts. This establishes the tail conditional on the static instruction reading; it does not establish the preceding multiplication or the node's runtime floating-point environment.

`model-vectors.tsv` is a table of **model predictions**, not captured execution. Under round-to-nearest binary64 arithmetic, input 3 and factor 1.5 yield 4 for the first path and -1 for the second. With input 1, infinite or NaN factors produce 0 in both models. Input `2^63` predicts the failure call regardless of factor. These examples distinguish truncation, sign handling, non-finite handling and guard order; they do not establish that these values occur at any caller.

## Implementation and comparison

Not yet implemented. There is no independently authored Rust component, Cargo lock, target execution, native differential comparison or binary identity claim. `model-vectors.tsv` contains 180 predictions from the Python model over nine input words and ten binary64 factors for each function; it is not an execution trace or a whole-domain proof. No operand normalization or masks are used for comparing the pinned function bytes. The model assumes round-to-nearest, ties-to-even for integer-to-double and arithmetic; the node's MXCSR state is not established here. NaN payloads and floating-point exception flags are not modelled.

The seven unit tests exercise the input digest, complete function-byte pins, a changed constant, a damaged conversion threshold, an unmapped range, the two distinct negative-result paths, the top-bit failure branch, endpoint saturation, and non-finite factors. The altered-byte checks bypass the digest only to exercise the more focused checks; normal generation always validates the digest first. They test the evidence reader and interpreted model, not the target's runtime behavior.

## Results and limitations

Two FDE ranges and four floating-point constants are pinned. The branch map is a static interpretation of their complete bytes; it has not been checked by executing the node. The whole-path model is sampled at 180 combinations; the conversion-tail partition covers all binary64 product bit patterns under the stated instruction interpretation. The failure helper's behavior beyond the call and the origin, scale and intended type of the inputs remain unresolved. The complement operation and the nonnegative output rule must not be generalized to other quantity helpers. No RE-004 progress gate is requested.

Next question: establish the caller contracts and floating-point environment for these conversions without overlapping the separately mapped caller functions.
