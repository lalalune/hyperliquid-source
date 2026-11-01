# RE-004: fixed-eight floating-point formatting and rounding path

Node #94 routes a quantity-linked binary64 value through an eight-place formatter with an intermediate half-up product, a separate fallback parity decision, and a trailing-zero normalization step, which a reconstruction must preserve as distinct stages.

- Component ID: RE-004 (quantities and rounding).
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was used only for search leads, not copied as implementation.
- Claim status: byte identities, relocations, selected branches, literals, and instructions are observations. Input meaning and the connection to the previously studied formatter controller are qualified inferences. The complete floating-point-to-text relation, final rounding correctness, and dynamic reachability remain unresolved.
- Scope included and excluded: seven selected FDE ranges and the arithmetic and branches described below; shared formatter and caller bodies are prior work and are included only as explicitly identified edges. The FDE ranges are unwind extents, not a claim that every function boundary or every basic block has been independently established. This is node #94 only.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 and the standard library. The target is only read. The generator checks the complete target digest before parsing ELF sections, relative relocations, and unwind records using the repository's shared parsers. It validates fixed instruction patterns and applies mathematical transcriptions; it does not run the node, invoke an instruction evaluator, invoke a disassembler, access the network, or read local runtime state. It writes only its requested output directory.

```sh
python3 tools/artifacts.py verify
python3 -m unittest tests.test_fixed8_float_rounding94 -v
python3 tools/fixed8_float_rounding94.py --out research/work-items/RE-004-fixed8-float-rounding-94
(cd research/work-items/RE-004-fixed8-float-rounding-94 && sha256sum -c MANIFEST.sha256)
python3 tools/catalogue.py --check
```

For an independent deterministic regeneration, replace `<dir-a>` and `<dir-b>` with two fresh output directories, then run:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/fixed8_float_rounding94.py --out <dir-a>
PYTHONHASHSEED=777 TZ=Pacific/Kiritimati python3 tools/fixed8_float_rounding94.py --out <dir-b>
diff -r <dir-a> <dir-b>
```

`MANIFEST.sha256` binds this README and all generated files. `evidence.json` contains every selected FDE body as raw hex, its digest, file offset, CIE/FDE address, selected windows, call edges, constants and counts. `branches.tsv` contains 69 selected conditional instruction sites; it is not a complete control-flow graph. `power-table.tsv`, `index-partitions.tsv`, `guard-cases.tsv`, `product-cases.tsv`, `carry-cases.tsv`, `piece-cases.tsv`, `trim-cases.tsv`, and `float-model.tsv` contain the generated data and explicitly scoped mathematical examples. All addresses below are ELF virtual addresses before any load bias; file offsets are recorded separately in `evidence.json`.

## Evidence

### Call path and format request

| Selected FDE start | End, exclusive | Role supported by the selected bytes |
| --- | --- | --- |
| `0x13cd260` | `0x13cd40b` | request a float format, then strip bytes and normalize `-0` |
| `0x15711b0` | `0x15715c5` | classify binary64, choose digit generation and write pieces |
| `0x1575e20` | `0x1575f87` | arrange decimal digit, point and zero pieces |
| `0x1575f90` | `0x1576131` | decide fast rounding or return a null result |
| `0x1576140` | `0x157653a` | normalize, select a power and generate fast digits |
| `0x1576b90` | `0x1577bcf` | fallback digit generation, limb comparison and carry |
| `0x15728c0` | `0x1572b1a` | write the resulting pieces through a formatter |

At `0x3330289`, the RIP-relative slot `0x576ea10` has an `R_X86_64_RELATIVE` relocation to `0x13cd260`. That call is in the same indexed caller FDE as the previously documented exponent-8 decimal-to-scaled-integer call at `0x33304df` in `research/work-items/RE-004-decimal-scaled-u64-94`. This supports a quantity-conversion connection; it does not by itself prove which external field, unit, or business operation reaches the call.

The new wrapper stores the incoming XMM0 binary64, places the previously scoped float callback from slot `0x576ea18` in descriptor row 0, stores `8` in the second word of row 1 at `0x13cd28f`, and passes request bytes `e5 20 00 00 70 01 00 00` from `0x20a150`. Its indirect formatting call uses slot `0x576e040`, and an external edge at `0x1344873` uses slot `0x576e008` to reach the previously studied controller `0x1571d90`.

Under the request relation already established in `research/work-items/RE-001-format-request-controller-94`, tag `e5` supplies options `0x70000020`, loads second quantity index 1, and substitutes the low 16 bits of row 1's second word, giving 8. The previously scoped callback at `0x1571d50` tests option bit `0x10000000`, loads that quantity, and its edge at `0x1571d7f` enters `0x15711b0`. The controller and callback are dependencies, not newly claimed subject functions; `evidence.json` retains their exact connecting bytes and relocations. The relation assumes normal allocation, unmodified descriptors and the previously documented controller semantics.

The formatter calls the fast generator at `0x15713bb`. A zero first output word branches at `0x15713c9` to the fallback call at `0x15714ba`; the two generators' outputs then either feed the decimal-piece builder at `0x157140e` or the formatter's zero-piece branch. Both eventually reach the piece writer at `0x1571573`. The fast generator calls `0x1575f90` at `0x15763da` and `0x1576498`; the guard's fallback leaf writes a zero first result word. These are direct and relocation-resolved static edges, not measured runtime coverage.

### Binary64 classification, table and bounds

The five-entry relative jump table at `0x251b18` dispatches NaN, infinity, zero, subnormal and normal classes. The bytes at `0x255d3f` contain `NaNinf0.`. Let `E` be the 11-bit encoded exponent and `F` the 52-bit fraction. For each nonzero finite input the selected instructions produce a positive integer `m` and signed exponent `e` such that the absolute input is exactly `m * 2^e`:

| Class | `m` | `e` |
| --- | --- | --- |
| Subnormal, `F > 0` | `2F` | `-1075` |
| Normal, `F = 0` | `2^54` | `E - 1077` |
| Normal, `F > 0` | `2 * (2^52 + F)` | `E - 1076` |

The sign is handled separately. Thus `2 <= m <= 2^54` and `-1076 <= e <= 970`. Before calling the fast generator, `0x15711b0` computes `metric = -12*e` for negative `e`, otherwise `5*e`, checks it against 16064, and calculates `(metric >> 4) + 21`. On this finite domain the metric is at most 12912 and the length lies in 21..828. Together with the `m` range, this excludes the observed formatter-capacity assertion and the fast generator's zero-mantissa, too-wide-mantissa and empty-buffer assertions for this route. Their literal bytes and branch sites are included; this does not exclude unrelated memory or callback failures.

For a nonzero `m`, let `L` be its count of leading zero bits in a 64-bit word. The fast table index is the unsigned result of

```text
z = (-96 - (e - L)) * 80 + 86960
index = (z * 2068695443) >> 42
```

For normal numbers, both `F = 0` and `F > 0` give `e - L = E - 1086`, so `z = 166160 - 80E`. For a subnormal with highest set fraction bit `j` in 0..51, `e - L = j - 1137`, so `z = 170240 - 80j`. These expressions are positive and fit the signed intermediate widths on this domain. The 2,046 normal exponent groups and 52 subnormal leading-bit groups cover every nonzero finite binary64 pattern; 6,242 representative endpoints verify the partition calculations. The table index spans exactly 1..80, so the unsigned `index > 80` failure at `0x15761c1` is also unreachable in this qualified domain. Row 0 exists but is not selected there. This is an algebraic range argument, not a claim of exhaustive target execution.

The relocation at `0x5770680` points to 81 file-backed, 16-byte records at `0x255db8`, each laid out as `<u64 mantissa, i16 binary_exponent, i16 decimal_exponent, u32 zero>`. Their decimal exponents are `-308 + 8*i`, for `i = 0..80`. Exact rational arithmetic verifies every stored mantissa as `round_to_nearest_even(10^decimal_exponent / 2^binary_exponent)`: 49 are below the exact rational, 29 above it, and 3 exact. This describes the stored approximation, not final printed-value rounding.

At `0x15761d5`, the normalized mantissa and table mantissa are multiplied to a 128-bit product. The machine adds the top bit of the low word to the high word. For any two unsigned 64-bit inputs this is `floor((product + 2^63) / 2^64)`, including half-up ties; it is an intermediate approximation. The minimum positive normal binary64 (`0x0010000000000000`) provides an actual table/input witness: index 78, high word `0x6a198bcece465c20`, low word `0x8000000000000000`. This step returns `0x6a198bcece465c21`; half-even at this intermediate point would return `0x6a198bcece465c20`. It does not establish a difference in the final formatted text.

### Decisions, decimal pieces and failures

In the guard at `0x1575f9e..0x1575fe1`, let `a`, `b`, and `c` be the three incoming stack words at frame offsets `+0x10`, `+0x18`, and `+0x20`. For the stated domain `0 <= a <= b < 2^64` and `0 < c < 2^64`, the byte-bound unsigned predicates simplify to the following ordered relation:

| Condition | Result |
| --- | --- |
| `2*c >= b` | null result; caller may use fallback |
| `2*(a+c) <= b` | keep the digits |
| `2*(a-c) >= b` | increment the digits |
| otherwise | null result; caller may use fallback |

The first two machine subtractions establish `b > 2*c` before `2*c` is used; the other subtractions are nonnegative where used on this domain. This proves the equivalence without assuming wrapping multiplication or addition. The connection between all possible live guard operands and this domain, and the semantic meaning of `a`, `b`, and `c`, are not yet proved. The tool additionally compares a direct predicate transcription and the simplified inequalities over every 6-bit domain triple and a larger selected 7-bit set; these are controls, not a substitute for the stated domain argument.

In the fallback at `0x1577950`, equal-length 32-bit limb arrays are compared from most significant limb to least. A greater result selects increment; a lesser result keeps the digits. On equality, the `AL == 0` path tests the low bit of the last output byte at `0x1577a34` and increments on odd; `AL != 0` selects a zero-length result. The increment code walks backward over ASCII `9`, increments the first preceding byte, and handles an all-`9` carry separately. The meaning of the two limb arrays as an exact remainder and midpoint has not been established; therefore this parity branch alone does not prove nearest-even final output for all inputs.

Together the fast and fallback carry code use four relocation-resolved calls to the `memset` dynamic symbol through slot `0x576e1f8`; the generated records preserve the `R_X86_64_GLOB_DAT` symbol index and name. Assuming normal symbol resolution and a nonempty valid ASCII digit buffer, both paths increment the last non-`9` digit and fill its following `9` bytes with `0`. For all `9` digits, both write `1` followed by zeros, increase the stored 16-bit decimal-position word, and may append another `0` when there is capacity. The following comparison is restricted to the fallback's `AL == 0` branch:

| State for an all-`9` buffer | Fast path append test | Fallback append test |
| --- | --- | --- |
| signed position `p < 32767` | `p + 1 > cutoff` | `p >= cutoff` |
| signed position `p = 32767` | wrapped `-32768 > cutoff` | `32767 >= cutoff` |

Both also require `length < capacity`. The tests are equivalent throughout the first row. At the signed upper bound they differ for every signed 16-bit cutoff when spare capacity exists: a synthetic input `9`, position 32767, cutoff 0, capacity 2 gives fast digits `1` and fallback digits `10`, with stored position wrapping to -32768 in each. This is a property of the selected comparison and write branches, not a demonstrated reachable binary64 state or a claim of different numeric output. The empty-buffer case and the fallback `AL != 0` carry variant are excluded from this relation.

The piece builder checks a nonempty digit buffer, first byte greater than ASCII `0`, and a piece capacity of at least four. Its caller passes four. For signed decimal position `d`, it builds `0.` plus leading zero pieces when `d <= 0`, splits the digit slice with a decimal point when `0 < d < digit_count`, and appends integer zeros when `d >= digit_count`. It appends fractional zeros as needed for the requested precision. For example the generated synthetic pieces for digits `123`, `d = 1`, precision 8 render `1.23000000`. These are builder-input examples; the digit generator has not been proved to produce those inputs for a particular binary64 value.

After successful writing, the outer wrapper repeatedly removes trailing ASCII `0`, then removes one trailing `.`, and changes the exact remaining bytes `-0` to `0`. The branch immediately after matching byte `0` checks that same byte's sign; it takes the one-byte path on stable memory. This is a byte rule: for the synthetic string `1000` with no decimal point it yields `1`; the packet does not assert that the formatter actually emits that input. Failure paths include the piece builder's three assertion branches, writer callback errors that return a nonzero status, and the wrapper's one-byte allocation failure branch followed by an allocation-failure call and `ud2`. Other allocator, unwind, writer, and panic behavior is outside this bounded analysis.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler and linker scope, compiled target comparison, two-build comparison, normalization masks, helper closure, vtable/data closure, relocations beyond the recorded edges, and whole-ELF comparison: not yet measured. No bytes were transplanted into implementation code.

The generator reads original ELF bytes and validates the specific machine patterns before applying integer arithmetic to classify and compare decisions. The independently written decimal-piece rendering check, reduced-width guard inequality check, exact rational power-table check, and corruption controls are local mathematical controls; they are not captured node execution. `float-model.tsv` is explicitly a conditional nearest-even rational model, not an observed target result. In particular its `1/512` and `3/512` examples only show what that model predicts.

## Results and limitations

- Seven selected FDE extents, 69 selected conditional branches, 15 recorded call/load/jump edges, 81 checked table entries and 2,098 index partitions; these are selection counts, not whole-node coverage.
- 131,040 complete six-bit guard-domain triples and 343,329 selected seven-bit triples agree between the two arithmetic formulations; the derived all-width statement is limited to the documented operand domain.
- 7,920 small digit-piece combinations, 799,920 carry-path model cases and 5,461 short trim inputs agree with separate mathematical formulations. Of 399,960 paired carry cases, 12 differ between the fast and fallback paths, exactly at the documented synthetic signed-overflow boundary with spare capacity. The standalone unit suite has 24 test methods, with boundary and intentional hash, instruction, relocation, table, range, descriptor and precision-edge corruption controls; no test skips are intended.
- Full binary64 final-text equivalence, slow-path remainder meaning, proof that every live fast-guard operand is within the stated domain, failure/unwind closure, unit provenance, original Rust source, and any full component acceptance gate remain open. No progress gate is requested.

Next question: derive the exact big-integer quantities compared at `0x1577950` and connect them to the decimal cutoff for precision 8, then prove or disprove final nearest-even text across every finite binary64 input.
