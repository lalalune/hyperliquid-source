# Candidate 38: conditional all-bit numerical projection

This closes the numerical bit relation needed by the fresh-reader FeeRateMapSerde decoder candidate. It does not admit Rust authorship, execute the captured program, determine a live CPU/MXCSR state, or prove rendering, allocation, exception handling, or the complete decoder. The relation is conditional on the ordinary valid-frame premises in the sealed wave24 scout and on the documented Intel SSE2 behavior stated below.

## Evidence and machine assumptions

The captured node #115 identity is SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes. The full retained numeric FDE is `0x3423120..0x34233b4` (660 bytes, 186 instruction rows), body SHA256 `378598f507c8bf24f338bfdb337d4dbc40c5feeb4f0fa0824ed8a07fc04cf83a`. This work uses the existing authenticated full-body GNU evidence; it does not claim new byte coverage or an independent captured lineage. NATIVE-BINDINGS.json binds the exact scout inputs and raw constants.

For the native correspondence theorem, MXCSR RC=00 (round to nearest, ties to even), DAZ=0, FTZ=0, and all six floating-point exception masks are set. Relevant ordinary helpers preserve these controls and the live input/result/frame. These are explicit premises, not measured properties. Intel documents the rounding control and masked continuation behavior in Table4-8 and §10.2.3; DAZ changes subnormal inputs to signed zero, while FTZ applies to underflowed results. [Intel Vol1, revision253665-080US, June2023, pp4-18 and10-4..10-5](https://cdrdv2-public.intel.com/782149/253665-sdm-vol-1.pdf).

Only output words are projected. Existing sticky flags, newly raised flags, traps, timing and callbacks are not reproduced. In particular a signaling NaN or subnormal operand can affect flags; an inexact integer conversion can affect precision. An unmasked exception can prevent the ordinary store and is outside the relation. Requiring all masks is a simple sufficient premise, not a claim every exception can occur on every path.

## All unsigned 64-bit integers

At `0x342334d..0x342335b`, a full big-endian u64 is consumed. The data at `0x451210` is `00003043000030450000000000000000`; at `0x450170`, `00000000000030430000000000003045`. The unpack at `0x3423364` places the low32 bits with exponent word43300000 and high32 bits with45300000. The packed subtraction is at `0x3423370`; the final scalar addition is at `0x3423380`.

Let n=H·2^32+L, with 0≤H,L<2^32. The two constructed binary64 values are exactly 2^52+L and 2^84+H·2^32. Their fractions use only32 bits. Subtracting their respective biases gives L and H·2^32 exactly: each mathematical difference is representable, so no rounding error is introduced. This includes H=0 or L=0; under the stated rounding mode the zero difference is positive zero. Thus the final addition is the sole potentially inexact operation, and its result is RN-even(n).

There is no overflow: the greatest possible rounded result is 2^64, far inside the binary64 finite range. There is no nonzero subnormal intermediate. DAZ and FTZ do not change this u64 path under these bounds. A proof must not replace the conversion with a signed cast, truncation, two separately rounded half-sums, or an assumed exact integer representation above2^53.

A mathematical specification valid over the complete domain follows. For n=0 return positive zero. For nonzero n, let k be its bit length. If k≤53, n is exact. Otherwise let s=k−53, q=floor(n/2^s), r=n mod2^s. Here 1≤s≤11. Round q upward precisely when r>2^(s−1), or when r=2^(s−1) and q is odd. If this increment carries to2^53, use the next binade. This is a scalar mathematical relation, not evaluation of native instructions.

For signed64 conversions at `0x342333b`, the same RN-even integer relation applies with the original sign. −2^63 is exactly representable. The 32-bit conversions at `0x3423281`/`0x34232d8` are exact for their admitted signed/narrowed inputs. Their byte/word extension and marker selection remain native decoder obligations; a generic 32-bit zero-extension assumption would be wrong.

## All binary32 bit patterns

The f32 payload is consumed and byte-swapped at `0x3423141..0x342315f`, converted by `CVTSS2SD` at `0x342316c`, then masked and sign-restored through `0x3423191`.

Write the input as sign S, exponent E and23-bit fraction F. The final binary64 bits are:

| Input class | Binary64 result bits |
|---|---|
| E=0,F=0 | S·2^63 |
| 1≤E≤254 | S·2^63 OR (E+896)·2^52 OR F·2^29 |
| E=0,F>0 | S·2^63 OR (k+874)·2^52 OR (F−2^k)·2^(52−k), k=floor(log2 F) |
| E=255,F=0 | S·2^63 OR 0x7ff0000000000000 |
| E=255,F>0 | S·2^63 OR 0x7ff0000000000000 OR F·2^29 OR 2^51 |

For normal finite inputs, expanding the23-bit fraction into52 bits preserves the exact value. For subnormals, F·2^-149=(1+(F−2^k)/2^k)·2^(k−149); k∈[0,22] yields biased exponent k+874 and the table's fraction. The smallest nonzero result is2^-149, which is normal in binary64. Thus every finite widening is exact, no finite overflow or underflow occurs, and the rounding mode does not change these finite results. FTZ does not change them; DAZ=0 matters because the input may be a binary32 subnormal.

Intel's conversion-specific TableD-11 supplies the nonfinite policy: infinity remains infinity; NaN expansion preserves sign, shifts the fraction29 bits, and quiets a signaling NaN by setting binary64 bit51. The quiet bit is already set for an input quiet NaN. No canonical-payload substitution is licensed by this specific native premise. [Intel Vol1, AppendixD, TableD-11, printedD-8/PDF page455 zero-based](https://cdrdv2-public.intel.com/782149/253665-sdm-vol-1.pdf).

The sign restoration independently follows from actual data: `0x456510` holds [−1,+1], `0x4559c0` the two sign masks, and `0x450180` the magnitude masks. NOT(raw32)>>31 equals1−S. The selected ±1 supplies only the original sign bit after AND; the converted value supplies only magnitude/payload; OR reunites them. Bitwise AND/OR does not perform another floating-point conversion.

The bit policy therefore covers all2^32 input words, including signed zero, both infinities and every quiet/signaling payload. This is an all-input algebraic/ISA argument, not an assertion that the finite witness set enumerated those inputs.

## Binary64 identity and binary visitor

The `0xcb` numeric route at `0x342328a..0x34232b2` loads, byte-swaps and stores the64-bit payload through integer operations. Its output is raw identity, including subnormal words and signaling NaNs; widening's quiet-bit rule must not be applied here. The array result uses moves, not further arithmetic. The binary visitor at `0x17fb170..0x17fb284` converts the first four unsigned payload bytes individually; each0..255 value is exact binary64. These paths do not establish equivalence of subsequent operations on the returned words.

## Portable implementation implication

A future implementation should keep decoded values as raw u64 words. A host floating-point cast alone is insufficient to guarantee the required NaN payload and sign. Rust1.95's documented arithmetic/cast NaN choices include multiple permitted payload/sign outcomes, whereas bit-preserving operations have stronger guarantees. Explicit integer bit construction can express the chosen native relation without depending on host FP state. [Rust1.95.0 primitive documentation, NaN bit patterns](https://github.com/rust-lang/rust/blob/1.95.0/library/core/src/primitive_docs.rs#L1230-L1293).

This is a recommendation for independent authorship, not supplied implementation code. No reconstructed Rust exists in this proof directory.

## Fresh-reader and depth boundary

The proposed decoder domain starts with category1, the actual no-cache state; arbitrary cached-marker bytes are excluded. This does not impose a blanket nonzero depth condition. The numeric and binary routes do not read the depth. At depth0, a complete `c4 04 00 00 00 00` binary input can therefore produce four positive zeros under the ordinary helper/frame premises. An empty input or a truncated variable-length container header can reach EOF before any depth check.

The container guards are path-specific: map at `0x17c47ce..0x17c47e8`, array at `0x17c484a..0x17c4864`, and ext at `0x17c4bc9..0x17c4be3` check depth after the necessary length header (these intervals have exclusive ends). Zero reaches panic routing; one decrements to zero and returns depth error8. A chosen safe-host refusal for the zero-depth guard path must be named as policy outside the ordinary-return theorem, with cursor/depth effects stated separately. It must not reject unrelated depth0 inputs as though the native body did so. These structural examples are manual deductions, not executed decoder cases.

## Qualification, chronology and limits

MANUAL-WITNESSES-v1.json was authored first and frozen at SHA256 `89ded30a86078ee19c84109f5370c86d54ab8d6bb5fd260d0f694d02b8bdd7de`. It contains24 unsigned integers,28 binary32 patterns,6 raw binary64 patterns and4 signed integers. The set includes both sides and the exact midpoint near2^53,2^63 and2^64; subnormal/normal transitions; both signs; quiet/signaling NaN payload extremes.

Then check_manual_math.py independently verified finite values with Fraction and checked each integer answer against its immediately adjacent representable values and tie parity. Nonfinite checks use the explicit bit policy above. It does not import project code, load target bytes, emulate instructions, call host floating conversion, or supply decoder expectations. The single actual run passed62 rows, exit0, empty stderr. Its raw output SHA256 is `2bd8220464298738610370eb5c5bb5c4b256d5c752cc00c0cc8625ceb8536763`; receipts record source/input/interpreter identities and exact argv. No literal witness correction was needed. This finite check corroborates manual boundary arithmetic; it is not the universal proof or target execution.

The remaining candidate obligations are the complete fresh-reader marker/cursor/depth/error projection, ordinary opaque helper frame contracts, ownership refresh, below-hash static controls and an independent decoder corpus before source. Native error formatting, allocation, unwind, CPU state and public economic meaning remain outside this result.

## EXPAND

- Use the explicit bit policy in an independently authored scalar reference and later source, with separate derivations and pre-source expectations; preserve the raw binary64 identity distinction.
- Include reached depth-zero guards and truncated length headers in the eventual decoder contract; exclude arbitrary cached-marker states.
- DEAD END: generic host f32-to-f64 casts as proof of exact NaN words; Rust's portable guarantee is weaker.
- DEAD END: a blanket depth>0 admission rule or assuming all container errors restore depth; native branches distinguish these cases.
- No additional instruction evaluator, target execution or full suite is needed to establish this algebra.

