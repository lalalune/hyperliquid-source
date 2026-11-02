# Addressed complete outer value relation

This is a conditional manual proof for Visor SHA256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`. It supports the all-bit contract in `CONTRACT.md`; it is not recovered source text or an executed target comparator. Both complete FDEs are retained: outer `330360..330581` (545 bytes/140 instructions), helper `7a6530..7a65a1` (113 bytes/24 instructions). All 658 bytes originate in the existing authenticated capture; prior fixed-input evidence is credited and no new recovery credit is claimed. Seventeen additional explicitly bounded caller contexts retain951 bytes/202 instructions for input-use evidence, not whole-caller theorems.

## Native premises, frame and closure

The entry low64 bits of XMM0 may be any binary64 encoding. Assume the admitted code/literal bytes remain immutable, the bound RELATIVE slot contains the relocated helper address, and normal x86-64/SSE2 behavior follows the referenced primary ISA contracts. Floating operations use round-to-nearest-even, all relevant exceptions are masked, DAZ/FTZ are off, and no asynchronous/exceptional transfer intervenes. No actual target CPU/MXCSR setting is observed. Upper SIMD lanes, flags and volatile registers are not part of the value projection.

Let entry RSP=S. The ordinary path may write `[S-8,S)` by `33036e push rax`; the nested CALL at`330377` writes `[S-16,S-8)`. The helper has no stack mutation or calls. On its return, `3303a0 lea rsp,[rsp+8]` restores S; the outer RET reads `[S,S+8)` and advances RSP to S+8. Thus those ranges must be valid, nonwrapping and disjoint from immutable code/data; the original return address must remain valid. All remaining memory operands in the two bodies read pinned RIP literals or the one call slot. There is no heap/output-memory store. The helper's MOVAPD literal addresses are16-byte aligned.

The sole outer call is `330377 ff15d3504b00`, whose signed RIP displacement gives slot`7e5450`. Its unique `R_X86_64_RELATIVE` record has addend`7a6530`, with symbol0. There are no imports or further callees in the complete value pair. Full raw FDE/CIE bytes and `.eh_frame_hdr` entries bind both extents. The CIE is version1/zR with signed32 PC-relative start encoding; the FDE augmentation length iszero. This is unwind identity, not a source ABI proof. The collector scans all15,595 RELA records, admits only the observed8-byte writer types6/7/8 and rejects any overlap with selected code/literals/unwind metadata. No runtime relocation/loader action is executed.

The syntactic CFG is acyclic even though `330574` jumps backward to fallback. Fallback itself returns without reentering the exponent dispatch. The helper has one RET, and the outer has exactly five. All decoded rows are reachable in the syntactic branch graph. This is not a claim that every branch condition is feasible under every input; the arithmetic below identifies infeasible CMOV alternatives. The native decoder/static CFG supports the manual argument rather than replacing it.

## Initial partition and ordinary nonnegative inputs

`330360..330368` compares zero against input using UCOMISD. A strictly negative ordered input selects fallback at`33036e`. Positive inputs, either zero and unordered NaNs select exponent inspection at`330439`. NaNs then have exponent2047 and enter fallback. Both infinities also reach fallback. Signaling-NaN invalid behavior is masked by premise.

For finite nonnegative input define exponent field e and fraction F. If e is nonzero, let `M=2^52+F`; then `x=M*2^(e-1075)`. Subnormal values use `F*2^-1074`. At`33044d..330457`, e<992 returns RAX=0 and EDX=0. For the greatest such normal value,
`2*(2^53-1)*10^9 < 2^84`, so x*10^9 is strictly less than one half. All smaller normals, subnormals and zeros also round tozero.

For992<=e<1023, `330458..33046b` builds M. At`330479`, the low-byte adjustment equals s=e-979, where13<=s<=43. The SHLD/SHL pair at`33047e..330484` is the exact two-word integer `T=M*2^s`; bit0x40 is always clear, so the following two CMOVNE alternatives are not selected. T is below2^96 and represents x*2^96. `330492..3304a4` computes the exact128-bit `P=T*10^9`, below2^126. Its low word is in RAX and high word in RCX.

Write `P=q*2^96+r`, with0<=r<2^96. `3304a7..3304aa` extracts q. Bit31 of ECX is the halfway bit of r; ifclear, the increment iszero. Ifset, `3304b7..3304d3` distinguishes r=2^95 from r>2^95 and increments for the latter or for an odd q at equality. Clearing low nine product bits loses no information:10^9 is divisible by512. This gives nearest-even rounding of x*10^9. Because x<1, the rounded integer is at most10^9. `3304da..3304e3` converts the endpoint10^9 to seconds1/nanos0; otherwise seconds0 and the rounded nanoseconds return at`3304e6`. Every EDX write clears upper RDX.

For1023<=e<1075, let d=e-1023 in0..51. `3304ef..330508` forms integer seconds `s=floor(M*2^d/2^52)` and fractional numerator `f=(M*2^d) mod2^52`. The left-shifted original encoding has the same low52bits: its exponent/sign bits cannot enter them, and the implicit leading bit contributes a multiple of2^52. `33050b..330520` computes the quotient of `f*10^9` by2^52. `330524..330553` applies the halfway bit51, remainder and parity test for nearest-even rounding. Its masked low nine bits are likewise identicallyzero. `330556..33056a` carries a rounded fraction of10^9 into one additional second, returning at`33056d`.

This equals rounding the whole x*10^9: adding integer `s*10^9` does not change fractional distances, and that integer iseven, preserving tie parity. The greatest possible seconds here is below2^52; carry cannot overflow u64. Finally1075<=e<1087 means x is integral. `33057a..330580` shifts M by e-1075 in0..11 and returns the exact value below2^64, with EDX alreadyzero. Other exponent classes enter fallback at`330574`.

## Complete reachable fallback classes

`33036f` multiplies the input by pinned binary64 bits`412e848000000000` (exactly10^6). Call the rounded low-lane product y. Possible reachable classes are nonpositive finite, nonfinite, or positive finite with y>=2^64. The latter arises only from finite positive x>=2^64; multiplication by10^6 cannot reduce it under nearest-even rounding.

The complete helper first copies y, applies the two-lane sign mask at`6dd20`, ORs the magnitude bits`3fdfffffffffffff` at`6cf40`, then ADDSD at`7a6548`. Let a be that positive magnitude;0<a<1/2. The low result is `z=RN64(y+copysign(a,y))`. Nonpositive finite y produces nonpositive z. NaNs remain NaNs, and infinities retain their sign/class. A positive finite y>=2^64 has spacing at least4096; adding a is strictly below half an ulp, so z=y and remains finite.

The exponent test at`7a655e` returns z unchanged when its exponent is greater than1074. This covers the nonfinite and positive-large classes. For lower exponents, `7a6566..7a6589` chooses a sign-only mask below1, otherwise a sign/exponent/integer-significand mask. The exponent-offset shift for the latter is0..51. The earlier shifted value is irrelevant when the sign-only alternative is selected. `7a658d..7a659b` either returns unchanged when the discarded bits arezero, or clears them. Both alternatives preserve the sign and cannot turn a nonpositive result positive. Thus every reachable helper branch is qualified sufficiently for the outer result. No exact standalone rounding API is claimed for arbitrary small positive helper arguments that this outer fallback never supplies.

On return, XMM2 starts atzero. `330381..3303a5` clears the sign bit of the helper result and excludes encodings above the largest finite word. Nonfinite results therefore leave XMM2 zero. For a finite nonpositive result, the ordered comparisons/MAXSD/MINSD at`3303ab..3303cb` clamp tozero (either zero sign is harmless here). A positive-large result exceeds the pinned upper2^64 and clamps to exactly2^64. Therefore XMM2 is numerically only0 or2^64. This narrow reachable set is essential; no arbitrary floating-to-u64 theorem is substituted.

`3303cf` and`3303e7` perform signed truncating conversions. Forzero the first yields0, and the conversion of `-2^63` is valid; the masking/selection yields integer0. For2^64 the intermediate signed conversions may be invalid, and return normally only under the masked-exception premise. Whatever temporary arithmetic they produce, the comparison against pinned `43efffffffffffff` (`2^64-2048`) at`330400` forces RCX=u64::MAX at`33040f`. Thus the final integer input is either0 or u64::MAX.

For those two integers N, `330413..330426` computes
`q=floor(N*0x431bde82d7b634db/2^82) = floor(N/10^6)`.
`33042a..330430` uses low32 modular arithmetic to compute `r=N-q*10^6`, which is in0..999999 and therefore recovered exactly. `330432` multiplies r by1000, below10^9, clearing upper RDX. RET`330438` returns `(0,0)` or `(18446744073709,551615000)`. The certificate checks both reachable reciprocal inputs; an unnecessary all-u64 reciprocal claim is avoided.

## Positive multiplication-overflow boundary

The exact positive binary64 overflow midpoint under nearest-even is
`H=2^1024-2^970`. The midpoint rounds to the even next-binade significand, hence infinity. Therefore the fallback product is finite iff exact x*10^6<H. For the boundary binade e=2027, x=M*2^952 and10^6=15625*2^6. The criterion becomes
`M*15625 < (2^54-1)*2^12`.

The last admissible M is4722366482869644; the next is4722366482869645. Their scaled distances below/above the threshold are14868 and757, so neither is a midpoint ambiguity. These encode adjacent input words`7eb0c6f7a0b5ed8c` and`7eb0c6f7a0b5ed8d`. Positive encodings are monotone by exact value, establishing the full threshold. NaN/infinity/negative cases were handled separately; no host floating comparison enters this certificate.

## Returns, callers and limits

| Outer RET | Reaching admitted class | RAX and full RDX |
|---|---|---|
|`330438`|Fallback, all reachable helper classes|Zero pair or microsecond-derived fixed pair|
|`330457`|Nonnegative e<992, including zeros/subnormals|Zero pair|
|`3304e6`|992<=e<1023|Nearest-even subsecond pair, possible one-second carry|
|`33056d`|1023<=e<1075|Integer seconds plus rounded fraction/carry|
|`330580`|1075<=e<1087|Exact integral seconds, zero nanos|

All returns restore the entry stack before RET. There is no other ordinary return edge. The helper's sole RET is`7a65a0`.

Seventeen known calls through unique slot`7e53c8 -> 330360` include six field loads, nine literal loads (1,5,10,60,300) and two contexts with an already available XMM0. These make the generic function a real dependency beyond fixed60. The contexts plus value pair retain25 total calls because some precede the selected call; those extra direct/register calls are contextual and opaque, with no new whole-caller/field-provenance/side-effect claim. The set is a retained syntactic search result, not proof of exhaustive indirect reachability. Hosting CIE/FDE records may include zPLR exception metadata; those raw identities are retained only to bound the contexts, with no LSDA/personality/exception semantic closure. Source seconds/nanoseconds units follow the native1e9 and1e6/1000 arithmetic, not inferred original type names.

`arithmetic.py` checks exponent intervals, exact product bounds, discarded-bit divisibility, reachable reciprocal inputs and the strict overflow inequalities. Its split integer equations agree with59,159 independently structured exact-rational cases. Thirteen false-model witnesses distinguish truncation, tie errors, omitted carry, microsecond rounding, absolute negatives, nonfinite saturation, wrong fallback units/threshold and double rounding. The finite cases and byte controls support this manual proof; they do not execute, emulate or interpret captured instructions, prove memory premises, or establish whole-Visor equivalence.
