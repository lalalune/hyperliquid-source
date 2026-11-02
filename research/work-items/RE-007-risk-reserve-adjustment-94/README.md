# RE-007: node94 reserve adjustment after aggregate margin

This packet resolves the body at `0x3708bf0`, previously an explicit unknown
edge in merged PR #1337 and `RE-007-positive-risk-scan-94`. It establishes how
that path subtracts a per-user table value after a binary64 1.01 adjustment,
which users bypass that adjustment, and how its signed error and saturation
arms interact. The new semantic scope is 652 bytes; the already documented
347-byte fixed-address predicate is rebound as a dependency.

- Component: clearinghouses and risk, bounded RE-007 follow-on.
- Target: Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`. No inferred
  implementation was read or copied for the new formula or models.
- Status: static observations for bytes, instruction boundaries, FDEs,
  branches, relocations, constants and source Locations; conditional numeric
  interpretation for arithmetic; economic names are inferences.
- Execution: the captured node was never loaded for execution or emulated.
  The only executable tools used on it are static ELF readers and decoders.
- Completion: no Rust reconstruction, compiled comparison, byte-window credit
  or component gate is requested. RE-001/RE-004 and helper closure remain partial.

## Reproduce

From the repository root with Python 3.12.14 and the authenticated artifact:

```sh
python3 research/work-items/RE-007-risk-reserve-adjustment-94/verify.py \
  --out work/reserve-review
python3 -m unittest discover -s tests -p test_risk_reserve_adjustment94.py -v
python3 research/work-items/RE-007-risk-reserve-adjustment-94/check_decoders.py \
  --llvm /path/to/installed/llvm-objdump \
  --binary artifacts/node/94/hl-node --out work/reserve-decoders
```

Compare `evidence.json` and `samples.json` in `work/reserve-review` to the
committed files. `verify.py` uses the repository's ELF, RELATIVE relocation,
Location and FDE parsers and a separately hash-bound frozen GNU decode. It does
not invoke a decoder or execute instructions. `check_decoders.py` optionally
repeats full-range decoding with installed tools and compares every address
and instruction byte string. Its commands, versions and raw output identities
are in `agreement.json`; raw GNU 2.44 and LLVM 19.1.7 outputs are retained.
Nearest exported-symbol annotations printed by either decoder are unrelated
labels and are not claimed as recovered function names.

The frozen decode covers every byte in both FDE ranges with no masks.
All 224 instruction boundaries agree between GNU and LLVM. The FDEs remain
unwind-described ranges, rather than independently proved source-function
boundaries. This packet is not a general indirect-call or cold-fragment census.

## Native path and helper closure

Coordinates are ELF virtual addresses; `evidence.json` supplies file offsets,
full FDE/CIE records, body hashes, branch bytes/targets, call encodings and
relative slots. `decode.json` retains every instruction byte and its mnemonic.

| Role | Half-open FDE range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| New reserve adjustment | `0x3708bf0..0x3708e7c` | 652 | 158 |
| Existing fixed-address predicate | `0x37e4fb0..0x37e510b` | 347 | 66 |

The already established caller sets `edx = 4` at `0x21bc862` and calls slot
`0x57738b8` at `0x21bc867`; its RELATIVE target is `0x3708bf0`. It supplies a
copied 20-byte key in `rsi`, the DEX context in `rdi`, and context byte `+0x2ed`
in `ecx`. It uses only a strictly positive `rax` result (`0x21bc86d..0x21bc870`).
Those call/gate bytes are independently rebound here. The new helper preserves
the supplied raw mode and byte into its aggregate call; this packet gives no
broader economic meaning to the byte or to other modes.

| Call site | Resolved target | Scope and remaining gap |
| --- | --- | --- |
| `0x3708c10` | `0x36f57f0` | Row lookup with context `+0xf8` and the 20-byte key; body, lazy defaults and effects are outside the new scope. |
| `0x3708c30` | slot `0x5773178` → `0x37d79e0` | Aggregate helper previously studied by `RE-007-margin-path-94`; takes the returned row, a zero argument, incoming raw mode/byte, context `+0x60`, and stack context. Producers, internal closure and units are not re-proved here. |
| `0x3708c62` | slot `0x5773228` → `0x37e4fb0` | Complete eight-address predicate rebound here; previously described by `fees-open-order-cap-94`. |
| `0x3708c8a` | `0x399c7a0` | Hash with context `+0x148` and the key. Its internals are an explicit gap. |
| `0x3708e00`, `0x3708e27` | slot `0x5773190` → `0x358dcd0` | Quantity recorder; effects and termination remain unknown. Numeric continuation assumes it returns. |
| `0x3708e51`, `0x3708e76` | slot `0x576e048` → `0x157aa10` | Unwrap failure helper; body/termination are outside scope and no normal error return is invented. |

All six unique callees have authenticated FDE starts/ends in `helper_closure`.
Only the adjustment and fixed-address predicate receive complete decoded
bodies here. The eight call sites comprise two direct and six slot calls.
External bodies, allocator/lazy-state behavior, indirect reachability and
exceptional continuations prevent a full path-equivalence claim.

## Branches, quantities and errors

1. After row lookup and aggregation, load words `E = [out+0]` and
   `M = [out+8]`. `0x3708c3b..0x3708c3e` rejects a sign-bit-set `M` through
   the unwrap arm before the predicate or reserve map is read. Otherwise
   `0x3708c4c` subtracts `M` from signed `E`; `jo` at `0x3708c59` selects
   the recorder path and signed saturation before continuing. With admitted
   `M >= 0`, the only possible overflow is below `i64::MIN`.
2. The predicate returns true exactly for the eight 20-byte constants in
   `exemption_list`. `0x3708c6c` then skips reserve lookup. The list helper has
   seven early equality branches and a final `sete`. Each comparison combines
   a 16-byte head with a 4-byte tail loaded by `movd`; all twelve high bytes of
   each tail constant are zero. These full 16-byte operands are authenticated.
   No real-world identities or special privileges beyond this call are assigned.
3. A zero item count at context `+0x140` (`0x3708c7a`) also uses reserve zero.
   Otherwise the map uses control pointer `+0x128`, mask `+0x130`, 80-byte
   entries, 16-control-byte probes and 20-byte equality. Equality at
   `0x3708d23` reads the selected word at entry end `-8`; an empty-control
   match at `0x3708d3e` uses zero. Collision and probe loops are retained in
   the branch table. Hash meaning and malformed-map behavior are unresolved;
   the numeric model assumes a well-formed map and supplies its lookup result.
4. A found sign-bit-set reserve `Q` branches at `0x3708d58` to its separate
   unwrap failure. A skipped or missing map never takes this check. Thus a
   hypothetical negative stored word does not fail when the predicate skips it.
5. `0x3708d61` converts nonnegative signed `Q` to binary64, and
   `0x3708d66` multiplies by the eight bytes `295c8fc2f528f03f` at `0x20a528`.
   They encode the binary64 value printed as `1.01`, whose exact fraction is
   `4548635623644201 / 4503599627370496`.
6. Conversion, comparisons and postfilters below produce nonnegative integer
   adjustment `A`. `0x3708dcb..0x3708dce` then performs the second signed
   subtraction; overflow reaches a distinct recorder Location before signed
   saturation. The return flag in `dl` is exactly `[row+0x20] != 0`
   (`0x3708dd0..0x3708dd5`). Its business meaning is unresolved.

The recorder Locations `0x56f3a78` and `0x56f1cf8` both resolve to
`l1/src/qtys/impl_ntl.rs:62:1`; the first unwrap carries
`l1/src/qtys/mod.rs:843:1` at `0x56f3a60`. Both failure-message sites contain
`called Result::unwrap() on an Err value` with backticks in the actual bytes.
These records support notional-like raw arithmetic, rather than a function
name or decimal exponent. The prior margin packet separately established
raw price × raw signed size feeding notional arithmetic. This helper itself
contains no price, size, wei or power-of-ten conversion. **Price, size and wei
denominations, decimal exponents and the reserve's economic producer remain
unknown.** The value 1.01 is dimensionless; its presence does not prove dollars,
wei, USDC scaling, or a production margin policy.

## Floating comparisons and admitted domain

The model assumes round-to-nearest, ties-to-even, masked floating exceptions,
and helper return. Target MXCSR is not recovered. It does not replace the
following instruction sequence with an unconditional mathematical clamp.

| Native site | Exact flag/control observation |
| --- | --- |
| `0x3708d6e`, `je 0x3708d76` | Compare the product with +infinity. Ordered equality **or unordered NaN** takes the zero-setting arm `0x3708da2`. |
| `0x3708d80`, `ja 0x3708d84` | Compare `-2^63` against the product. Only an ordered product below that lower bound takes the clamp arm. |
| `0x3708d86`, `jbe 0x3708d8e` | Compare product against `+2^63`; below/equal or unordered skips the clamp arm. NaN was already diverted above. |
| `0x3708d90..0x3708d9c` | `maxsd` with the lower bound, then `minsd` with the upper bound. These SSE operations have operand-order-dependent NaN behavior; no generic all-input clamp claim is made. |
| `0x3708da6` | `cvttsd2si rcx,xmm0` truncates toward zero. Positive `2^63` produces integer-indefinite under masked exceptions before the next correction. |
| `0x3708dab..0x3708db3` | Compare with `0x43dfffffffffffff`, the binary64 predecessor of `2^63`; ordered `>` makes `cmova` select `i64::MAX`. |
| `0x3708db9..0x3708dbd` | A self-compare supplies PF; `cmovp` replaces unordered with zero. |
| `0x3708dc1..0x3708dc4` | Integer signed `<= 0` replaces the converted word with zero. |

For the admitted reserve domain `0 <= Q <= i64::MAX`, conversion and
multiplication produce finite, nonnegative binary64 values under the stated
rounding assumption. The product is below `2^64`; NaN, infinity and negative
clamp inputs cannot arise from this sequence. An upper clamp or saturation
can arise. For this domain alone, the numeric relation reduces to:

```text
subtotal = signed_saturating_sub(E, M)
A = min(i64::MAX, trunc(RN_binary64(RN_binary64(Q) * binary64(1.01))))
result = signed_saturating_sub(subtotal, A)
```

Use `Q = 0` for exemption, empty map or missing entry. A negative aggregate
requirement or selected reserve takes its error arm, rather than this returned
relation. If the first recorder returns, both subtractions can independently
underflow and call it; no equivalence is claimed for its effects or failure.

## Synthetic controls and validation

`samples.json` retains 18 reserve boundary witnesses and 12 conditional scalar
cases. The focused tests regenerate a deterministic 1,300-value reserve sweep;
its summary is retained while repetitive rows remain transient. The independent
oracle uses exact fractions and integer ties-to-even rounding twice; the host
model uses Python binary64 conversion/multiplication. All 1,300 comparisons
agree. An exact `floor(Q*101/100)` replacement disagrees on
66 sampled inputs. At `Q = 2^52`, the native-derived relation gives
`4548635623644201`, while that exact rational replacement gives
`4548635623644200`. At `Q = 2^53` and `Q = 2^53+1`, conversion collapses the
two integers to the same value. At `i64::MAX`, the adjustment saturates.
These are derived model results, not captured-program observations.

Seven focused unittest methods pass without skips. Controls change the full
input digest; all 24 branch encodings; float comparisons, conversion and
postfilter bytes; the five binary64 constants; FDE/CIE records; each recorded
call-slot relocation and source Location; a fixed-address SIMD zero tail;
the frozen transcript; and the arithmetic replacement above. Most body
corruptions are rejected by a frozen whole-body SHA. These are byte-identity
admission controls, not an independent semantic CFG proof or execution test.
Scalar controls cover error precedence, skipped negative reserve, missing
entry, negative/zero/positive result, both saturation sites and the return flag.

Two regenerations with different hash seeds and timezones, one under Python
optimization, are byte-identical. `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` pass locally; exact rebuild
readiness remains false. Logs, versions, commands and environment details are
in `VALIDATION.md` and `validation/`. The coordinator will run the broad
repository `make test` after integration; this lane makes no full-suite or
hosted-CI claim.

Next question: independently establish the producer, decimal denomination and
admitted ranges of the context `+0x128` table's final word, then close recorder
effects and aggregate-helper dependencies before a Rust or target-equivalence
claim.
