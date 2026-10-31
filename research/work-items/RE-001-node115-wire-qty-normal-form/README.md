# RE-001: exact integer preparation in a node #115 WireQty-associated body

- Component: assets/foundation; bounded scalar preparation before formatting.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Measured body: actual FDE **`0x41c57f0..0x41c5b83`**, **915 bytes / 237 native instructions**.
- Question: what coefficient/scale relation is established by the unrolled integer path before the opaque formatter call?
- Observation/proof: for the raw RSI word `N` in `[0, 2^63-1]`, the prepared coefficient removes at most eight trailing decimal zeros, with abstract scale `s` in `0..8` and `N = coefficient * 10^(8-s)`. Zero uses `(coefficient,s)=(0,0)`.
- This is a static preparation theorem. No original Rust input/niche type, Decimal ABI, wire units, final displayed string or reconstruction gate is claimed.

## Identity and native evidence

`body.objdump.txt` covers every body byte from the real FDE entry. `frames.txt`
independently confirms the bounds with GNU readelf. `records.json` retains the
original FDE/CIE records, file offset, full-body hash, actual arithmetic constants,
13 unique reciprocal-bound certificates and source/call relocations. No comparison
normalization mask is used; a hash-pinned body is not a reconstructed Rust match.

The actual Location `0x6482050` points to `l1/src/wire_qty.rs:29:48`. Its RELATIVE
pointer, path bytes, length, line/column and native LEA at `0x41c5b4a` are bound.
That source association does not recover the original function signature. The
sign-bit-set path passes the generic **Result::unwrap on Err** diagnostic, not
an explicit negative-quantity assertion. A niche Result representation remains
possible; this packet does not assign a production negative-value policy.

Existing #638 studies a different #94 floating-price-to-Decimal route with a
per-asset scale and rounding windows. This #115 body directly prepares integer
limbs at a fixed abstract eight-place scale, without floating-point instructions.
No #94 correspondence or reuse of that packet's implementation is claimed.

## Local dataflow and prepared words

For a sign-clear input, the code splits `N` into `H=N>>32` and `L=N mod 2^32`.
Thus `H<=2^31-1`. Zero takes a separate local path. Nonzero input enters up to
eight unrolled divisibility-by-ten tests. At stage `k` (starting at zero), prior
divisions have only been accepted when exact, so the current coefficient is
`N / 10^k` and its high word is `floor(H / 10^k)`.

The shared integer identity is:

```
x = (current_high % 10) * 2^32 + current_low
current_coefficient = 10 * floor(current_high/10) * 2^32 + x
0 <= x < 10 * 2^32
```

Hence the coefficient is divisible by ten exactly when `x` is. Its quotient has
high word `floor(current_high/10)` and low word `floor(x/10)`, which fits u32.
The captured high-word reciprocals, low-word MUL-high reciprocal, modular test,
remainder masks and register holds implement that split-limb relation. The
algebraic checker evaluates formulas, not instructions or a program counter.

The failed-test paths preserve the **current** coefficient rather than the
one-step-ahead tentative quotient. Native dataflow holds its low word as:

| Failed stage k | Current low word retained from | Scale immediate |
| --- | --- | --- |
| 0 | incoming ESI | `8 << 16` |
| 1 | R12D saved before the next MUL | `7 << 16` |
| 2 | ESI saved before the next MUL | `6 << 16` |
| 3 | R12D saved before the next MUL | `5 << 16` |
| 4 | ESI saved before the next MUL | `4 << 16` |
| 5 | R15D saved before the next MUL | `3 << 16` |
| 6 | ESI saved before the next MUL | `2 << 16` |
| 7 | R15D saved before the next MUL | `1 << 16` |

R8D carries the corresponding current high word (the first failure explicitly
restores the original high word). If all eight tests succeed, the eighth low
quotient is placed in ESI, the eighth high quotient in R8D, and the initial scale
word remains zero. The eight actual unsigned JBE tests and scale immediates are
checked separately, along with the complete body bytes.

Immediately before constructing formatter arguments, four observed words are
stored at stack offsets:

| Offset | Raw prepared value |
| --- | --- |
| `+0x20` | `s << 16` |
| `+0x24` | 0 |
| `+0x28` | coefficient low 32 bits |
| `+0x2c` | coefficient high 32 bits |

Defining the abstract scale as `s` makes the value identity
`coefficient / 10^s = N / 10^8` exact. The coefficient is not divisible by ten
when `s>0`; zero is canonicalized separately. This does not by itself identify
a concrete Rust Decimal layout or prove that the callee renders that value.

## Complete-domain arithmetic certificates

There is no sampled-input assumption in the reciprocal bounds. For a positive
multiplier `C`, `C*d = 2^b + e` with `e>=0`, write `n=q*d+r`. Then

```
n*C = q*2^b + (q*e + r*C)
```

For every `n` in `[0,N]`, the required residual is nonnegative. Let `N=Q*d+R`.
Its maximum occurs at one of two endpoints:
`Q*e + R*C`, or, when `Q>0`, `(Q-1)*e + (d-1)*C`.
Checking both are below `2^b` proves the quotient over the entire declared
integer domain without enumerating up to 100 million remainder classes.

Eight captured high-word reciprocals cover division by `10^1..10^8`, with
`H<=2^31-1`. The `10^5` case first shifts H by five and uses reduced divisor
3125; the actual preshift is checked. All high-word products fit u64. The shared
low-word reciprocal is **`0x199999999999999a`**, using MUL's high 64 bits over
`x<=10*2^32-1`, a deliberately smaller bound than the whole u64 domain.

High-word remainder preparation also has bound certificates. Four sites use
the same `0x1999999a >> 32` divide-by-ten law; one proof at the largest applicable
high-word bound covers all four. The final three smaller domains use exact
division by five plus an even mask and multiplication by five. Exhaustive
bounded checks cover at most 21,475 high-word values, including their low16/
low8 truncation bounds. Repeated identical certificates are deduplicated: the
packet reports **13 unique arithmetic laws**, not 16 independent laws for the
four repeated sites.

The divisibility test is a separate full-u64 modular proof. Its actual inverse
is **`M=0xcccccccccccccccd`**, with `5*M == 1 (mod 2^64)`. The code rotates
`(x*M mod 2^64)` right by one and compares unsigned with
`T=floor((2^64-1)/10)`. Odd x rotates a set bit into bit63 and cannot pass.
For even `x=2z`, the rotated result is `y=(z*M) mod 2^63`. Then
`y<=floor((2^63-1)/5)` exactly when `z=5y`: the bounded product cannot wrap.
Thus the actual predicate is equivalent to divisibility by ten, independently
of sampled test vectors.

These laws, the split-limb identity, the eight conditional exits and the native
register-hold/pack observations establish the bounded preparation theorem.
They do not establish complete function/runtime equivalence after the call.

## Formatter boundary and unknowns

The call at `0x41c5aeb` resolves through RELATIVE slot
`0x64e95c8 -> 0x5c449c0`. Its implementation and formatting/vtable closure are
not recovered here. A zero return flag selects the local output-copy path;
a nonzero flag reaches the captured Display-error diagnostic. Generic unwrap/
error dispatch and cleanup/unwind behavior also remain unclosed.

Original raw input/niche representation, semantic quantity units, production
caller reachability, concrete Rust numeric type, accepted wire schema and final
string are all unresolved. The sign-bit-set diagnostic is not treated as proof
of a production negative-quantity rejection policy. No public security finding
or complete component is claimed.

## Reproduce and controls

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From repo root with
materialized pinned captures and native GNU tools on PATH:

```sh
python3 -B tools/wire_qty_normal_form.py --output work/wire-qty-normal-form-check
# Compare generated files with this packet except README/manifest.
python3 -B -m unittest discover -s tests -p test_wire_qty_normal_form.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-node115-wire-qty-normal-form && shasum -a 256 -c MANIFEST.sha256)
```

The full capture is authenticated before analysis/output/native calls. GNU tools
read a private byte-identical snapshot; raw exports use UTF-8/LF bytes. Public
wrong-release, truncated and same-size modified inputs fail before output creation.

Six focused tests check native regeneration, exact Fraction identity/minimality
at decimal/limb/domain boundaries and the following actual counterfactuals:

- Incrementing the real inverse-five immediate makes x=5 incorrectly pass the
  changed modular predicate before the checker rejects the broken inverse law.
- Clearing the actual high byte of the low-word reciprocal changes the quotient
  of 10 from 1 to 0, before its whole-domain bound is rejected.
- Changing the first actual shift from 35 to 34 gives high input 10 a quotient
  of 2 instead of 1, before its bound is rejected.

Further controls alter all eight scale exits and unsigned branch polarities,
three small-word masks, sign/zero/pack operands, real code/source relocations,
source/diagnostic bytes and the actual FDE extent. Boundary vectors illustrate
the theorem; they are not node-output comparisons or the basis of the complete
integer-domain proof. Below the public digest this checks the stated obligations,
not arbitrary-byte corruption detection.

No captured executable/emulator, formatter execution, wallet/signing/network/
chain action or host process state is used. Imported inputs/source pins and all
progress gates remain unchanged. Hosted CI and reconstructed Rust equivalence
are not claimed.

Next question: establish the raw input's original type and close the formatter
callee before claiming wire units or exact displayed strings.

Observed local validation: six focused tests passed in **37.003s**. Required
`make doctor verify test catalogue-check` passed **437 tests in 186.677s**,
all pinned capture/import/source/signature checks and catalogue consistency.
`make reproduce` passed. Packet manifest and staged whitespace checks passed.
These are local static/native-tool results, not hosted CI or captured-node runs.
