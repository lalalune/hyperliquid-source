# RE-001: node #115 spot scale round-up wrapper 0x5a00fc0

## Bounded question

The routine at `0x5a00fc0` is called from four sites in the
node #115 binary, and every site passes the same `v`: the f64
constant `0.1` stored at `0x4593e0`. It forwards its first two
arguments to the spot scale selector at `0x5a01310` (the
subject of the open RE-001-spot-scale-select-1310-115 packet,
PR #3320) and returns a `u64`. What integer does it return for
given `(flag, v, n, scale)`, and how is that integer computed,
stage by stage — the flag's negation, the magic-number
conversion of `n`, the rounding leaf it calls through a
relocation slot, the saturating cast, and the final division
and multiplication?

## Evidence and binding

- Artifact: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (the `artifacts/node/115/hl-node` entry in
  `provenance/artifacts.json`). verify.py recomputes the digest
  of the materialised `work/hl-node-115.bin` and refuses to run
  against anything else.
- `main.txt` is the `objdump` excerpt for
  `0x5a00fc0..0x5a01101`; `round.txt` the excerpt for the leaf
  at `0x63efe40..0x63efeb1`. `export_excerpts.py` regenerates
  both; verify.py regenerates both again and compares them
  against the committed files byte for byte, and against the
  binary's own bytes.
- `frames.txt` carries the `readelf --debug-dump=frames` FDE
  lines for the wrapper, the leaf and the four callers.
  `relocations.txt` carries the `readelf -rW` line for slot
  `0x64e1890`, whose `R_X86_64_RELATIVE` addend is the leaf's
  address. `callers.tsv` is the call census; `census.py`
  regenerates it from the whole binary and verify.py compares
  the two.
- The model is `tools/spot_scale_roundup_fc0_115.py`; its
  tests are `tests/test_spot_scale_roundup_fc0_115.py`.

## Layout and signature

The wrapper is one FDE, `0x5a00fc0..0x5a01101`, 321 bytes,
with no padding. Its signature is

```
(rdi = object, rsi = second argument, edx = flag,
 xmm0 = f64 value v, rcx = u64 n) -> rax u64
```

`rdi` and `rsi` are saved and forwarded unchanged to the
selector call at `0x5a010a3`; they play no other role. `edx`
is tested twice: once for the negation and once, at the end,
for the round-up choice.

The round leaf is one FDE, `0x63efe40..0x63efeb1`, 113 bytes.
The wrapper reaches it only through the indirect call
`call qword ptr [0x64e1890]` at `0x5a01009`, and the slot's
RELATIVE relocation names the leaf.

## The front: negate, convert, multiply

At `0x5a00fd4`, if `edx != 0`, `xmm0` is xorpd-ed against the
`(-0.0, -0.0)` pair at `0x4559c0`: `v` is negated (sign bit
flip, nothing else).

`n` in `rcx` is converted to an f64 by the standard
magic-number sequence at `0x5a00fdc..0x5a00ff9`: the low and
high 32-bit halves are interleaved with the dwords
`0x43300000` and `0x45300000` (at `0x451210`) to form the
biased doubles `2^52 + n_lo` and `2^84 + n_hi * 2^32`; the
biases `2^52` and `2^84` (the pair at `0x450170`) are
subtracted with one `subpd`; an `unpckhpd`/`addsd` pair sums
the exact halves. The result is the correctly rounded
`(f64)n` — the model transcribes the sequence operation by
operation and the tests prove it equal to `float(n)` on
directed edges (powers of two ± small deltas, `2^53`
neighbours, `2^64 - 1`) and random inputs.

The product is then `(v + 1.0) * (f64)n`: one `addsd` against
the `1.0` constant at `0x4592b0` and one `mulsd`.

With the callers' actual inputs this is `(1 ± 0.1) * n`: the
flag picks `0.9 * n` (flag set) or `1.1 * n` (flag clear) —
before the rounding and clamping below, which is where the
flag's second use makes the two cases land differently.

## The round leaf: nearest integer, halves away from zero

The leaf at `0x63efe40` is the classic
add-a-signed-just-under-one-half-then-truncate construction:

1. `t = copysign(0.49999999999999994, x)` — the constant pair
   at `0x450e60` supplies the magnitude
   (`0x3fdfffffffffffff`) and the pair at `0x4559c0` the sign
   extraction — and `s = x + t` (one `addsd`).
2. If the biased exponent of `s` exceeds `0x432`, `s` is
   returned unchanged: this covers the infinities and NaN
   (exponent `0x7ff`) and every `|s|` at or above `2^51`,
   where the sum is already integral.
3. Otherwise the fraction bits of `s` below its binary point
   are cleared: the mask is `0xfff0000000000000`
   arithmetic-shifted by `exponent - 0x3ff`, or, when
   `|s| < 1`, the sign bit alone, so a negative input in
   `(-1, 0)` yields `-0.0`. If no fraction bits are set the
   sum is returned as is.

The net function is round to the nearest integer with halves
away from zero — `+/-0.5` map to `+/-1.0`, not to zero or to
even. The model transcribes the leaf instruction by
instruction (`round_leaf_sim`) and separately implements the
exact rational spec (`round_half_away`, built on
`Fraction(x) + 1/2` floored); the tests prove the two equal
on every directed boundary (halves in a wide range, the
`2^52` and `2^51` edges, subnormals, `+/-inf`) and on tens of
thousands of random bit patterns and wrapper-shaped products.

## The reference: clamp, saturating cast, raise to 1

The leaf's result is clamped below by `+0.0` with a `maxsd`
at `0x5a01013`: a negative value becomes `+0.0`, and so does
NaN (the comparison is unordered, so the zero source operand
wins). What follows, at `0x5a01017..0x5a01096`, is the
saturating f64-to-u64 cast, transcribed literally in
`reference_sim`:

- The absolute bit pattern is compared against
  `0x7fefffffffffffff` (the bits of the largest finite
  double). Only `+inf` takes the greater branch — and that
  branch skips the clamp with the scratch register `xmm2`
  still zeroed, so `+inf` is cast as `0.0`. Finite values fall
  through to a clamp at `2^64` (constant at `0x459090`),
  which no finite value can exceed, so the clamp value is the
  rounded value itself.
- The cast proper is the two-part `cvttsd2si` pair: cast the
  value, cast the value minus `2^63` (constant at
  `0x459360`), and combine under the first result's sign.
- A negative scratch value would select 0 (unreachable after
  the clamp); a value above `2^64 - 2048` (the largest f64
  below `2^64`, constant at `0x458d58`) keeps `u64::MAX`
  instead of the cast result — the saturation arm.
- Finally `cmp r12, 1 / adc r12, 0`: a cast result of exactly
  0 is raised to 1. The reference is therefore never 0.

The closed form (`reference_spec`): NaN, non-positive and
`+inf` inputs all give 1; a finite value of exactly `2^64`
gives `u64::MAX`; any other value gives its truncation
toward zero, with 0 raised to 1. The tests prove the
transcription equal to the closed form on directed cast
edges (`2^63` neighbours, `2^64 - 2048`, `2^64`, infinities,
NaN) and on random wrapper inputs, and check the caller
shape end to end: for `v = 0.1` the references for `n = 5`
are 6 (flag clear: `round(5.5)`) and 5 (flag set:
`round(4.5)`) — halves going away from zero in both
directions.

## Rounding to the scale

The wrapper calls the selector at `0x5a01310` directly
(`0x5a010a3`) with `(object, second argument, reference)` and
takes its return value as `scale` in `rcx`. Then:

- If `(reference | scale) >> 32 == 0`, a 32-bit `div`
  (`0x5a010c6`) computes the quotient; otherwise a 64-bit
  `div` (`0x5a010bc`). Both leave `q = reference / scale`.
- The candidate counts are `q` and `q + 1`. The increment at
  `0x5a010cb` saturates: when `q == u64::MAX` the wrapped 0
  is replaced by `u64::MAX` (`cmove` at `0x5a010d5`). The
  flag makes the final choice at `0x5a010db`: `q` when the
  flag is 0, `q + 1` when it is not.
- The chosen count is multiplied back by `scale` (`mul` at
  `0x5a010e2`); on overflow the result register keeps
  `u64::MAX`. A product of exactly 0 — the `q = 0`,
  flag-clear case — is raised to 1 by the closing
  `cmp/adc` at `0x5a010ea`.

So the wrapper returns the reference snapped down (flag
clear) or up (flag set) to a multiple of the spot scale — a
`round-to-scale` with the direction carried by the same flag
that negated `v` — and it never returns 0: the smallest
possible result is 1.

## Callers

`census.py` scans the whole binary for direct references:

| site | enclosing FDE | flag | v |
|---|---|---|---|
| `0x517b48f` | `0x517af50..0x517b75d` | stack byte at `rsp+0x67` | `0.1` |
| `0x517c57f` | `0x517c040..0x517c84d` | stack byte at `rsp+0x197` | `0.1` |
| `0x54f0797` | `0x54efca0..0x54f126d` | constant `1` | `0.1` |
| `0x54f1d67` | `0x54f1270..0x54f283d` | constant `1` | `0.1` |

Four direct calls, no tail jumps (E9), no 8-byte-aligned
stored qword equal to the wrapper's address anywhere in the
file, and no `R_X86_64_RELATIVE` addend naming it. Which
semantic quantity each caller places in `rcx`, and where its
flag byte comes from, is those routines' own question and is
not claimed here.

## Relationship to neighbouring packets

- The selector at `0x5a01310` is pinned by the open
  RE-001-spot-scale-select-1310-115 packet (PR #3320), which
  cites this wrapper as a caller but does not enter it. This
  packet takes the selector's return as an input and pins
  everything around it: the reference it is called with and
  the use made of its answer. The division above relies on
  that packet's pinned behaviour only for `scale >= 1`; a
  scale of 0 would fault the binary's division.
- The perp selector at `0x5a01110`, pinned by the open
  RE-001-pow10-scale-01110-115 packet (PR #3315), is never
  called here; the questions are disjoint.
- The round leaf is cited as a stored string in the merged
  RE-001-node115-bole-entry-counter-order packet's records.
  A citation is not a pin of its semantics; this packet
  supplies the pin.

## Verification

```
python3 research/work-items/RE-001-spot-scale-roundup-fc0-115/verify.py
python3 tests/test_spot_scale_roundup_fc0_115.py
```

verify.py re-derives, from the pinned binary alone: the
SHA-256 digest against `provenance/artifacts.json`; the
packet manifest; both excerpts byte for byte; the spot bytes
of the flag test, the negation, the conversion sequence, the
slot call, the maxsd, the cast compares, the selector call,
both divisions, the saturating increment, the flag choice,
the multiplication and the closing raise, and of the leaf's
constant loads, exponent gate and mask construction; the six
FDE ranges (wrapper, leaf, four callers) in the live frame
dump and in `frames.txt`; the slot relocation against
`relocations.txt`; every named constant's bytes and value;
the whole-binary census against `callers.tsv`, including the
caller attribution of each site to its smallest enclosing
FDE; the `records.json` semantics; and the model test suite.
It prints `ALL CHECKS PASSED` on success.

## Honest limits

- The selector at `0x5a01310` is an input here, not measured:
  the model treats its return value as `scale` and relies on
  the sibling packet's contract (`scale >= 1`) for the
  division to be reachable at all. The model's `ValueError`
  on `scale == 0` is a model safety property, not a binary
  claim.
- The leaf's own caller census is not taken: the claim is
  only that this wrapper reaches it through slot
  `0x64e1890`, not that the wrapper is its only caller.
- `v` and `n` are pinned as raw register inputs. All four
  real call sites pass `v = 0.1`; what `n` and the flag mean
  in each caller is not reconstructed here.
- No native execution, no Rust rebuild, and no byte
  equivalence are claimed.
