# All-i32 calendar constructor and selected return registers

The claim is the value projection of complete node94 function
`[0x151f6f0,0x151f86a)`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The 378-byte body and six separate padding bytes are bound. The nearby
packed-date addition at `0x151f870` is a different entry and API, already
studied separately. This constructor takes no packed date or caller validity
assumption: its input is the signed interpretation of incoming RDI's low32.

## Exact total relation

Let `d = signed32(RDI mod2^32)` and `a = incoming RAX`. Define the monotone
absolute year-start function over all integers:

```
F(y) = 365*y + floor((y+3)/4) - floor((y+99)/100) + floor((y+399)/400)
```

Then the complete ordinary-return relation for selected registers is:

```
RCX = a
RAX = 0,                                  d < -95746129 or d > 95745399
RAX = ((y mod2^19) << 13) | (o << 4) | f, otherwise
```

On the nonzero branch, `y` is the unique year with
`F(y) <= d+365 < F(y+1)`, `o = d+365-F(y)+1`, and `f` is the bound four-bit
year flag. Its bit3 is zero for leap years and eight for common years;
its low three bits equal `((F(y)-367) mod7)`, replacing zero with seven.
These equations describe the numeric encoding; no private quantity or
whole-caller semantics follow from it.

The year interval is `[-262143,262142]`. Its exact day endpoints are
`F(-262143)-365 = -95746129` and
`F(262143)-366 = 95745399`. Thus 191,491,529 of the 2^32 low-dword inputs
produce nonzero values; the remaining 4,103,475,767 produce zero. The result
always zero-extends an original EAX write into full RAX, including negative
year encodings. Every high32 input pattern has the same result as its low32.
Zero is an actual target result; this safe API has no refusal case.

The prologue PUSHes incoming RAX before clearing EAX. Both ordinary return
sites POP RCX. Neither intervening code nor any reachable call overwrites
that stack slot, so full RCX equals the original RAX on both zero and nonzero
returns. Other scratch registers, flags and the physical ABI/stack are
explicitly outside the two-field API. It does not imply they are unchanged.

## Initial addition and exact signed cycle division

ADD EDI,365 uses only the incoming low32, writes a zero-extended dword and
sets signed overflow. Since 365 is positive, overflow occurs exactly when
`d > 2147483282`. That path immediately returns RAX zero. Otherwise the
signed sum `t=d+365` lies in `[-2147483283,2147483647]` and is sign-extended.
This is the source's checked i32 addition. An unbounded alternative followed
by the final year gate happens to have the same selected outputs for the
overflow inputs; we do not claim an effective native control for a distinction
that those outputs cannot observe. Static controls bind the actual overflow
branch and immediate.

The signed reciprocal constant is `C=0x396b06bd=963315389`; its scale is
`Q=2^47=140737488355328`, divisor `D=146097`, and `C*D-Q=31405`.
For every positive `n<=2^31`, write `n=qD+r`, `0<=r<D`. The extra numerator
`q*31405+r*C` is bounded above by `140736986693439 < Q`. Hence
`floor(n*C/Q)=floor(n/D)` over the whole needed magnitude range. C is odd,
and `0<n<Q`, so `n*C/Q` cannot be an integer. For a negative product,
adding its sign bit to the arithmetic-shifted quotient therefore produces
truncation toward zero. The original split logical-SHR 64/SAR 32 sequence is
the same signed product shift by 47: the logical shift keeps bits 32..63 and
the following signed dword shift propagates original bit 63. The product's
magnitude is below 2^63, so the multiply itself does not lose information.

The following 32-bit subtraction gives the signed remainder `r_t` in
`[-146096,146096]`. Adding 146097 if `r_t<0` gives `r` in `[0,146096]`;
subtracting one from the truncated quotient in that case gives the floor
cycle `c`. Thus `t=146097*c+r`. The source uses `div_euclid` and `rem_euclid`
for this relation, not the reciprocal instruction sequence. Cycle bounds
are `-14700<=c<=14699`; all subsequent year arithmetic stays within i32.

## Closing every table index and panic arm

Let `L(k)` denote the first target table for k=0..400. All 401 bytes equal
`floor((k+3)/4)-floor((k+99)/100)+floor((k+399)/400)`. They are the leap-day
prefix of the 400-year cycle, with `L(0)=0`, `L(400)=97`. Let
`P(k)=365*k+L(k)`. Its adjacent differences are 365 or 366 and
`P(400)=146097`.

The unsigned reciprocal using `0x6719f361` computes `e=floor(r/365)`.
`certificates()` checks this identity at every one of the 146,097 possible
r values, evaluating the bounded integer expression
`(floor((r-floor(r*C/2^32))/2)+floor(r*C/2^32))//256`.
This is a finite arithmetic certificate, not instruction execution or an
instruction interpreter. It gives `0<=e<=400`, so the first access `L(e)`
always lies inside the full 401-byte table.

Write `h=r-365*e` (0..364). If `h>=L(e)`, use `k=e` and
`o=h-L(e)+1`. Otherwise use `k=e-1` and `o=h+366-L(k)`.
The exhaustive certificate verifies the same result against an independently
built prefix partition for every r; the following bounds explain each gate:

- The correction branch cannot occur for e=0 because L(0)=0. Therefore e>=1
  and r>=365. The panic branch at `0x151f76f` requiring r<365 is unreachable.
- Corrected k is in 0..399, so the unsigned k>=401 bounds branch at
  `0x151f77f` is unreachable. Both table accesses are now bounded.
- The original NEG/ADD/ADD correction yields `h+365-L(k)` modulo 2^32.
  Since L(k)<=97, the final value is at least h and at most 729. The unsigned
  below-h check at `0x151f79d` cannot select its overflow panic. Intermediate
  negative residues are modulo 2^32, but the final mathematical value fits.
- If e=400, then r>=146000 and h<=96<L(400)=97, forcing correction.
  Consequently the noncorrection branch always has e<400 and r<=145999
  (`0x23a4f`). Its branch at `0x151f7c5` to the flag-table panic is unreachable.

There are 19,600 correction residues and 126,497 noncorrection residues. The
result in every case is the unique k with `P(k)<=r<P(k+1)` and ordinal
`o=r-P(k)+1` in 1..365 or 1..366 according to that year's length. The original
unsigned `(o-367) >= 0xfffffe92` gate therefore always passes. This certificate
covers every possible post-addition input because every such t normalizes
into exactly one of these residues; it is not sampling the original i32 space.

All four outgoing calls are thus unreachable for every original low32 input
under the bound readonly tables. Their actual relocated slots, target bodies
and FDE/CIEs remain retained for evidence. No behavior of those error targets
or their further dependencies is needed or claimed.

## Year range, flags and final encoding

The full year is `y=400*c+k`, within `[-5880000,5879999]`. Both the multiply
and addition are signed-i32 representable. The actual unsigned comparison
`(y-262143) mod2^32 >= 0xfff80002` accepts exactly
`-262143<=y<=262142` in that wider derived bound. Outside it, RAX remains
zero from the initial XOR and the function returns. Monotonicity of F gives
the exact admitted day interval stated above.

All 400 bytes of the second table match the independently derived flags.
Because 146097 is divisible by 7 and the leap schedule repeats every 400 years,
the flag for k also describes y=400*c+k, including negative c. The source
computes leap status from `L(k+1)>L(k)` and weekday
`1+(P(k)+3) mod7`; this equals the full-year definition above. No table bytes
or upstream table initializer were transplanted into the source.

The original final gate examines `(packed & 0x1ff8) < 0x16e1`. For a common
year the largest allowed ordinal 365 yields 5848; for a leap year ordinal 366
yields 5856. Both are below 5857, so the gate cannot reject a date constructed
above. The source may return that packed value directly after its year gate.
Its shift counts 13 and 4 are fixed below32; the source's u32 casts and shifts
preserve the target's low32 year encoding, then u64 widening matches EAX's
zero extension. Since the flags are 1..15 and ordinal is positive, none of
these accepted encodings is zero.

## Independent source and safe-domain proof

The source uses one checked addition, Euclidean quotient/remainder,
ordinary division by 365, an at-most-one correction, derived leap/weekday
formulas and field assembly. Every u64 input and incoming RAX is admitted.
All potentially subtracting unsigned expressions are nonnegative under the
partition proof: correction decrements only a positive e, and the final
ordinal subtracts the start of the containing year. Intermediate products
are bounded by the 146,097-day cycle or the derived i32 year bounds. There
is no allocation, unsafe code, pointer dereference, variable-size memory
access, unbounded loop or Rust panic for any admitted input.

Original correspondence assumes the bound code and readonly tables remain
stable under ordinary mapping and valid return-stack storage. It excludes
MMIO, concurrency, corrupt stack/code, faults, ABI, flags, other scratch
registers and access traces. It does not execute the captured target or
require a native x 86 host.

The pre-Rust oracle instead tests the exact absolute-day endpoints, then
binary-searches a monotone absolute-year function over the entire admitted
year interval. It does not use the source's 400-year decomposition or
single-step correction. It derives flags from the absolute year's start.
The corpus includes every normalized residue, alternating cycle 0 and -1,
all century/year edges over more than 800 years, admitted endpoints, the
signed-add overflow boundary, ignored high32 bits and all saved-RAX bits.
All finite comparisons qualify new Rust; the universal arithmetic argument
above supplies the full 2^32-domain result.

## Retained static boundary

Whole-target authentication precedes parsing. Full body hashes, unique
actual overlapping FDEs and their CIE bytes bind the constructor, the one
qualified 323-byte caller, and three unreachable target bodies. The complete
801 table bytes, four Location-shaped records and two referenced source
paths are bound, with exact symbol-zero RELATIVE records. Every relocation
is checked for conflicts, including partial overlapping slot/data writers.
The entry's slot is `0x576e890`; its expected writer is unique.

E 8/E 9/FF 15/FF 25 scans find 324 FF 15 byte-pattern candidates through that slot,
zero in the other classes. Only `0x13c8e97` is qualified as a call boundary in
the retained complete caller at `0x13c8e10`; the other 323 candidates are not
claimed as decoded callers. The enclosing millisecond conversion and its
formatter/unwind effects remain outside this API. Prior
`foundation-millis-94` supplies the earlier static table/attribution evidence;
`RE-004-node94-packed-date-add-rust` is related shared-table work, not this
constructor's domain proof. No source provenance, pristine-library identity,
whole-node equivalence or component gate follows from this bounded result.
