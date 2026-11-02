# Validated packed-date addition

This proof concerns the numeric result in EAX of the complete node #94
`[0x151f870, 0x151fa9c)` FDE. Addresses are ELF virtual addresses. The full
identity and supporting bytes are locked by `static-lock.json` and the frozen
oracle. The outer checked wrapper at `0x1450810`, neighboring calendar helper,
panic implementations and invalid input representations are outside the claim.

## Domain and observable result

Decode the low 32 bits of EDI into signed year `y = (EDI as i32) >> 13`,
ordinal `o = (EDI >> 4) & 511`, and flag nibble `f = EDI & 15`. Admit exactly:

- `-262143 <= y <= 262142`;
- `1 <= o <= L(y)`, where `L(y)` is 366 when `4 | y` and either `100 ∤ y`
  or `400 | y`, and 365 otherwise;
- `f = (8 if L(y)=365 else 0) | (1 + ((S(y)+3) mod 7))`, with Euclidean
  remainder and
  `S(y)=365y+floor((y-1)/4)-floor((y-1)/100)+floor((y-1)/400)+1`.

ESI is any `i32` day offset `d`. No other incoming register is read before
being overwritten. In particular the outer wrapper's computed RCX is unused.
The callee has no input pointer or observable memory mutation; its own balanced
stack saves are outside the value projection. All normal returns write EAX,
therefore zero-extend that value into RAX. The safe Rust API returns this u32
value. `Ok(0)` is the target's normal range rejection. `InvalidPackedDate` is a
new API refusal; it is not a recovered original return or exception.

`S(y)` counts days from ordinal one of year zero. It is strictly increasing,
`S(y+1)-S(y)=L(y)`, and `S(y+400)-S(y)=146097`, divisible by 7. Thus both
length and flags repeat every 400 years, including negative years. The admitted
serial interval is `[-95745764, 95745764]`. No admitted packed date is zero.

## Bound tables and edges

The LEA at `0x151f8e3` resolves to `0x250354`: all 401 bytes are
`A[r]=sum(L(j)-365 for 0<=j<r)`, for `r=0..400`. The LEA at `0x151fa09`
resolves to `0x2504e5`: all 400 bytes are the flag formula above for years
`0..399`. The oracle independently generates the complete arrays and compares
them byte for byte with the authenticated target; it does not infer identity
from a few examples. No relocation overlaps either table.

Five panic call sites remain in the complete body. Calls `0x151fa55` and
`0x151fa62` use slot `0x576e150`; calls `0x151fa74` and `0x151fa89` use
`0x576dfc8`; call `0x151fa96` uses `0x576e118`. Exact RELATIVE records, zero
stored slot bytes, RIP-relative location references, all five 24-byte source
locations and both pointed path strings are retained. These are dependency
facts, not execution or a semantic model of the panic targets. The arithmetic
below proves all five calls unreachable on the admitted domain.

## Fast path

`0x151f87e..0x151f88e` computes the signed 32-bit sum `o+d` and retains OF
before testing its sign. It goes slow on signed overflow or a nonpositive
sum. The expression `(EDI << 28) as i32 >> 31` is -1 exactly for common-year
flag bit 3, making the upper bound `366 + (-1 or 0) = L(y)`. If the positive
sum is at most that bound, `0x151fa3c` clears only the ordinal field with
`0xffffe00f` and inserts `(o+d)<<4`. The result has the same valid year and
flags and the correct ordinal. It equals the global serial calculation.
The bit mask preserves the full signed 19-bit year; no sign-extension of the
returned EAX value is claimed.

## Slow path and original-width overflow

The signed reciprocal sequence at `0x151f8ac` computes truncating `y/400`.
Subtracting 400 times that quotient gives a remainder in `[-399,399]`.
Adding 400 to a negative remainder, and subtracting one from the quotient,
produces Euclidean `y=400c+r`, `0<=r<400`.

The table sum is `365r+A[r]+o`, in `[1,146097]`, so its zero check at
`0x151f8f3` cannot reach the first panic. After decrement it is a cycle day
`u` in `[0,146096]`. The target then performs the **signed i32** addition
`t=u+d` and returns zero on OF. This is not silently treated as an unbounded
addition in the proof: negative overflow is impossible because `u>=0`, and
positive overflow means `t>=2^31` mathematically. Since the smallest admitted
input cycle is -656, the corresponding global serial is at least
`-656*146097+2^31 = 2051644016`, already above the admitted maximum 95745764.
The Rust i64 calculation therefore rejects precisely these overflow cases too.

For nonoverflow `t`, the second signed reciprocal sequence computes truncating
`t/146097`; the sign/remainder correction again gives Euclidean
`t=146097q+D`, `0<=D<146097`. Combining input cycle and day cycle gives
`S(y)+o-1+d = 146097(c+q)+D`.

Both signed reciprocal claims follow from integer inequalities, not sampling.
For divisor `v`, scale `B=2^s`, multiplier `m`, positive error `e=mv-B`, and
magnitude bound `M`, write a nonnegative magnitude as `kv+r`. The check
`floor(M/v)*e+(v-1)*m < B` proves `floor(x*m/B)=floor(x/v)` over the entire
magnitude domain. Here:

| v | s | m | e | M | residual upper bound | B |
| --- | --- | --- | --- | --- | --- | --- |
| 400 | 39 | 1374389535 | 112 | 262144 | 548381497825 | 549755813888 |
| 146097 | 47 | 963315389 | 31405 | 2147483648 | 140736986693439 | 140737488355328 |

For a negative nonzero magnitude, the odd `m` and `0<x<B` prevent `xm/B`
from being an integer. Consequently arithmetic right shift of the negative
product followed by adding one gives the negative truncating quotient. Signed
64-bit products are within range. The target's high-half extraction followed
by `SAR ESI,15` is the signed shift by 47 represented in that table.
`oracle.certificates()` rechecks these inequalities under optimized Python.

## Inverting the normalized cycle and excluding the panic arms

At `0x151f939`, the unsigned multiply/high-half/add/shift expression equals
`a=floor(D/365)`. The certificate exhausts **every** `D` in `[0,146096]`
and independently checks this quotient identity; no captured instruction or
instruction emulator is run. Therefore `0<=a<=400`, and the first leap-table
read is always within its 401-byte allocation. Write `b=D-365a`, `0<=b<365`.

If `b>=A[a]`, use year residue `a` and ordinal `b-A[a]+1`. The branch's
extra `D<=145999` check holds; in particular `a<400`, so its 400-byte flag
table access is valid. If `b<A[a]`, decrement the year residue to `a-1` and
use ordinal `b+366-A[a-1]`. Here `D>=365`, `a>=1`, `a-1<401` and
`b+365-A[a-1]>=b` hold. These establish respectively the subtraction,
bounds and addition panic guards. The certificate checks them separately,
including the original unsigned comparisons, for all normalized days.

In both branches the resulting residue `r'` and ordinal `o'` satisfy
`PREFIX[r'] <= D < PREFIX[r'+1]` and `o'=D-PREFIX[r']+1`, where
`PREFIX[r]=365r+A[r]`. This is independently checked with a prefix-boundary
binary search. There are 19,600 decrement cases. Hence the apparently loose
ordinal guard `(o'-367) mod 2^32 >= 0xfffffe92` accepts (`1..=366`), and the
final `((o'<<4)|flags[r']) & 0x1ff8 < 0x16e1` also accepts: common-year
ordinal 365 yields 5848; leap-year ordinal 366 yields 5856; the next invalid
values would fail. These conclusions cover all offsets after Euclidean
normalization, rather than only the fixture deltas.

## Year gate and final packing

The assembled signed year is `Y=400(c+q)+r'`. Input `c` is in `[-656,655]`,
and `q` in `[-14700,14699]`. Thus `Y` is within `[-6142400,6141999]`; every
intermediate add and multiply fits i32. The unsigned comparison at
`0x151f9f9..0x151fa05` accepts exactly
`(Y-262143) mod 2^32 >= 2^32-524286`, which in this bounded range is
`-262143<=Y<=262142`. Other years return zero.

For an accepted year, `Y<<13`, the one-based ordinal shifted by 4, and the
flag nibble occupy disjoint fields. The returned low 32 bits are exactly the
packed representation of the global serial result. The original shifts are
32-bit and intentionally discard the high year bits. There is no pointer
arithmetic, unknown dereference, undefined shift or admitted panic path.

## Independent Rust and oracle

Before either Rust file existed, `oracle.py`, all target/edge facts, arithmetic
certificates, inputs and expected outputs were frozen with their SHA-256 values
and timestamp in `frozen/ORACLE-FREEZE.json`. The oracle decomposes a year by
Euclidean division into a 400-year cycle and a prefix partition. It adds the
delta and locates the result with `bisect_right` over that fixed cycle.

The independently authored Rust uses the closed expression `S(y)` and searches
the entire admitted year interval. Its invariant is `S(low)<=serial<S(high)`;
choosing the midpoint and retaining the containing half terminates with
`high=low+1`, so `low` is the unique containing year. The interval has fewer
than 2^19 years. All serial arithmetic fits i64 (even an extreme i32 delta is
less than 2.25 billion in magnitude); divisors are nonzero and fixed, shifts
are 13 and 4, and the final ordinal is at most 366. No dependencies, unsafe
code, copied source or captured instruction bytes implement the function.

Agreement with these target-grounded arithmetic facts supports the stated
value projection. Native execution compares only the newly built Rust with
the frozen arithmetic oracle. It is not direct differential execution of the
target, ABI reproduction, machine-code equality or whole-node equivalence.
