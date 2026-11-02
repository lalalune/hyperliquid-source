# Source refinement of the frozen request-throttle contract

The immutable pre-code CONTRACT, PROOF and CALL-FRAMES remain the native
premises. This source implements their finite supplied-state relation. It does
not close native logging, locking, memory allocation, scheduling, panic or
network behavior. Source allocation must succeed. There is no allocation-panic
rollback claim, and no claim that Rust B-trees have native shape or capacity.

## Owned state and ordinary result order

`RequestKey` derives lexicographic ordering over `u64` round followed by all32
hash bytes. `RequestThrottle` privately owns a BTreeMap keyed by this value.
Its stored RequestRow contains the same key, a canonical timestamp, a BTreeSet
of byte reasons and a bool. `from_rows` validates each stamp and rejects duplicate
keys; it returns no partially constructed state. A public raw RequestTimestamp
can be invalid, but only valid values enter retained rows. Fields cannot be
modified through the private map. `snapshot` returns cloned values in key order;
future calls cannot mutate earlier snapshots. Initial rows are an explicit
supplied-state interface, not recovered wire decoding or runtime memory admission.

In `consider`, invalid time returns before accessing or modifying the map.
The entry operation preserves an occupied row's stamp/reasons/sent; a vacant
entry installs precisely the event time, empty reasons and false. It records
whether registration happened. Reason insertion is before delay calculation,
deadline-range refusal, time comparison and sent suppression. An invalid
deadline therefore leaves registration/reason changes in place and sent
unchanged, including when already sent. These two refusal rules are new safe
policies, not equivalence to native failure/unwind behavior.

On an in-range deadline, derived timestamp Ord compares signed packed date,
unsigned second, then unsigned nano. The frozen proof establishes canonical
packed-date chronological order, including negative years. `time < deadline`
suppresses strictly before the deadline. The second operand `row.sent` suppresses
every already-sent row. Otherwise sent becomes true and the exact key is returned.
Registration/deadline are explicit derived observations; native inactive output
words and key padding are not represented. No other row changes.

The native proof establishes the same map/set value updates for arbitrary valid
finite tree height, including both split algorithms and the new-row handle
through separator propagation. Using standard BTreeMap/BTreeSet refines that
abstract relation; it does not assume native generic insertion from a symbol name.

## Integer implementation of rounded delay nanoseconds

Let finite binary64 magnitude be `m * 2^e`. For a normal value, m is the53-bit
integer implicit-one significand and e=encoded_exponent-1075; for a subnormal,
m is the at-most52-bit fraction and e=-1074. Thus m<2^53 and -1074<=e<=971.
The exact product magnitude by1e9 is `P * 2^e` with P=m*1000000000<2^83.
The multiplication in u128 cannot overflow. Zero P returns integer zero;
encoded exponent2047 also returns zero, matching every masked NaN/infinity
product's nonfinite class without needing to retain a NaN payload.

For nonzero P let w=bit_width(P), 1<=w<=83, and s=max(w-53,0), so0<=s<=30.
If s=0 the product is already exact. Otherwise q=P>>s, discarded=P mod2^s,
half=2^(s-1). The source increments q precisely for discarded>half or equality
with odd q, which is round-to-nearest/ties-to-even. q is initially53bits;
increment reaches at most2^53. In that sole carry case q is divided by2 and
the exponent is incremented. The adjusted power is e+s+(carry?1:0).
After this step 1<=q<2^53 and q*2^power is the rounded product.

No separate right shift to a subnormal quantum is missing: original e>=-1074,
and multiplying the significand by the integer1e9 cannot introduce bits below
2^-1074. A product still below the minimum normal magnitude is already an exact
integer multiple of the minimum-subnormal quantum and has at most52bits. It
therefore takes s=0. Normal/subnormal crossover is exact as well.

The highest occupied exponent is `power + bit_width(q)-1`. If this exceeds1023,
the binary64 product overflowed and the source returns zero before conversion.
At the maximum finite boundary, the same53-bit rounding and carry implements
the nearest/ties-even overflow threshold; it does not saturate an infinite
product. Under the native masked exceptions/RN-even/FTZ-off/DAZ-off premises,
this is the same classification as the native absolute-product-bit check.
The source uses no host floating point and does not require those settings
itself; the settings remain premises of correspondence to the captured SSE.

For a finite rounded product with highest exponent>=63, all positive magnitudes
truncate/saturate to i64MAX and negative magnitudes to i64MIN. This includes
the exact +/-2^63 endpoints. With highest exponent<63, a nonnegative power
can be at most62; q<<power is less than2^63, so its u128 shift and i64 cast are
exact. For negative power, unsigned right shift truncates toward zero; a shift
of128 or more yields0 via checked_shr. For smaller shifts the result is also
less than2^63. Applying the original sign is safe: magnitude is in0..i64MAX,
so no signed negation overflow occurs. The saturated branch never negates
i64MIN. Signed zero becomes integer0 as required. Default delay bypasses this
conversion and uses the exact integer1000000000.

## Private Gregorian bridge and integer widths

Define D(y)=365*y+floor((y+3)/4)-floor((y+99)/100)+floor((y+399)/400).
For every integer year, D(0)=0 and D(y+1)-D(y) is365 plus the Gregorian leap
predicate. Therefore D is exactly the serial day of year start, including
negative years. Rust div_euclid with positive divisors implements these floors.
`year_flag` is ((D(y)+3) mod7)+1 plus8 for common years, identical to the
frozen captured cycle-table bridge. The source does not copy or import the
pre-code oracle's400-year prefix array or bisect inversion.

Timestamp admission extracts signed y=packed>>13 and ordinal=(packed>>4)&511,
checks -262143<=y<=262142, ordinal1..365+leap, the exact canonical low nibble,
second<86400 and nano<1e9. Those fields partition all32 packed bits, so no
unvalidated high field remains. D and all its intermediate arithmetic are
well inside i64: |y|<=262144 for every input or search boundary, and
|D(y)|<96000000. Timestamp total nanoseconds have magnitude<8.3e21; adding
any i64 delta stays below8.4e21, far below2^127. All i128 products/additions
are exact. Euclidean division by86400e9 yields a day within1e8 in magnitude,
so the day-to-i64 cast before range checking is safe even for range refusals.

Out-of-range day returns None. Otherwise binary search starts with
D(-262143)<=day<D(262143) and maintains D(low)<=day<D(high). The interval
strictly decreases until high=low+1 (at most19 steps), giving the unique
year. Ordinal=day-D(low)+1 lies in1..365+leap, and the Euclidean remainder is
in0..86400e9-1, yielding valid u32 second/nano. The admitted year fits signed
19bits, so shifting its i32 by13 yields the exact signed packed upper field;
ordinal and flag occupy only lower bits. Their bitwise union is the exact
canonical packed date. No raw timestamp normalization is silently performed.

This proves in-range deadline addition as stamp_ticks+signed_nanoseconds.
The native proof separately establishes the same composition through its
time/day helpers under explicit frames and normal-return premises.

## Qualification boundary

The pre-code949 histories/3776 steps and their expectations predate this source.
The input-only client will decode TH01 frames, construct supplied state, call
consider and serialize snapshots/results; it will not receive case names,
domain labels, expected outputs, native bytes or the oracle. Its transport
checks are separate from InvalidTime/DeadlineRange value policies.

Only explicit library and request_throttle tests are selected. The old
evidence_contract test was inspected: it reads another packet and invokes
shasum on captured bytes. It is not run in this qualification. No captured
executable, instruction evaluator or broad repository suite is executed.

Source/client/harness/toolchain admission and immutable freeze precede any
authorized compilation. Exact raw commands, failed commands if any, source
copies and first compiled artifacts are retained. Compiled mutants must run
the entire input stream; compilation failure or malformed output is not a
semantic kill. Native-conditional and new-policy history mismatches are counted
separately. Parent source/build gate is still required.
