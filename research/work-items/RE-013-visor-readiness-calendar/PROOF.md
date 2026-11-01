# Conditional +60 calendar argument

Target: Visor SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
All addresses below are ELF virtual addresses. Byte/FDE/native records are in
[observed/records.json](observed/records.json); complete native exports retain
cold branches as well as the admitted path. This is an argument about a stated
domain, not a source-type identity, generic helper theorem or runtime trace.

## Domain and premises

Define, mathematically, `leap(y)` by divisibility by 4 except centuries not
divisible by 400, with integer years including zero and negative years.
Let `L[r]` count leap years in `0 <= j < r`, for `0 <= r <= 400`.
Let `F[r] = (leap(r) ? 0 : 8) | ((365*r + L[r] + 3) mod 7 + 1)`,
for `0 <= r < 400`. The modulo is Euclidean. The exact 401 and 400 captured
bytes equal these formulas. The low-three-bit formula is a raw cyclic encoding;
no absolute weekday name or source-language representation is needed.

A canonical date is the signed 32-bit word
`p(y,o) = 8192*y + 16*o + F[y mod 400]`, where
`-262143 <= y <= 262142` and `1 <= o <= 365 + leap(y)`.
Its underlying bits are formed by the observed shift/OR layout. The positive
low part is below 8192, so fields do not overlap. These are explicit admission
conditions; the fast path is not a validator for arbitrary input words.

For the ordinary theorem, the source time words satisfy
`0 <= s < 86400`, `0 <= n < 1000000000`.
For the separate extended-input theorem, replace the latter bound with
`0 <= n < 2000000000`. These are numeric domains; calling the extended values
leap-second encodings would require a source/API contract not established here.

Assume execution reaches `0x5b4369` with R15 pointing to a readable, stable
12-byte source `(p,s,n)`, and with a valid, distinct caller stack. The copied
input at `rsp+0x88..+0x94`, the time output at `rsp+0x28..+0x38` and the
current triple at `rsp..+0xc` must be valid nonaliasing storage. Assume the
relocated slots select the retained callees, code/tables/slots are unchanged,
ordinary x86-64 instruction behavior and call/stack preservation apply, and no
concurrent/opaque writer changes the relevant storage. Normal behavior of
earlier calls is not by itself proof of these premises.

The timestamp's original constructor, earlier calls/mutations, current-clock
calendar construction, live loader behavior and ambient memory are not closed
by this packet. For the comparison corollary, independently admit the current
triple into the same canonical-date and ordinary-time domain. This is stronger
than merely assuming a clock call returned.

## From source copy to fixed duration

At `0x5b4369..0x5b437d`, the source tail DWORD at +8 and source head QWORD at
+0 are copied to the three words at stack +0x88, +0x8c and +0x90. The order of
the two loads is retained; there is no atomic-snapshot claim.

At `0x5b437f`, the eight bytes at `0x6e748` are binary64 60.0, and the call
at `0x5b4387` uses RELATIVE slot `0x7e53c8 -> 0x330360`.
The positive finite value takes `0x330368 -> 0x330439`. Its exponent is
`0x404`, and the implicit-leading-one significand is shifted by
`0x433-0x404 = 47` at `0x3304fd`, yielding 60. The residual fraction
after the shift by 5 at `0x330505` and mask at `0x330508` is zero.
Thus multiplication and rounding at `0x33050b..0x330564` leave nanoseconds
zero; the return at `0x33056d` has RAX=60, EDX=0. This selected path makes
no external call and does not enter the negative/general-duration path.

The caller's `0x5b438f..0x5b43d5` forms 60,000,000,000, which is below the
i64 clamp, then uses multiplier `0x112e0be826d694b3` and shift 90 to recover
60 seconds and remainder zero. These particular integer facts are certified.
The call at `0x5b43e7`, via `0x7e5390 -> 0x445830`, receives:
RDI=stack+0x28, RSI=stack+0x8c, RDX=60, ECX=0.

## Time output and day carry

The complete time extent is `[0x445830,0x445992)` (354 bytes, 87 rows).
The source seconds are loaded with zero extension at `0x445831`; the
nanoseconds DWORD is loaded at `0x445834`.

Because RDX=60, `0x445837..0x445856` leaves duration seconds 60 and fractional
addition EAX=0. For ordinary n, the signed comparison at `0x445859` goes
directly to `0x4458a2`. For extended n>=1e9, all n are still below signed
2^31, and the positive-duration branch at `0x445864` goes to `0x44589c`,
which subtracts exactly 1e9 before reaching `0x4458a2`.
It does not add an extra second on that positive-duration branch.

Hence let `n' = n` for ordinary input and
`n' = n - 1000000000*[n>=1000000000]` for the extended input domain.
At `0x4458a2..0x4458bb`, seconds are `t=s+60` in [60,86459], ESI=n' in
[0,999999999], and neither signed-overflow exit nor either further fractional
normalization branch is selected. All interval claims follow from the stated
bounds, not sampled n values.

At `0x4458dd..0x445918`, the signed high-product sequence with
`M=0x1845c8a0ce512957` is `floor(t*M/2^77)` on this positive domain.
The finite certificate checks every t in [60,86459] against `floor(t/86400)`.
The remainder is nonnegative, so the negative-remainder correction is zero.
Consequently the stores at `0x445923,0x445926,0x445929` write:
DWORD +0 = `(s+60) mod 86400`;
DWORD +4 = n';
QWORD +8 = `86400*k`, where `k=[s>=86340]`.
All selected additions/subtractions remain in signed bounds, so no overflow
call is reached. The normal return at `0x445931` follows.

This is not a theorem for arbitrary seconds, duration seconds/fractions,
signed-invalid n, or all helper branches.

## Caller guards and date argument

The caller loads the QWORD carry at `0x5b43ed`. For both possible carries
0 and 86400, the unsigned comparisons at `0x5b4409` and `0x5b4425`
avoid the fallback branches at `0x5b440c` and `0x5b4428`.
The certificate records both intermediate unsigned values; it does not assume
these guards are universally redundant.

At `0x5b442a..0x5b4433`, EBP receives the new second, R12D the new n', and
EDI the copied date. The magic division at `0x5b443a..0x5b4452` gives ESI=k
for these two nonnegative carries. Although that caller uses a logical shift,
its value is nonnegative here. RELATIVE slot `0x7e5398` binds the call at
`0x5b4454` to `0x444040`.

## Date output, including year-end and range failure

The complete date extent is `[0x444040,0x44426c)` (556 bytes, 145 rows).
At `0x444043..0x444048`, the extracted ordinal is `(p>>4)&511=o`.
At `0x444060..0x444068`, bit 3 supplies year length 365 when set and 366
when clear, exactly matching the admitted table-derived date.

For k=0, and for k=1 with o less than the year's length, `o+k` is positive,
has no signed overflow and is within year length. The branch at `0x444070`
goes to `0x44420c`, which preserves year/flag bits with `0xffffe00f` and
replaces only the ordinal by `o+k`. These paths return a canonical nonzero
date, including the upper year when no day rollover is needed.

The remaining admitted case has k=1 and o equal to year length.
At `0x444076..0x4440a9`, the arithmetic right shift recovers signed year y.
The `0x51eb851f` multiplication and shifts implement truncating y/400;
the finite certificate checks every admitted y. The remainder correction
produces `r=y mod 400` in [0,399] and a corresponding floor cycle q.

At `0x4440ac..0x4440cd`, the table at `0x7d692` forms
`365*r + L[r] + o - 1 + 1 = 365*(r+1) + L[r+1]`.
This is positive and at most 146097. No zero or signed-overflow exit is
selected. EAX is explicitly zeroed at `0x4440cb`.

The division through `0x396b06bd` at `0x4440d8..0x444107` splits that
quantity into a 400-year carry and nonnegative cycle day c. For each of the
400 year-end cases, the next year-in-cycle is r+1, except that r=399 produces
year 0 with cycle carry 1. The certificate retains every case.

At `0x444109..0x444132`, the multiply/shift estimate equals `floor(c/365)`;
its identity is checked for all c in [0,146096]. At a year start,
`c=365*r'+L[r']` and `0<=L[r']<=97<365`, so the estimate is exactly r'.
Subtracting L[r'] at `0x444135` yields zero and no borrow. Therefore the
admitted path takes `0x444137 -> 0x444192`; the correction branch beginning
at `0x444139` is never needed for this theorem. The largest admitted year
start is 145732, below the guard bound `0x23a4f=145999`.
The increment at `0x44419e` gives ordinal 1, passing the [1,366] gate.

At `0x4441b6..0x4441c6`, the corrected old cycle and day carry combine into
year y+1. The unsigned gate at `0x4441c9..0x4441d5` admits exactly
[-262143,262142] among possible result years; every value in the needed
[-262143,262143] interval is certified. If y=262142, the result year 262143
fails and the return at `0x444191` carries the still-zero EAX. Otherwise,
the flag-table read at `0x4441e0`, shift/OR at `0x4441e4..0x4441ed` and
mask/bound validation at `0x4441f0..0x444201` return canonical
`p(y+1,1)`. The ordinal 1 validation is well inside the bound.

Thus, for canonical input and k in {0,1}, date return zero occurs exactly
when k=1 and the input is the final day of year 262142. The panic/bounds-call
paths in this complete extent are excluded by the stated range and branch
argument; their implementations and any unexpected returning behavior are
not assumed to supply useful results. Generic date shifts remain unproved.

## Selected deadline and ordinary saturation

On nonzero date return, `0x5b445e..0x5b4470` selects that date and the
new second/n' words. On zero, `0x5b4485..0x5b449b` selects the immutable
triple at `0x7c7e4`:
`(2147473118,86399,999999999)`.
The first word equals `p(262142,365)`: this year is common, ordinal 365 is
its final day and F[142]=14. The fallback is not a zero date.

For ordinary admitted input, the selected deadline is the canonical
calendar result of adding 60 seconds, clamped at the greatest ordinary
admitted triple. This clamp happens exactly for the final admissible date
with source second>=86340. It does not require nanosecond rounding.

Canonical signed packed dates order by year then ordinal: changing a year
adds 8192, exceeding every allowed ordinal/flag low part; within a year the
flag is constant. Together with the unsigned second/nano comparisons at
`0x5b4475..0x5b44c6`, the existing strict lexicographic comparison therefore
cannot select override against the fallback when the current triple is
also admitted into the ordinary domain. Equality selects deferral.
This is a local branch-selection result, not proof that later diagnostic
calls return, that the whole predicate completes, or that elapsed time is
monotonic.

## Extended input and counterexample

For source n in [1e9,2e9), the same date carry is used and n' is n-1e9.
For example, source second 86399,n=1999999999 yields second 59,n'=999999999
and day carry 1. This is a raw normalization fact. It does not establish
civil leap-second validity, UTC behavior or a physical 60-second interval.

A separate current triple
`(2147473118,86399,1000000000)` compares strictly above the fallback,
because the unsigned final word is larger. Thus the fallback cannot be
called a universal maximum of the extended domain, and the ordinary
deferral corollary must not be extended to it.

## Evidence boundary

The collector authenticates the complete image, binds RELA call slots,
complete FDE extents, their CIE back-references and raw CIE records, native rows
and exact bytes, and compares independent
GNU/LLVM instruction byte partitions. An FDE is unwind provenance, not by
itself a complete function-ownership proof. Local direct-branch inventories
do not exclude computed incoming references or opaque effects elsewhere.

The arithmetic certificate checks scalar formulas and complete finite
domains; it has no instruction stream, registers or program counter.
The manually reviewed address-to-formula connection above remains necessary.
Below-image-hash controls independently exercise named byte/table/RELA checks.
They are binding tests, not semantic executions of modified machine code.
No arbitrary repository evaluator, captured binary, child process of Visor,
Rust reconstruction or two-build comparison was run.
