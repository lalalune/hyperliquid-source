# Local relation argument and evidence limits

This proof concerns the raw instructions in the three FDE-bounded exports,
under valid memory and normally returning helpers. It does not assign Rust
symbols or prove whole-oracle equivalence. All addresses below are node115 VAs.
`obligations.json` binds the instruction spans; `records.json` also binds the
complete bodies, relocations, constants, native instruction boundaries and FDEs.

## Source association, arguments and configuration

The instruction at `0x366fbbe` loads Location `0x6468b20`. A RELATIVE relocation
binds its path pointer to `0x447094`, the 47-byte string
`l1/src/clearinghouse/oracle/reference_oracle.rs`; the remaining record encodes
line 211, column 25. This associates the request site with a source file, not
with a recovered function name or original source listing.

The decision keeps incoming RDI in R14 (state base), RSI in RBX (current
12-byte record pointer), and ECX in EBP (selector). The provider call at
`0x366f920` uses slot `0x64e8cc8 -> 0x4209430`; RDX, XMM0, XMM1 and R8 remain
incoming values. Its raw u16 result tag is saved in R13 and its qword at local
`+0x58` in R15. A tag other than `0x1a2` first requests cleanup `0x36dae30`.
The value is not used for the ratio unless that tag later passes.

A two-byte key is `[0, low8(selector)]`. The configuration call at `0x366f966`
uses state `+0x40`, this key, and slot `0x64e8cc0 -> 0x4209a50`. Its raw tag
byte is local `+0x48`: tag 0 loads a flag byte from `+0x49`, tag 1 substitutes
zero, and other tags jump directly to the false return at `0x366faeb`.
The double at local `+0x40` is the tolerance. The provider, cleanup and
configuration calls are opaque and may themselves have side effects; the
short return does not mean that the whole function is effect-free.

## Lookup and strict ratio gate

`NEG` followed by `JNO` distinguishes a first state qword equal to
`0x8000000000000000`. In that sentinel shape, state `+8` must be nonzero;
`0x35bf030` returns a raw record whose dword tag must differ from 1.
The candidate address is returned base + 56 * returned index + `0xb8`.

The other shape calls `0x4558710`. A set result low bit or returned index
at least state `+0x18` takes the stateful path. Otherwise it forms index +
state `+0x10`, subtracts the first state qword once when unsigned-greater-or-
equal, and computes backing(state `+8`) + 72 * adjusted index + `0x10`.
These are observed address formulas, not independently established container
invariants or recovered key-comparison contracts. Arithmetic is machine-width;
valid no-overflow container inputs are a premise for the array interpretation.

At either successful lookup, the provider tag must equal `0x1a2` and the qword
at candidate `+0x30` must be nonzero. Let the provider qword be `p` and that
candidate qword be `q`. Both are used unsigned. `CMOVB` and `CMOVA` at
`0x366fa6b/0x366fa73` select `lo = min(p,q)` and `hi = max(p,q)`.

The PUNPCKLDQ/SUBPD/ADDSD sequences convert each u64 to binary64. Constant
`0x451210` supplies dwords `0x43300000,0x45300000`, and `0x450170` supplies
biases `2^52,2^84`. The low lane becomes the exact low 32 bits; the high lane
becomes the exact high 32 bits times `2^32`; their addition produces the
rounded u64 value. Under round-to-nearest-even, the independent integer
reference in `relations.py` agrees at 554 exponent, endpoint and midpoint
neighbors. The general deduction follows from the exact lanes and final add,
not from exhaustive sampling of all u64 values.

Writing RN for binary64 rounding, the distance is
`d = RN(RN(RN(hi) / RN(lo)) + (-1.0))`. The code adds the bound `-1.0`
constant at `0x458dc8`; it does not compute `abs(p/q - 1)` with an asymmetric
reference denominator. If `p == 0`, nonzero `q` gives positive infinity under
masked divide exceptions. Large neighboring integers can round to the same
double, making `d == 0` even when their u64 values differ.

MAXSD with a positive-zero second operand clamps tolerance `t` to `t` when
`t > 0`, otherwise to positive zero (including quiet NaN and negative zero).
UCOMISD at `0x366facf` compares this result with `d`. JBE at `0x366fad3`
takes the stateful path for less/equal/unordered. Only strictly `clamp(t) > d`
requests `0x3ce7650` with state `+0x78` and the two-byte key, then returns false.
Calling this a reset/remove-shaped request is an inference; the helper's
internals and actual removal are not closed here. Equality retains state,
including equal prices with zero tolerance and infinity against infinity.

The floating comparison argument uses Intel's documented MAXSD second-operand
selection and UCOMISD flag relations. See the primary
[Intel instruction reference](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf).
The packet assumes nearest-even rounding, masked floating exceptions and quiet
NaNs; it does not recover live MXCSR or behavior when exceptions interrupt flow.

## Stateful entry writes and pair projection

Lookup misses, the rejected provider tag, zero `q`, and the ratio fallback
converge at `0x366faf2`. The code requests `0x3cc83c0` for state `+0x78` and the
key, then passes that raw result to `0x3f15c10`. Let its returned pointer be E.
The selected writes are:

| Condition | Destination | Source |
| --- | --- | --- |
| dword[E+8] == 0 | qword[E+8], dword[E+16] | current qword[0], dword[8] |
| always on this path | qword[E+20], dword[E+28] | current qword[0], dword[8] |

The first conditional tests a dword, not the whole first record. If a copied
record has a zero low dword, a later call can still take that write again.
“First” and “latest” are positional roles; one-time initialization is not proven
for every possible current record. The 12-byte values are timestamp-shaped
inferences, not established Rust types, clocks or time units.

The pair helper at `0x366fb47` uses slot `0x64e0fc0 -> 0x162a290`, with RDI =
current and RSI = E+8. Its raw results are signed RAX:i64 and EDX:i32. For
`s < 0 && n > 0`, the code increments `s` and subtracts `10^9` from `n`.
This preserves the exact rational `s + n/10^9`; increment/subtract stay within
the stated signed widths. Otherwise the pair is unchanged. The double is
`RN(RN(s') + RN(RN(n') / 10^9))`, followed by MAXSD with +0. Comparison with
positive infinity selects +0 for equal/unordered. For all raw i64/i32 inputs
the preceding arithmetic is finite, so that last guard is inactive under
these assumptions.

The signed-pair projection is prior research, already present in
`RE-001-node115-latency-projection` and PR #993. Its reuse is credited rather
than claimed as a new arithmetic discovery. What is new here is its bound use
in the reference-oracle entry, subsequent threshold branch, return identity
and caller store gate. The pair helper's complete contract remains unclosed.

## Threshold gates the code-8 request, not the returned low bit

Let `x` be the projected nonnegative value, `T = double[E]`, and `f` the saved
raw configuration byte (zero for configuration tag 1). The tail is:

1. UCOMISD `x,T`; SETBE AL; AND AL,f.
2. A second UCOMISD `x,T`; JBE return.
3. Otherwise XOR f,1; TEST f,1; JNE return.
4. Request slot `0x64e4ea8 -> 0x4524e40` with EDI=8 and the source Location;
   then MOV AL,1 and return.

| Comparison | First AL | Code-8 request | Final AL, normal return |
| --- | --- | --- | --- |
| less/equal/unordered | f & 1 | never | f & 1 |
| ordered greater, f even | 0 | never | 0 |
| ordered greater, f odd | 0 | yes | 1 |

For every raw byte, **final AL = f & 1**. The request occurs iff `x > T` is
ordered and `f` is odd. A tie or quiet-NaN threshold makes no request. Calling
this a notification-shaped request is an inference: logging, panic, throttling
or other effects of the callee are not established. PR #2092 also binds this
shared callee; this packet does not claim its reconstruction. The code-8 call
could fail to return, which is why the return identity is explicitly conditional.
All 256 raw bytes across four comparison categories are enumerated, without
claiming that nonboolean flag encodings are reachable from valid Rust values.

## Entry seed and caller consequence

At `0x3f15c10`, raw input tag 3 takes an existing-entry-shaped pointer path and
skips seed construction. The other path loads bits `0x4024000000000000` (10.0)
at `0x3f15c50` and stores dword zero at local offsets 8 and 20. It does **not**
initialize all 32 bytes: payload bytes outside those markers remain unspecified
by these instructions. Tag 2 packs the local record into a request to
`0x4548aa0`; the other non-3 path passes the local seed to `0x3706d00`.
Thus the native fact is a submitted seed and marker pair. Propagation through
the insertion helpers, other writers, universal default values and “ten seconds”
are not established. The remaining pointer formulas are retained in the complete
exports but are not a reconstructed container contract.

The selected caller `0x53811a0` invokes the primary decision twice on distinct
branches: selector 1 at `0x538141e` and selector 0 at `0x5381496`, through
RELATIVE slot `0x64e64a8`. Both pass the state at outer-object `+0x160` and the
current record at caller-base `+0x60`. The proposed qword is passed in XMM0;
XMM1 carries the previous stored qword interpreted as a double. TEST AL/JNE skips the proposed qword
store when AL is nonzero. AL == 0 writes the field at caller-base `+0x7a8`
(selector 1) or `+0x7a0` (selector 0). Both branches then write output tag
`0x1a2`. Price-field terminology is inferred from this native caller context;
its earlier conversions, provider semantics and complete business policy are
not claimed. The other two primary-call owners appear only in the qualified
incoming census: `0x2767d10..0x27680b6` and `0x5381550..0x53818f6`.

## Comparator controls and exclusions

`verify.py` authenticates 23 spans, 14 RELATIVE records, seven literals/Location
records and three FDE extents. One corruption per obligation is rejected with
whole-image/body/export guards bypassed (47 total). Independent tests also
exercise whole-image, body-hash and export-byte guards. `relations.py` changes
eight real operand bytes: ratio JBE to JB, late JBE to JB, AND to OR, XOR
immediate 1 to 0, request code 8 to 9, latest-record displacement 20 to 24,
seed 10.0 to 20.0, and caller JNE to JE. Each changes a selected relation before
the native instruction obligation rejects it. This avoids treating an unchanged
high-level formula plus a hash rejection as a semantic mutation control.

No target execution, target emulation, Rust compilation, normalized-byte match,
full helper equivalence, runtime reachability or full oracle reconstruction is
claimed. Exported context bytes are not completion credit. The 11-site incoming
census covers E8 and RIP-relative FF15/FF25 encodings in .text, qualified by full
owning-FDE Capstone decoding; arbitrary register/vtable dispatch is excluded.
