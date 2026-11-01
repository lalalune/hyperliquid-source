# Independent complete validator normal-state proof

This is private pre-source mathematical analysis of the complete no-call body
`0x157a200..0x157a3f7` (503 bytes / 143 GNU rows), reached by the complete
gossip helper `0x466dc10..0x466dcf4`. It is bound with the independently generated corpus by FREEZE.json.
No new Rust, repository implementation module or instruction evaluator was read
or executed. Native bytes/listings and FDE/CIE are in the authenticated source
peer handoff. The validator's actual 256-byte table at `0x2564a0` is bound by
`DATA-AND-IMPORTS.json` SHA3e978b618386c5b7d886d34a658260dc133e32e3a089c5d6aa727b2f51a3a5f9.
Its raw SHA is02b189407fa32e9604226dec547e4849ffaa560a3bf60c7e2cf4d48db5aa2f90;
all256 classifications were independently compared to the equations below.

## Normal domain and chosen observable projection

The input is an immutable readable nonwrapping byte slice of length at most
`isize::MAX`, with separated writable output. For nonempty input, alignment
round-up `p+7` does not overflow. Ordinary finite returns are considered;
faults, aliases, concurrent mutation, unwind and native output padding are
excluded. The chosen result is success or `(valid_up_to, error_len)` where
`error_len` is an optional 1..3 integer. It does not assign original Rust types.

## ASCII progress and bounds

`0x157a20a..215` computes `q=max(n-15,0)` and immediately accepts empty input.
`0x157a21e..226` computes `a=((-p) mod 8)`, in 0..7. The scan index starts at
zero. At `0x157a24f` an ASCII byte first advances bytewise until `(a-i) mod8=0`.
The two-qword bulk read at `0x157a279..285` occurs only while `i<q`; therefore
all 16 read bytes are within `[0,n)`. The OR/high-bit test is zero exactly when
all 16 bytes are ASCII. Only that case increments `i` by 16. If a block has a
high-bit byte, the scalar scan at `0x157a290..29c` locates its first such byte.
Neither scan can skip a non-ASCII byte. Every scalar access is guarded by an
index bound. Thus the loop is equivalent, for every pointer residue modulo8,
to advancing across the maximal initial run of ASCII bytes.

## Non-ASCII branch equations

Let `i` be the first not-yet-validated byte. A table lookup selects width2/3/4
or a rejecting default. The actual table gives width2 for C2..DF, width3 for
E0..EF, width4 for F0..F4, and rejection for other high bytes. ASCII entries
are1 but never used by the non-ASCII branch.

Every continuation comparison is signed-byte arithmetic. Signed `x<=BF`
(`0x157a2db`, `385`, `3a9`) is exactly unsigned `80<=x<=BF`. Signed `x<C0`
(`0x157a376`, `39a`, `3b8`) has that same byte domain.

- Width2 (`0x157a2ce..2e8`) requires one continuation. Its absence returns an
  incomplete suffix; its invalidity returns error length1. Success advances2.
- Width3 (`0x157a2ed..316`, `349..353`, `364..390`) restricts E0's second byte
  to A0..BF by `(x & E0)==A0`, ED's to80..9F by signed `x<=9F`, and other
  admitted leads to80..BF. The third byte must be80..BF. Invalid second/third
  bytes yield error lengths1/2; an absent required byte yields incomplete.
- Width4 (`0x157a31b..344`, `358..362`, `392..3c5`) restricts F0's second byte
  to90..BF via `((x+70) mod256)<30`, F4's to80..8F via signed `x<=8F`, and
  F1..F3's to80..BF. Third and fourth bytes must be80..BF. Invalid required
  bytes yield lengths1/2/3; an absent required byte yields incomplete.

The width3/4 extra lead predicates also exactly admit E1..EC/EE..EF and
F1..F3. All successful scalar forms are precisely shortest UTF-8 encodings
of Unicode scalar values: no surrogate, overlong form or value above10FFFF
is admitted. NUL and noncharacters are admitted; no normalization is observed.

`0x157a3c7..3d1` returns success after all bytes validate. On failure,
`0x157a3de..3ee` stores the scalar's starting offset `i`, the presence byte,
and a length byte meaningful only when presence is1; an incomplete suffix
sets presence0 at `0x157a3d3`. The stored incomplete length byte is inactive
and must not enter the chosen logical projection or expected records.

## Composition observations, not closed allocation theorem

The vector stage first calls actual u64 wrapper `0x466bd10`. Its own
`0x4589a5c` compares the full mode QWORD against zero, unlike the prefix
wrapper's literal low-DWORD1 test. After prefix success with decoded lengthN,
nonzero QWORD mode adds N to the post-prefix counter; overflow rejects before
store, otherwise the sum is stored before testing `sum<=limit`. This store
occurs even for N=0. Payload shortage then returns raw tag1 without consuming
payload. On the admitted allocation/copy path, exactlyN bytes are copied and
only then are input pointer/remaining updated (`0x4589aff..b06`).

Primary validates the whole copied vector. Validation failure therefore
retains full prefix+payload consumption and all prior charges. For capacityN
in0..isize::MAX the NEG overflow branch is unreachable. Capacity0 skips
release; nonzero capacity calls the actual release entry before writing tag6
and the logical validator error. Success returns tag18 and the owned triple.
The supplied `0x466bbb0` element-decoder address is not used by the actual
specialized vector body; it is not an executed element loop or helper claim.

Allocator/copy/release behavior remains a separate explicit functional premise
under the root-qualified NORMAL-DOMAIN.md; its transitive internals are not closed. This draft claims no
whole gossip response, original owned-string ABI or full allocation/runtime
equivalence.

## Active-field boundary

Native error bytes +16/+17 encode presence/payload. With absence, the payload
byte is still written but can be stale BL, including EE/EF and F1..F3 lead-path
values. The following six copied bytes are unwritten padding. The mathematical
Option projection excludes that inactive byte and all padding; it does not
claim an equality over all raw native result memory. Successful observations
retain the complete original input bytes as validated_hex.
