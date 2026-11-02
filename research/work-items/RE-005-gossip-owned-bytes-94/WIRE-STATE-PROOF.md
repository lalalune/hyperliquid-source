# Native length-delimited validated-byte relation

Target node94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The independently exported complete bodies are primary
`0x466dc10..0x466dcf4` (228 bytes / 68 rows), collection
`0x4589a30..0x4589b2b` (251 / 78), and validator
`0x157a200..0x157a3f7` (503 / 143). They total 982 bytes / 289 rows.
`NORMAL-DOMAIN.md` gives the precise ordinary-return allocation, copy, release,
valid-slice and separation premises. Those premises are part of this theorem.
No captured execution or instruction evaluator is used.

## Entry and established length dependency

The primary preserves its output pointer, passes its decoder state unchanged
to the collection helper, and supplies the address `0x466bbb0` in RDX. The
complete specialized collection body never reads that incoming RDX: it reads
the length, allocates and copies an entire byte span. It does not invoke the
supplied byte-decoder function per element. The new byte/bool reconstruction
is therefore context, not a required production callback or new byte credit.

Collection calls the complete existing u64 wrapper `0x466bd10`. Its established
theorem is credited as dependency context. With raw mode QWORD m, that wrapper
enables fixed charge 8 exactly when m's low DWORD equals 1. Overflow rejects
before storing; otherwise C+8 is stored before its unsigned limit comparison.
The wrapper then chooses its fast path when remaining>8, otherwise the consuming
little-endian Reader. Invalid FE/FF fast markers consume zero and use expected
code 2; the slow Reader consumes one and uses expected code 3. Short permitted
payloads consume their marker only and carry the additional missing count.
Success consumes 1/3/5/9 bytes and yields the exact unsigned length N. These
paths and their raw 0/2/3/18 status fields are existing evidence, not newly
reconstructed wrapper scope or copied PR #1365 code.

On any non-18 length status, collection copies that status and its established
active error fields. Primary also forwards the status and active fields without
calling the validator or releasing a byte buffer. Native copy instructions move
additional inactive bytes too; the safe projection does not read those bytes.
No payload charge, allocation or payload consumption occurs on this route.

## The payload mode and ordered counter stores

After length success, collection reads the *entire QWORD* at state+0 and skips
payload charging only if that full word is zero. This differs from the length
wrapper's low-DWORD-equals-1 test. In particular, raw m=2 or m=2^32 skips the
header charge but enables the payload charge. No original enum/configuration
validity follows from admitting those raw machine words.

For m!=0, it adds N to the counter left by length decoding. Carry rejects with
tag 2 before a payload counter store. Without carry it stores C+N, then admits
only when the stored value is <=limit. A failed limit comparison retains this
store. The full input cursor already reflects the successful length prefix.
For N=0 the same counter value is still stored; an observer must record this
store even though before and after values compare equal. With m's low DWORD 1,
there can be two stores: header charge then payload charge, including repeated
equal values when N=0. No later branch rolls either one back.

These tests run before looking at payload availability. A payload-budget error
therefore has tag 2, preserves all remaining payload bytes, and can precede a
would-be payload-shortage result. It does not allocate or validate bytes.

## Availability, allocation, copy and cursor

Collection subtracts N from remaining length and branches on unsigned borrow.
If too few bytes remain, it writes only tag 1 and returns. It does not write a
missing-count word, consume available payload bytes, allocate or release. Header
consumption and all admitted counter stores remain visible.

Otherwise N<=remaining<=isize::MAX. This proves the later signed-negative N
allocation branch unreachable in the admitted domain. For N=0, no allocation
call occurs; the selected destination is the nonnull dangling pointer 1. For
N>0, the actual selected allocator at `0x54c0780` receives (1,N) and must supply
the genuine disjoint allocation under the domain premise. Null allocation/error
dispatch is outside the ordinary-return premise and supplies no claimed OOM
result. Its exact 21-byte dispatch is nevertheless retained as evidence.

The real GLOB_DAT import `memcpy` at slot `0x576dfe0` receives destination,
original payload pointer and N. Only *after* it returns does collection store
pointer+N and remaining-N to the decoder state. It then writes native success
fields (capacity=N, allocated pointer, length=N) at output+8/+16/+24, tag 18 at
output+0, and returns the output pointer. Input bytes and unread suffix remain
unchanged. This is one copy of the complete payload, not per-byte callbacks.

## Validator's exact byte language and error fields

The complete 503-byte validator has no calls. Its only static data dependency
is the actual 256-byte width table at `0x2564a0..0x2565a0`, with file bytes,
read-only mapping and no overlapping write among all 80,300 actual RELA records
bound separately. The table classifies 00..7F as 1, C2..DF as 2, E0..EF as 3,
F0..F4 as 4, and all other bytes as 0.

ASCII bytes are accepted, including zero. The aligned fast path advances 16
only after two in-bounds 8-byte loads have no high bits. Its condition i<n-15
guarantees i+16<=n. The initial alignment calculation and low-three-bit test
select the same predicate at all eight addresses. A mixed block falls back to
individual ASCII-byte scanning. Thus the invariant is: i is in 0..n and every
byte before i belongs to complete accepted sequences. Fast scanning cannot
skip a non-ASCII byte, overread, or change an error position.

At a non-ASCII start i, the actual signed predicates give these next-byte
classes: continuation is 80..BF; E0 requires A0..BF; ED requires 80..9F; F0
requires 90..BF; F4 requires 80..8F. Remaining legal 3- and 4-byte leads use
80..BF. Later bytes require the same continuation class. These predicates
exclude overlong encodings, surrogate scalars and values above U+10FFFF.
C0/C1, isolated continuations and F5..FF are illegal first bytes.

A missing continuation returns error at the start i with option tag 0. An
available illegal continuation at offset j=1/2/3 returns error at i, option
tag 1 and error length j. An illegal leading byte returns error length 1.
Every successful sequence advances by its complete width, so all loops
terminate. These cases exhaust every byte class, length boundary and normal
return. The accepted language is strict UTF-8; this proves a byte property,
not an original String type or text normalization/display policy.

On success, the validator writes QWORD tag 0 and the input pointer/length.
On error, it writes QWORD tag 1, QWORD i at +8, option tag at +16 and an option
payload byte at +17. That payload is inactive and can be stale for option tag 0;
six other bytes of the 16-byte metadata span are not written by the validator.
Only (i, Option(error_length)) is in the safe error projection.

## Primary composition, release and dead niche route

After collection success, primary saves the genuine (capacity,pointer,length)
and invokes the actual validator through slot `0x576e3f8`. On validation success
it forwards that saved triple and writes raw success tag 18. On validation error
it saves the validator's 16-byte metadata span, conditionally requests release
of the allocated buffer with size=capacity and flags=0, then writes tag 6 and
that metadata span. The safe result exposes only its defined index/Option.

Capacity=N<=isize::MAX after genuine collection success. Therefore NEG(capacity)
cannot set overflow and the primary's special JO route requiring capacity=2^63
is unreachable here. This is a provenance proof, not an interpretation as a
borrowed/owned source variant. With capacity=0, the byte buffer is empty and the
validator must succeed; an ordinary validation error has N>0 and requests release
exactly once before error publication. Reader/counter state is not rolled back.
Validation therefore reports a payload error after the entire payload has been
consumed, while preserving the complete following suffix.

The exceptional landing pad at `0x466dcd6` retains its exact conditional release
and `_Unwind_Resume` import. No normal branch enters it. Unwind/fault behavior,
original allocation/TLS/cache state and ABI are excluded, with their raw evidence
and transitive gaps retained. The free helper's nonlocal tail `0x54c7550` is not
misrepresented as a closed 165-byte standalone deallocator.

The new value/state theorem is conditional exactly as `NORMAL-DOMAIN.md` states.
A separate independent grammar/wire authority must be sealed before new Rust;
finite comparisons corroborate this proof without executing captured instructions.
Full component gates, original compiler/machine bytes and caller/network grammar
remain unestablished.
