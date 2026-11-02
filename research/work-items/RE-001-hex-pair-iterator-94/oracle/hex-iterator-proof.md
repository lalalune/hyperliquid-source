# Hex-pair953 and scalar140 independent pre-source normal-domain proof

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Primary complete FDE: ELF VA `0x4eb64f0..0x4eb68a9`, 953 bytes. Supporting
direct scalar decoder: `0x4eb6360..0x4eb63ec`, 140 bytes, with no calls. The
two denominators remain separate. Basis is the actual full-digest native
intake at `../hex-iterator-intake/`, including full raw rows, selected FDE/CIE,
load mappings and actual exceptional relocation/data records. The older
ASCII/outer-caller anchor does not supply this full relation. No Rust
implementation or original inferred/public parser source was read to author
this proof. No captured instruction evaluator or target execution is used.

## Admitted constructor and observation

The original immutable bytes encode one valid UTF-8 string of byte length L,
with valid allocation, L<=isize::MAX, no pointer wrap, and separated state,
output and string roles. Let S denote its start and E=S+L. The constructed
iterator starts with cursor P=S, end E, consumed count C=0 and halt H=0.
Only states reached by repeated normal calls on that construction are admitted;
arbitrary native field forgeries and external concurrent mutations are not.
Output is an independently supplied mutable 16-byte region, with arbitrary
initial bytes. Each normal call returns that same output identity. Native
addresses, nominal enum/struct layout, padding beyond the chosen16 bytes,
register clobbers, stack/return-PC and unwind/fault behavior are not asserted.

The logical observation is the complete16 output bytes, cursor offset P-S,
consumed count C, H and same-output identity. Byte order of all multi-byte
output writes is little-endian. Reusing output across calls preserves and
exposes the exact native write masks. The caller may provide any initial16
bytes; the mathematical authority varies those bytes independently of input.

## Character and whitespace relation

ASCII hex is exactly 0..9, A..F and a..f, mapping to 0..15. The unsigned8
subtract-and-range comparisons at `0x4eb6539..0x4eb6585` and their second
nibble/loop counterparts establish all three disjoint ranges. Upper/lower
forms subtract55/87; digits subtract48. Both the first and second nibble scans
skip exactly byte values9,10,13,32: the bits of immediate `0x100002600`.
ASCII vertical tab11, form feed12 and every other non-hex ASCII value are
invalid. Every non-ASCII scalar, including Unicode whitespace, is invalid.

The first nibble scan consumes accepted ASCII whitespace until a hex digit,
invalid scalar or end. Its whitespace loop is `0x4eb6638..0x4eb66ad`.
After a first digit, the second nibble scan independently consumes the same
whitespace set; its loop is `0x4eb66f1..0x4eb6767`. Skipping is therefore
allowed before, between and after a pair. There is no prefix stripping in this
953-byte leaf: `0x` consumes hex0 then reports invalid ASCII x at byte index1.
An outer caller's optional prefix handling is a separate operation and scope.

Each inspected byte increments the count by one before classification. On
recognized ASCII digit/whitespace, cursor advances to the byte after it.
When two digits are found, write DWORD tag2 at output[0..4] and one byte
`16*first+second` at output[4]. Bytes5..15 retain their prior values. H remains0,
including if the second digit is the final byte. The next call then finds end.

If no first digit exists before end, write DWORD tag3 only, retaining bytes4..15.
Cursor is end and C=L. H is unchanged, so natural exhaustion can remain H=0.
An initial empty string likewise returns tag3 with C=0 and H=0. If a first
digit exists but no second digit remains (possibly after whitespace), write
DWORD tag1 only, retain bytes4..15, set H=1, cursor=end and C=L. These cases
are respectively the paths through `0x4eb66af/0x4eb66b3` and
`0x4eb6769/0x4eb676d`.

For an invalid scalar starting at original byte index i, cursor becomes S+i+1
and C becomes i+1: exactly the first byte is consumed by this outer iterator.
The invalid scalar is separately decoded from original string boundary S+i by
the scalar140 helper. Set H=1 and write all16 output bytes: DWORD tag0 at0,
the scalar's u32 value at4, and u64 original byte index i at8. The scalar may
occupy2/3/4 UTF-8 bytes; the helper's temporary cursor is distinct from the outer
iterator cursor. A Unicode error therefore intentionally leaves the latter
inside that scalar. Future calls test H before touching cursor and write only
DWORD tag3. They preserve that same cursor/count and output bytes4..15. Odd
errors are similarly fused. The exact returning epilogue at `0x4eb66b9` moves
output address into RAX for every normal result.

## Supporting scalar140 theorem

The helper receives a temporary two-word cursor/end slice. Empty returns low
EAX0 without reading a byte; nonempty returns EAX1 and scalar in EDX, advancing
the temporary cursor by that scalar's UTF-8 width. Its admitted input is a
valid UTF-8 suffix at a scalar boundary. It does not validate arbitrary bytes.

For ASCII b0<128 it returns b0 after one byte. Valid2-byte leads C2..DF
take the `b0<=DF` arm and return `(b0&31)*64+(b1&63)`. Valid3-byte leads
E0..EF take the `b0<F0` arm and return
`(b0&31)*4096+(b1&63)*64+(b2&63)`; valid3-byte leads already have bit4 zero,
so the mask31 agrees with UTF-8's mask15. Valid4-byte leads F0..F4 return
`(b0&7)*262144+(b1&63)*4096+(b2&63)*64+(b3&63)`. The moves at
`0x4eb636d/0x4eb6385/0x4eb639f/0x4eb63bb` establish respective cursor
advances1/2/3/4. These positional formulas are exactly the UTF-8 scalar rule;
validity ensures enough continuation bytes, no overlongs/surrogates and a value
at most0x10FFFF. No further helper/data dependency exists in this140-byte body.
Only its nonempty valid suffix arm is reached by the outer error path.

## Induction and exceptional-route closure

While H=0 and before any error, all consumed bytes are ASCII hex/accepted
whitespace, P=S+C and 0<=C<=L. Every inspected byte exists because the loop
checks against E, and contributes exactly one to cursor/count. Therefore every
outer inspected position is a boundary in the original valid UTF-8 string:
before a first non-ASCII scalar, only complete ASCII bytes have been consumed.
The ASCII digit/whitespace steps preserve the invariant; successful pairs return
it, natural end yields C=L, and either error sets H=1. Halted calls return
before dereferencing the potentially interior cursor. This proves the finite
normal relation by induction over calls and consumed ASCII prefixes. Each
nonhalted scanning loop advances, so a finite string gives a finite call.

The three exceptional indirect routes have genuine actual mappings, but are
unreachable in this domain. Their behavior is therefore not invented:

* Count overflow at `0x4eb6882`, GOT0x576e118 ->0x157b480: inspected counts
  are bounded by L<=isize::MAX, so neither C==UINT64_MAX nor a loop's
  pre-two-increment count==UINT64_MAX-1 can hold. The subtraction-based
  original-start reconstruction P-C equals S under the invariant.
* String slicing boundary failure at `0x4eb6893`, GOT0x576e070 ->0x15793d0:
  every error index i satisfies0<=i<L and is a scalar boundary. At i>0 the
  signed8 test against0xBF rejects continuation bytes80..BF; a valid boundary
  byte is ASCII or C2..F4, so this rejection never triggers. Index0 is already
  a valid boundary. The native out-of-range branches cannot trigger either.
* Missing scalar at `0x4eb6875`, GOT0x576e470 ->0x157a9f0: i<L, so the valid
  suffix is nonempty and scalar140 returns EAX1; the None assertion is dead.

The actual three source-location data records are24 bytes each at0x5750a78,
0x5750a90,0x5750aa8, with actual symbol-zero RELATIVE source-path bindings.
Observed enumerate.rs/rustc-hex path and line labels are supporting provenance,
not permission to copy source or substitutes for the instruction proof. Panic
semantics, forged-state behavior and invalid UTF-8 are outside the claim.

## Pre-source mathematical authority

The independent oracle classifies high-level Unicode scalar strings using the
three explicit ASCII digit sets and four whitespace values. Its expected error
scalar is Python ord, not a native/helper instruction evaluator; a separate
serializer emits raw UTF-8 for the input-only Rust client. Expected full16-byte
write masks and cursor/count/halt states are computed from the relation above.
No expected event roles, codepoints, byte plans or outputs enter that client.
The corpus supports this complete mathematical/native proof and is not a
claim that finitely many vectors prove all strings. New code/proofs use MIT;
no unlicensed inferred implementation is copied. No gate or rebuilt byte
identity is advanced. Accepted #339 is an outer/ASCII anchor; related open
#1334 supplies outer ASCII20-byte acceptance and explicitly excludes Unicode,
full iterator state and helper closure. Root reviewed that boundary and assigned
this distinct953+140 stateful relation; no duplicate outer ASCII API or nibble
case split is proposed. Source may begin only after this independent authority
and normal helper-closure proof are frozen.
