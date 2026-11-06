# Whole-body UTF-8 Boolean relation

This supplements the independently derived decoder contract. It proves only the
valid/invalid predicate needed by a future typed error projection. Error text,
allocation, exact inactive bytes and physical memory-access traces are excluded.
The complete body is `16815e0..16817d7` (503 bytes / 143 retained GNU rows), body
SHA256 `3ff2fdb7228f89579b15327cfe53871b0d275e0c54668dfeca9b349800836de0`.
The complete byte-class table `46ebe7..46ece7`, SHA256
`02b189407fa32e9604226dec547e4849ffaa560a3bf60c7e2cf4d48db5aa2f90`,
was independently bound to the captured target in `bind.stdout`. These are
ordinary static instruction/data observations, not evaluated target code.

Preconditions: readable stable span (base,len), nonwrapping address arithmetic,
valid disjoint output, and valid System V calling convention. Length and address
arithmetic must remain representable throughout the admitted source slice domain.
The body has no call instructions. Base+len and output lifetime are premises;
there is no allocator or external predicate inside this helper.

## ASCII invariant

RAX is output, RSI base, RDX length. RCX is the current lead-byte index. Empty
input branches directly to success at 16817a7. At 168162f, a nonnegative BL is
ASCII 00..7f and is consumed without changing the multibyte invariant.

The alignment prelude computes `r8 = (base+7)&~7 - base`, modulo ordinary pointer
arithmetic under the valid span premise. The low-three-bit test of r8-rcx at
1681637..1641 advances by individual ASCII bytes until alignment. Its use of a
32-bit intermediate does not alter low-three-bit alignment for long slices.
The bound RDI is max(len-15,0). The 16-byte loop reads two qwords only when
rcx<RDI, hence rcx+15<len, ORs them, and tests mask8080808080808080. A zero test
means every one of those 16 bytes is ASCII; advancing16 therefore preserves the
invariant. On a non-ASCII byte or near the end, the single-byte loop advances
only while bytes are nonnegative and rcx<len, and returns to the lead dispatcher
at the first negative byte. Thus vectorization changes neither accepted values
nor the first unvalidated position.

## Complete lead partition

The table read at1681690 has these exact maximal runs:

| Lead bytes | Table value |
|---|---:|
|00..7f|1 (already handled by ASCII branch)|
|80..c1|0|
|c2..df|2|
|e0..ef|3|
|f0..f4|4|
|f5..ff|0|

For negative leads, only 2,3,4 can continue. Table0 reaches rejection16817b8.
Consequently continuation bytes cannot start a scalar, C0/C1 cannot introduce an
overlong two-byte scalar, and F5..FF cannot introduce an out-of-range scalar.

For each continuation test below, signed `byte <= 0xbf` means precisely
80..bf: these are signed -128..-65. Signed `byte < 0xc0` has the same accepted
set. ASCII bytes are nonnegative and fail these tests; c0..ff are -64..-1 and
also fail. The source must not replace these signed predicates with unsigned
`byte <= 0xbf`, which would wrongly accept ASCII continuation bytes.

- Two-byte leads C2..DF: index+1 must exist (16816ae..16b5), then its byte must
  be80..bf (16816bb..16c2). The next current index becomes old index+2 via
  1681620. These encode exactly U+0080..U+07FF.
- Three-byte leads E0..EF: index+1 must exist. E0 uses `(second & e0)==a0`
  (1681729..1731), preciselya0..bf. ED uses signed second<=9f
  (16816f0..16f4), precisely80..9f. E1..EC are selected by low-byte
  `(lead+1f)<0c`; EE/EF by `(lead & fe)==ee` (1681744..1754), and these admit
  second80..bf. Index+2 must exist and be80..bf (168175c..176a). Next index
  becomes old+3. E0's restriction excludes overlong values below0800; ED's
  restriction excludes D800..DFFF surrogates; remaining cases cover0800..FFFF.
- Four-byte leads F0..F4: index+1 must exist. F0 checks unsigned
  `(second+70) mod256 <30` (1681738..1740), precisely90..bf. F4 uses signed
  second<=8f (168171e..1722), precisely80..8f. F1..F3 pass low-byte
  `(lead+0f)<=2` and the generic80..bf second-byte test (1681772..177e).
  Indices+2 and+3 must exist and each be80..bf (1681780..179d). Next index
  becomes old+4. F0 excludes values below10000; F4 excludes values above10FFFF.

Every missing required continuation enters16817b3; every inadmissible lead or
continuation enters16817b8/17bc/17a3. Those routes set output QWORD tag1 at
16817c9..17ce. A completed scalar advances by exactly its encoded length and
returns to the same current-index invariant. No branch skips an unchecked
non-ASCII byte. Finite input plus strictly positive successful advancement gives
termination within the admitted span domain.

## Result and caller relation

Exhaustion after complete scalars reaches16817a7, writes original base and len
to output+8/+16, sets ECX0, and stores output QWORD0 at16817ce. Any failure stores
QWORD1 instead. It additionally records the lead index and an optional error
length, but those details need not be exposed by the proposed safe decoder API.

The main decoder calls this exact target through RELATIVE slot64dfca8 at
17c4ed8. It tests DWORD tag exactly1 at17c4ede. Thus, under the stated span and
frame premises, that branch is precisely rejection by the canonical Unicode
scalar UTF-8 byte grammar above. The opposite branch is valid UTF-8. This is
enough to use a separately implemented standard UTF-8 validity test in a source
projection; it is not a claim that arbitrary library diagnostic details or
physical read strategies match this native helper.
