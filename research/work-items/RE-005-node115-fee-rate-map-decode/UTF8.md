# UTF-8 validity used by the decoder

The source needs only the Boolean validity relation of 0x16815e0..0x16817d7, not its diagnostic offset/length representation. The complete helper is503 bytes / 143 rows, body SHA256 `3ff2fdb7228f89579b15327cfe53871b0d275e0c54668dfeca9b349800836de0`. The256-byte table at 0x46ebe7..0x46ece7 has SHA256 `02b189407fa32e9604226dec547e4849ffaa560a3bf60c7e2cf4d48db5aa2f90`. Both are bound in [obligations.json](obligations.json).

This helper has no calls. The relation assumes a stable readable span, valid disjoint output and representable pointer/length arithmetic. No allocation or external predicate is inferred. Physical read strategies, error formatting and inactive bytes are outside the Boolean projection.

## ASCII advancement

RCX is the first unvalidated byte index. Empty input reaches success. At0x168162f, nonnegative BL means ASCII 00..7f and advances the index.

The alignment prelude uses the low-three-bit distance to an eight-byte boundary. Its32-bit intermediate preserves those three bits. The two-qword fast loop reads 16 bytes only when index<max(length−15,0), so the final byte read is still inside the span. It ORs both words and tests0x8080808080808080. A zero result proves all 16 bytes are ASCII and permits advancement by 16. A non-ASCII block or end-of-span condition returns to bounded single-byte scanning. No unchecked non-ASCII byte is skipped.

## Complete multibyte partition

The byte-class table has these exact runs:

| Lead byte | Width |
|---|---:|
|00..7f|1, handled by the ASCII branch|
|80..c1|0, invalid lead|
|c2..df|2|
|e0..ef|3|
|f0..f4|4|
|f5..ff|0, invalid lead|

For a negative lead, only widths 2,3,4 continue. Each required continuation must exist. Signed byte≤0xbf or signed byte<0xc0 admits precisely 80..bf; an unsigned comparison would incorrectly admit ASCII.

- C2..DF requires one continuation80..bf. This excludes overlong two-byte forms.
- E0 requires second byte a0..bf. ED requires 80..9f. E1..EC and EE..EF require 80..bf. All require a third byte80..bf. These rules exclude overlong three-byte forms and surrogate code points.
- F0 requires second byte 90..bf; F4 requires 80..8f; F1..F3 require 80..bf. All require third and fourth bytes80..bf. These exclude values belowU+10000 and aboveU+10FFFF.

The specific native restrictions are E0 at 0x1681729..0x1681731, ED at 0x16816f0..0x16816f4, F0 at 0x1681738..0x1681740 and F4 at 0x168171e..0x1681722. The F0 unsigned modular test (second+0x70) mod256<0x30 admits exactly90..bf. The generic continuation branches and table must be read together; byte-class width alone is insufficient.

Each completed scalar advances by its full encoded length and restores the first-unvalidated-index invariant. Missing or invalid continuation routes store failure tag 1; reaching the span end after complete scalars stores success tag 0 at 0x16817ce. Strictly positive advancement on every successful iteration terminates for finite valid spans. This proves the canonical Unicode-scalar UTF-8 Boolean grammar without executing the helper.

## Caller projection

The decoder calls this helper through RELATIVE slot0x64dfca8 at 0x17c4ed8 and tests the DWORD tag against1. The entire string payload has already been consumed. Valid text reaches an always-rejecting string visitor and becomes InvalidType. Invalid text also produces a diagnostic error and cleanup request, then the caller replaces it with category 7, exposed as InvalidUtf8.

A standard independently implemented UTF-8 validity test is therefore sufficient for this Boolean choice. The source does not claim identical first-error offsets, optional error lengths, message text, allocations, cleanup effects or read order. Required diagnostic and cleanup calls must return normally and preserve the active frame for the final native category 7 store. The validity helper's absence of calls does not remove those caller premises.

The [manual pre-source cases](manual-pre-source.json) include UTF-8 boundaries; the later [TSV projection](manual-cases.tsv) preserves their expectations. Finite cases support the implementation review but do not replace the whole-body invariant or its memory premises.
