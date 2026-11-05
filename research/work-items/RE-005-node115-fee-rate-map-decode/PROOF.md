# Conditional decoder relation

All addresses are ELF virtual addresses in the exact node #115 image identified by [README.md](README.md). This proof concerns the concrete15-byte `FeeRateMapSerde` wrapper and an initially fresh reader. It composes actual branches and active fields; it does not infer a general decoder from the encoder or a symbol name.

## Evidence and premises

The complete31 retained bodies total 8,850 bytes /2,192 instruction rows. The principal bodies are:

| Role | Complete FDE interval | Bytes |
|---|---|---:|
| Concrete wrapper | 0x27667a0..0x2766800 |96|
| Ordinary decoder | 0x17c4630..0x17c550e |3,806|
| Numeric element reader | 0x3423120..0x34233b4 |660|
| Binary first-four visitor | 0x17fb170..0x17fb284 |276|
| Top-level scalar rejection dispatcher | 0x344c690..0x344c95b |715|
| UTF-8 predicate | 0x16815e0..0x16817d7 |503|

The other 25 complete bodies comprise the ordinary rejection visitors, error construction/drop and formatting adapters bound in [obligations.json](obligations.json). Their retained bytes do not close every transitive formatter, allocator, panic or cleanup callee. Full FDE/CIE bytes authenticate boundaries and context; they are not evaluated as unwind programs.

The complete FDE intervals in the table have exclusive ends. Smaller instruction-site ranges below identify the relevant branch/store sequences rather than claiming additional function extents.

Native correspondence requires stable readable input and valid, disjoint writable reader/result/frame storage, with representable nonwrapping address/length arithmetic. Required opaque calls must return normally, honor their declared output/copy spans and preserve active input/reader/frame values outside those outputs. ABI register preservation alone is insufficient to establish this memory premise. Numeric controls are as specified in [FLOATING-POINT.md](FLOATING-POINT.md). These assumptions do not establish a live machine configuration or termination through exceptional paths.

Reader offsets observed here are pointer+0x10, remaining+0x18, normalized cache category+0x20, cache payload+0x21 and u16 depth+0x22. They are roles, not recovered source type names. Category1 means no cached marker. Arbitrary cache bytes are outside scope: the indexed dispatch contains invalid/UD2 entries. The wrapper's15-byte name excludes the length 10 `_ExtStruct` route.

The wrapper compares its child's DWORD tag to1 at 0x27667be and writes canonical QWORD1 for that case,0 otherwise. Actual ordinary children supply0/1. It copies 32 payload bytes, including inactive error storage. The source exposes only the selected typed observations and does not read those inactive bytes as values.

## Complete ordinary top-marker partition

Fresh marker processing clears category to 1 before marker EOF or consumption at 0x17c4663..0x17c4691. Empty input yields MarkerEof without changing depth. There is no final exhaustion check.

| Raw marker | Ordinary operation after marker consumption |
|---|---|
|00..7f,e0..ff|Immediate scalar; rejecting outer visitor|
|c0,c2,c3|Nil/boolean; rejecting outer visitor|
|c1|UnexpectedMarker(c1), without payload|
|ca,cb,cc..d3|Read fixed numeric payload, then rejecting outer visitor|
|80..8f,de,df|Map count, depth guard, rejecting map visitor|
|90..9f,dc,dd|Array count, depth guard, up to four numeric elements|
|a0..bf,d9,da,db|String length, complete payload, UTF-8 predicate, rejection|
|c4,c5,c6|Binary length, complete payload, first-four-byte visitor|
|c7,c8,c9,d4..d8|Extension length, depth guard, rejecting visitor|

The ordinary table at 0x49e228, extension table, numeric/top-scalar tables and error-drop table are bound as actual data. The alternate `_ExtStruct` table remains retained context but contributes no ordinary-path claim.

A missing marker gives MarkerEof. A short fixed-width numeric or length read advances to the end of all available bytes and gives TruncatedRead. After a complete binary/string length, an insufficient payload instead remains wholly unread: the header was already consumed, and the native result is category 1 with direct word0x2500000003. The chosen projection names this PayloadTooShort. A length check is not permission to drain a declared payload on failure.

Top-level numeric, nil and boolean inputs never produce a FeeRateMap value under the selected visitors. Their successful scalar parsing ends in a coarse InvalidType observation. Formatting may itself perform floating-point work; those diagnostics and flags are excluded.

## Arrays and depth

After a complete array header,0x17c484a..0x17c4864 tests depth before decrement. Zero reaches a panic-call boundary; one is stored as zero and returns category 8/DepthLimit. A safe PanicBoundary(Array) replaces the call only as an explicit host policy, with state observed before the call. A truncated header can return TruncatedRead before this boundary even when depth is zero.

For initial D≥2, depth D−1 is stored before element reads. Four unrolled sites at 0x17c4feb,0x17c5143,0x17c5207 and0x17c535a call the same numeric reader through slot0x64e2228. Success requires its byte tag 9. Accepted element forms are fixpos/fixneg, unsigned8/16/32/64, signed8/16/32/64, float32 and float64, with big-endian multibyte payloads.

For declared count N<4, exactly N successful elements are read before the formatted InvalidLength(N) request. An element failure takes precedence and stops immediately. Missing element markers give MarkerEof; truncated numeric payloads drain the suffix; unsupported element kinds give UnexpectedMarker of the normalized category without consuming their nested payload; nil/bool give InvalidType. These paths retain depth D−1. A normalized category is not always the original raw marker byte.

Only after four successful values does0x17c53c3 compare the declared count with4. Equality returns the four words in order. Greater counts return category 4 with active expected-count word 4, exposed as ExcessElements. No fifth element is read, skipped, validated or dropped. Both outcomes restore depth D at 0x17c542e..0x17c543b. Failure while reading the fourth element instead retains D−1.

## Maps and extensions

Map depth is guarded/decremented at 0x17c47ce..0x17c47e8. The complete 0x2655240 visitor always writes error tag 1 after its diagnostic constructor returns, without reading entries. Its generic success arm in the caller is therefore unreachable under the stated visitor/frame premise. The projection is InvalidType with depth D−1 for D≥2; map count zero does not imply success.

Ordinary extension length headers are consumed before0x17c4bc9..0x17c4be3 checks depth. The complete 0x2643600 visitor rejects without reading the extension type or payload. At D≥2, the caller restores depth at 0x17c4c95..0x17c4ca6 after the normal visitor return. Thus even a missing type byte need not cause an EOF result on this selected path. Depth0 and1 follow their respective boundary/DepthLimit rules. Behavior from the excluded `_ExtStruct` route must not be substituted here.

## Binary and strings

The binary path at 0x17c49bd..0x17c49f0 advances over the whole declared payload and constructs (start,end,counter=0) before the visitor. Length 0..3 produces exactly that InvalidLength after full payload consumption. For length ≥4, 0x17fb1e6..0x17fb217 converts bytes 0..3 as unsigned values to binary64 and stores result tag 0. It does not require the fourth byte to meet the endpoint. Initial counter 0 and valid nonnull/nonwrapping spans exclude the visitor's checked counter-overflow and null-sentinel ambiguity. No depth field is used.

The complete string payload is consumed before UTF-8 validation at 0x17c4ebd..0x17c4ed8. [UTF8.md](UTF8.md) proves the Boolean grammar from the complete helper/table. Valid strings reach an always-rejecting visitor and InvalidType. Invalid strings also construct an error, request its cleanup, and then replace it with native category 7 at 0x17c4f04..0x17c4f48. InvalidUtf8 exposes neither the native offset/length details nor any inactive bytes. The nominal successful byte-visitor arm is unreachable for these selected visitors under ordinary returns.

Error constructors and cleanup requests do not prove that memory was reclaimed, how diagnostic strings were rendered, or that an exceptional callback returns. The source need not reproduce those effects to implement the explicitly narrower projection.

## Manual counterexamples and scope

These deductions explain behavior; they are not additional executed tests:

- `c4 05 01 02 03 ff 99`, depth 0: [1,2,3,255], consumed7, unchanged depth.
- `94 01 02 03 04 ff`, depth 2: value, consumed5, restored depth 2, trailingff unread.
- `95 01 02 03 04 05`, depth 2: ExcessElements after consumed5, depth 2, final05 unread.
- `93 01 02 03 04`, depth 2: InvalidLength(3), consumed4, depth 1.
- `c7 04`, depth 2: InvalidType after consumed2, depth 2, despite absent type/payload.
- `c4 04 01 02`: PayloadTooShort after its two-byte header, leaving01 02 unread.
- `dc`, depth 0: TruncatedRead before an array depth guard.

The925 manual JSON cases and 62 scalar JSON witnesses were frozen before source. Later TSV projection is separately dated; it does not acquire pre-source provenance by preserving expectations. Finite tests cannot prove this complete branch argument, caller frame premises or all native effects. No generic cached-state, diagnostic, ABI, fee integration, accepted gate or whole-ELF claim follows.
