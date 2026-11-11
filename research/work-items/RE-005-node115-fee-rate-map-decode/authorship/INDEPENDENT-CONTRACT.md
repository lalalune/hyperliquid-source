# Independent conditional FeeRateMapSerde decoder review

Target: Linux x86-64 node115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105896032 bytes. This is a manual static derivation, not execution, simulation,
an instruction interpreter, a native oracle or source admission. Addresses are ELF VAs.

## Evidence and independence

I read the complete wrapper `27667a0..2766800`, main decoder
`17c4630..17c550e`, scalar decoder `3423120..34233b4`, binary visitor
`17fb170..17fb284`, outer scalar rejection dispatcher `344c690..344c95b`,
UTF-8 validator `16815e0..16817d7`, all retained ordinary rejection leaves,
both retained error constructors, drop dispatcher and diagnostic format adapters.
The four encoder leads 2764f60, 2765730, 28b5d90 and 28b64a0 are excluded.
The resulting 31-body set is 8850 bytes / 2192 GNU rows. `bind.stdout`
binds every row to independently parsed unique PT_LOAD and allocated section
mapping, each complete body hash, FDE/CIE raw bytes and pcrel extent, 74 CALLs,
the relocated drop tail, 16 data spans and 17 selected relocations. All 61001
RELA entries were inspected for overlap; selected bodies and data have none.
No full unwind/LSDA semantics is inferred from the FDE check.

The metadata audit is independently authored stdlib parsing; the disassembler
exports and captured artifact are shared with the installer scout. This is one
target-source lineage and one GNU decode, not two independent organizations or
two independent native decoders. The first audit compared CALL count to a list
that included one tail-jump. Its unchanged failure, script and raw streams are
retained in `history-01`; `CORRECTION.json` explains the bounded correction.

## Admitted ordinary relation

The concrete wrapper supplies the 15 bytes `FeeRateMapSerde` at 5f70d5. The
length-10 `_ExtStruct` route at 17c4640..4661 is therefore unreachable from this
wrapper. Its bytes remain retained; its alternate type/payload behavior must not
be transferred to the ordinary path.

Use a readable, stable, nonwrapping input span and a disjoint writable reader
and result. Reader fields are pointer +0x10, remaining +0x18, normalized cache
category +0x20, cache payload +0x21 and depth u16 +0x22. The simplest complete
future source domain starts with category 1, meaning no cached marker. This
does not prove an arbitrary raw cache byte is valid: the 225-entry table at
49e228 has UD2 entries and no local protection for every possible cached byte.
The selected routines do not define the reader constructor. A later cached-mode
API needs its own explicit normalized-tag/payload domain and provenance.

Ordinary correspondence requires required allocation/formatting/drop calls to
return normally and preserve the input, reader, result and active stack values
outside their declared outputs. This is a genuine frame premise even when a
callee is not passed the reader directly. No concurrent mutation or aliasing is
admitted. Calling convention preservation alone does not prove that premise.
Diagnostic strings, allocations and native ownership are opaque. Unwinding,
abort, allocation refusal, panic targets, physical ABI equivalence and total
termination are not established. A safe source refusal is a separate host policy.

At 27667be the wrapper compares the temporary DWORD tag to exactly 1; it writes
canonical QWORD 1 for that case and 0 otherwise. The actual ordinary children
produce tags 0/1. It copies all 32 payload bytes, but many error bytes are
inactive/uninitialized. Only defined active error fields may be exposed. There
is no trailing-input/exhaustion check.

## Complete ordinary marker partition

With fresh category 1, 17c4677..4691 consumes one marker unless input is empty.
The cache category is set to 1 before either outcome. Empty input returns error
category 0 with descriptor 641ccb0; no bytes or depth are consumed.

| Raw marker | Operation after consuming marker | Ordinary result and remaining state |
|---|---|---|
| 00..7f, e0..ff | Immediate unsigned/signed scalar, outer dispatcher 344c690 | Always rejection after its matching visitor returns; no further bytes or depth change |
| c0,c2,c3 | Nil/boolean outer scalar visitor | Always rejection; depth unchanged |
| c1 | Direct reserved-marker store at 17c4958 | Error category 2, marker c1; no payload read |
| ca,cb,cc..d3 | Read fixed scalar payload then outer scalar visitor | Always rejection on ordinary completion; a short payload drains available bytes and returns category 1, descriptor 64622f0 |
| 80..8f,de,df | Map count (inline/u16BE/u32BE), then depth and map visitor | All maps reject without consuming any entries; depth behavior below |
| 90..9f,dc,dd | Array count (inline/u16BE/u32BE), then depth and up to four numeric values | Exact count four plus four successful numeric values succeeds; other cases below |
| a0..bf,d9,da,db | String length (inline/u8/u16BE/u32BE), then payload and UTF-8 check | Never a successful FeeRateMapSerde value; valid text gives formatted category 6; invalid text gives category 7 after error cleanup |
| c4,c5,c6 | Binary length u8/u16BE/u32BE, then whole borrowed payload | Length >=4 succeeds using its first four bytes; length 0..3 gives formatted length rejection |
| c7,c8,c9,d4..d8 | Extension length (u8/u16BE/u32BE or fixed 1/2/4/8/16), then depth and extension visitor | Always rejection; does not read extension type or payload |

Both ordinary dispatch tables, both scalar tables and the drop table are bound
in `bind.stdout`; no marker class was inferred from a library name.

A short 2- or 4-byte length field consumes all available prefix bytes and sets
remaining to zero (17c4a39..4a40 and 17c4af1..4af8). A missing 1-byte length has
zero bytes available, so the cursor is already unchanged/end. Both give category
1 with 641ccb0. Once a complete binary/string length has been read, an
insufficient payload instead leaves those payload bytes untouched and returns
category 1 with the immediate word 0x2500000003 (17c49bd..49c2,
17c4b63..4b83). The length field has already been consumed.

## Arrays, errors and depth

Array/map/extension entry depth is checked before decrement. Depth 0 calls
1681e40 through slot 64df848; its termination/return behavior is not closed, so
this is not a normal parser-error return claim. Depth 1 is stored as zero and
returns category 8 without visiting any element/type/payload. Non-container
branches, including binary, need no positive depth.

For arrays with depth D>=2, the count header is consumed, then depth D-1 is
stored. The four unrolled value reads at 17c4feb/5143/5207/535a call the same
3423120 target through 64e2228. Short count N=0,1,2,3 reads exactly N successful
numeric values and calls 17fbb40 with that count. It does not read an N+1st
marker. An error within those N values takes precedence over short-count error.
Every such short-count/element error leaves depth D-1, not D.

After four successful numeric values, 17c53c3 compares the declared count to
four. Equality returns the four values in order. A larger count gives category
4 with active u32 count 4 at result +0x0c (17c5417..5424). It does not consume,
skip, validate or drop the extra serialized elements. Both these branches
restore depth to D at 17c542e..543b. A malformed fourth value leaves D-1 instead.

Absent element marker gives category 0/641ccb0. Truncated numeric payload
drains all its available bytes and gives category 1/64622f0. Unsupported
element marker gives category 2 with normalized category and immediate data;
its payload/length is not read. Nil/bool elements construct category 6 errors.
No further element is examined after any error.

The complete 2655240 map visitor unconditionally stores result tag 1 after
18be120. Consequently the map path never reaches the successful visitor branch
17c4f4d under the frame premise: entries remain unread and depth stays D-1.
The complete 2643600 extension visitor likewise stores tag 1 without using its
reader/count argument. However its caller 17c4c95..4ca6 restores D even on this
error. In the ordinary extension route, even a missing type byte is not checked;
only the variable-length header, if any, has been consumed.

## Binary and string routes

17c49c8..49dd advances over the complete declared binary payload and constructs
the iterator (start,end,counter=0), before calling 17fb170. The visitor compares
the endpoint at lengths 0,1,2,3 and reports exactly that length via 17fbb40. For
length >=4, 17fb1e6..212 separately zero-extends bytes 0,1,2,3 and applies four
integer-to-f64 conversions. These values are exactly representable. It stores
four binary64s and result tag 0. It has no requirement that byte 4 equal end.
The internal counter-overflow branches compare supplied counter to negative
sentinels; the actual constructed zero counter excludes them. Valid nonnull,
nonwrapping span premises exclude the visitor's null-pointer sentinel ambiguity.

String payload advancement occurs before UTF-8 validation (17c4ebd..4ed8).
I read the complete UTF-8 validator and its bound 256-byte class table: ASCII
fast paths, 2/3/4-byte continuation checks, E0/ED/F0/F4 restrictions, first-error
index and truncated-sequence option. The string visitor 265d560 always rejects.
For invalid UTF-8, 26350d0 also always rejects. Its formatted error is discarded
via 189f500 and replaced by category 7 carrying the validator's active
valid-up-to index and optional error length (17c4f04..4f48). The nominal success
arm 17c5070 is unreachable for this concrete visitor under the frame premise.
No allocator/drop side-effect equivalence is claimed.

## Numeric values and explicit FP obligations

3423120 accepts normalized fixpos/fixneg, u8/u16/u32/u64, i8/i16/i32/i64,
float32 and float64. Multi-byte payloads are big endian. Every successful result
has byte tag 9 and the binary64 bits at +8. Other element kinds reject as above.

Signed/unsigned 8/16/32-bit integers convert exactly. Signed i64 uses CVTSI2SD
(342333b), requiring an explicit MXCSR rounding premise for non-exact values.
For u64, PUNPCKLDQ at 3423364 constructs two binary64 values with exponent words
43300000 and 45300000. Subtracting exact biases [2^52,2^84] at 3423370 yields
low32 and high32*2^32 exactly; ADDSD at 3423380 performs the final rounding.
Under RN-even, u64::MAX therefore rounds to 2^64, not a saturated integer value.
No native numeric range/finite-value filter exists on these success paths.

Float64 at 342328a..32b5 is an integer byte swap and raw store: zeros, infinities,
quiet/signaling NaN payload bits are copied without FP conversion at this step.
Float32 uses CVTSS2SD at 342316c, then explicitly restores input sign. NOT(bits)
>>31 chooses [-1,+1] at 456510; mask4559c0 keeps that sign and mask450180 clears
the converted sign before OR. Under DAZ=0, all finite binary32 values widen
exactly (including subnormals and signed zero). Exact signaling-NaN quieting,
payload propagation, exception masking and MXCSR behavior need the separate
ISA proof before an all-bit portable source theorem; this review does not
replace that proof with host casts. Formatting a rejected top-level float can
also execute FP work in its visitor/opaque formatter.

## Hand-reasoned counterexamples, not executed fixtures

- `c4 05 01 02 03 ff 99`, D=0: success [1,2,3,255], consumes all 7 bytes.
  This refutes exact-four binary length and raw-four-f64 interpretations.
- `94 01 02 03 04 ff`, D=2: success [1,2,3,4], consumes 5, leaves ff, restores D=2.
- `95 01 02 03 04 05`, D=2: category 4/count4, consumes 5, leaves 05, restores D=2.
- `93 01 02 03 04`, D=2: formatted short-length3, consumes 4, leaves 04, depth1.
- `94 01 c1 03 04`, D=2: category2/c1 after three total bytes, depth1.
- `80`, D=2: formatted map rejection after one byte, depth1; no empty-map success.
- `c7 04`, D=2: formatted extension rejection after two bytes, depth2 despite
  absent extension type/payload. `_ExtStruct` behavior would predict differently.
- `c4 04 01 02`: category1/0x2500000003 after the two-byte header; 01 02 remain.
- `94 cd 01`, D=2: numeric short-payload category1/64622f0 after all bytes, depth1.
- `a1 ff`: full string payload consumed; category7 with index0, error-length1,
  provided diagnostic construction and cleanup return normally.

## Novelty and remaining admission work

The existing fee-rate-map-wire packet/encoder explicitly leaves decoding open;
this is a new composed operation rather than its inverse. Preserve that prior
credit and its separate APIs. Shared UTF-8/drop/error routines are dependencies,
not newly discovered coverage. Saved PR3300/3302/3305 concern other Action/enum
dispatchers; protect their ownership, cite shared dependencies, and do not import
or execute their captured-instruction interpreters. The saved old PR2355 reads
returned 404, so prior attribution is from the local packet/history, not a live
merge readback. No complete current ownership clearance is supplied by this review.

Before implementation: settle precise fresh-reader/ordinary-output host API,
invalid depth/cache admission, all-bit FP semantics and diagnostic projection;
pin all consumed data/slots in the public static contract; freeze an independent
oracle/corpus only after those choices. A full decoder claim must include every
ordinary marker family, truncation and residual-state rule above. It must exclude
alternate `_ExtStruct`, malformed raw reader states, diagnostic rendering,
allocation/unwind and full fee/storage/whole-node equivalence explicitly.

## EXPAND

1. Complete the separate x86 FP/MXCSR proof, especially sNaN payload/quieting and
   portable bit construction, without evaluating captured instructions.
2. Root should freeze a typed active-field error/state projection and exact fresh
   reader domain, then independently derive boundary expectations.
3. Refresh bounded current ownership before admission/publication; existing saved
   100-open screen and three related path lists are not global absence evidence.
4. Dead ends retained: four encoder leads duplicate existing work; arbitrary
   cached states and exact diagnostic/allocator behavior remain outside closure.
