# Fresh-reader FeeRateMapSerde prefix projection, pre-source contract v1

This is a proposed safe source API for the complete ordinary operation under
node115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
It extends the existing encoder component; it does not redefine that encoder,
fee units, fee-state integration or native ABI. Root owns source admission.
No decoder source, reference parser or native execution produced these fixtures.

## Library relation

`decode_prefix(input: &[u8], depth: u16) -> Observation` starts a fresh reader
(native normalized category1). `Observation` contains `consumed: usize`,
`depth_after: u16`, `cache: Fresh`, and one of:

- `Value([u64; 4])`: the four output binary64 bit patterns, in observed order.
- `Error(DecodeError)`: one of the active-field projections below.
- `PanicBoundary(ContainerKind)`: Array, Map or Extension, with the state at
  the native depth-zero call site. This is a chosen safe-host refusal. It is
  explicitly **not** a returned native parser error or native unwind/termination
  equivalence. Non-container routes at depth0 are still processed.

| DecodeError | Observed native projection |
|---|---|
| MarkerEof | category0 on absent top/element marker |
| TruncatedRead | category1 for a short fixed-width numeric or length header |
| PayloadTooShort | category1 with direct word2500000003 after a complete binary/string length |
| UnexpectedMarker(u8) | category2; normalized marker category only |
| InvalidLength(u8) | formatted invalid-length request with actual count0..3 |
| ExcessElements | category4 with active expected-count word4 |
| InvalidType | coarse formatted invalid-type request; no diagnostic message/payload |
| InvalidUtf8 | category7 after the rejecting byte visitor and cleanup request |
| DepthLimit | category8 after depth1 is stored as0 |

These are intentionally typed observations, not a copied native result layout.
UnexpectedMarker never exposes the inactive marker-data word. InvalidUtf8 does
not expose error offset/length/padding. InvalidType/InvalidLength do not render
messages, allocate diagnostic strings or reproduce disposal side effects.
No cache payload is observed. `cache: Fresh` denotes native +0x20=1 at the
observed ordinary return or depth-zero call boundary, not a byte-for-byte reader.

Every finite input slice and every u16 depth has a source observation. There is
no library-level maximum byte count beyond valid Rust slices, no numeric
finite/range restriction, no generic depth0 rejection and no end-of-input
requirement. Driver limits/resource errors belong to a separately admitted
transport contract; they must not become native decode errors.

## Conditional native correspondence and state rules

Source correspondence concerns the concrete wrapper27667a0 passing the exact
15-byte name to17c4630; `_ExtStruct` and arbitrary cached/raw reader states are
excluded. Input/reader/result/frame spans are valid, stable, nonwrapping and
disjoint. Opaque formatter/allocation/drop callbacks return normally, preserve
the active reader/input/frame outside declared outputs, and do not change the
admitted FP environment. Allocation failure, diagnostic rendering, physical
ownership, panic behavior and unwind remain unproved. Source returns safe
PanicBoundary at the corresponding call site instead of invoking that callback.

The independent native contract is
`SESSION/cycles/wave24/artifacts/next-fee-scout/peer/INDEPENDENT-CONTRACT.md`
(use the exact path/SHA pin in FREEZE.json), with the whole-body UTF8-PREDICATE
supplement. Main source sites are:

- marker consumption/cache reset17c4663..4691;
- map depth17c47ce..47e2 and unconditional rejection2655240;
- array depth17c484a..485e, value calls17c4feb/5143/5207/535a,
  short-count requests17c4f8e/50d6/51ba/5305 and exact-four check17c53c3;
- successful-four/excess restoration17c542e..543b;
- length truncation17c4a39..4a54, payload insufficiency17c4b63..4b83;
- binary whole-payload advance17c49bd..49f0 and first-four visitor17fb170;
- string advance17c4ebd..4ed8, full UTF8 predicate16815e0,
  rejection/override17c4ede..4f48 and265d560/26350d0;
- ext header/depth17c4783..4bc9, unconditional visitor2643600,
  restoration17c4c95..4ca6;
- element numeric3423120, top scalar rejection344c690 and complete leaves;
- depth-zero calls17c5479/5486/5493.

Array/map/ext depth0 is reached only after a complete count/length header.
Therefore a truncated header at depth0 is TruncatedRead, not PanicBoundary.
At depth1, a complete container header yields DepthLimit with depth_after0.
At depth>=2, maps reject before reading entries and retain depth-1; extensions
reject before type/payload and restore depth; arrays retain depth-1 on short
count/element failure, but restore depth after four successful values for both
Value and ExcessElements. No rollback or generalized restoration is implied.

Bin payload length>=4 succeeds even if overlong, consumes the whole payload and
uses only its first four u8 values. Its depth is unchanged. Strings always
reject after complete-payload consumption. The independent whole-body/table
proof establishes standard UTF-8 Boolean validity, not diagnostic details.

## Numeric contract

Binary64 payloads preserve all input bits by integer load/byte swap/store.
Numeric integers map to binary64 RN-even values (no saturation); binary32 maps
to its exact binary64 value for finite values and signed zeros, preserves sign,
shifts NaN fraction left29 and quiets signaling NaNs by setting bit51 under the
masked-exception x86 conversion premise. The separate installer FP proof must
be admitted before an all-bit source theorem. RN-even, DAZ0, FTZ0 and masked
exceptions are explicit correspondence premises, not an observed runtime MXCSR
claim. Flags/traps and diagnostic FP activity are excluded from the projection.

The manual fixtures here use exact small integer/finite values plus raw binary64
bits. Separate frozen scalar witnesses cover difficult conversion endpoints and
NaNs; their authorship/provenance is not attributed to this fixture author.

## Fixture construction and limits

`write_manual_fixtures.py` mechanically materializes manually specified case
families and expected tables. It reads no target/export/model and contains no
decoder, marker loop or floating conversion. It does not derive expectations by
running source/reference code. Arithmetic is limited to literal byte assembly,
known header lengths, case IDs and fixed expected-state tables. Its source and
actual authoring receipt are retained; it is not a qualification harness.

`manual.json` contains complete literal byte inputs and expected typed results.
Its all256 top-marker partition is based on marker-only inputs, not an all-input
correctness claim. Additional cases cover array element classes, all partial
length/numeric widths, depth0/1/2/65535, array0..5 and bin0..5, trailing data,
map/ext/String rejection and UTF8 boundaries. Source implementations must be
compared against unchanged literal expectations; these cannot by themselves
prove total correctness, runtime equivalence or opaque effects.
