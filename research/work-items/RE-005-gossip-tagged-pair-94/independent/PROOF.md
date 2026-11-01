# Independent normal-state proof for the response tag-2 payload helper

The accepted response route selects table arm0x438b795 for outer variant2 and
calls0x466c770. The newly authenticated complete body is
0x466c770..0x466c8ae, 318 bytes / 86 GNU instruction rows, SHA-256
47be169576f57402f5681a43722cf6b25f16d52e33187c39a6a2ccf7990569fb,
on node94 SHA3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
METADATA/BINDINGS retain the exact FDE/CIE, executable mapping, complete raw
body/row partition, in-body branches, two direct calls and two RIP data refs.
Source peer independently exported the same body before any new field Rust.

## Domain and scope

Input is a valid immutable nonwrapping slice of at most isize::MAX bytes,
separated from mutable state/output/stack. Fixed code/data and ordinary helper
returns are assumed. The raw mode's low DWORD controls charging; upper bits are
irrelevant in every stage. Counter and limit are full unsigned u64 words.
Names, safe result and diagnostics are chosen logical projections, not a native
type/ABI or whole gossip message. No allocation, copy/release runtime or new
opaque callee appears. The already-established u64 wrapper/Reader/error theorem
is separate dependency context, not new byte recovery or PR1365 duplication.

## Selector stage and error precedence

At0x466c77c only low32(mode)==1 enables an initial charge1. CounterMAX rejects
rawtag2 before store or input access. Otherwise0x466c79f stores C+1, then the
unsigned oldC>=limit comparison at0x466c7a3 rejects with that store retained.
For C<MAX this is exactly C+1>limit. Charging precedes empty input checking.

Empty input returns tag0/needed1 and consumes0. An available selector is
zero-extended at0x466c7b9, then pointer/remaining are updated at0x466c7c2/7c6
before its0/1 comparisons. Thus every non-budget-rejected available selector
is consumed, including invalid values2..255.

Selector0 stores branch marker0 at output+8 and success18. It calls no field
decoder and leaves every suffix byte unread. Selector1 takes the two-call
path. Every other selector returns rawtag5, found selector, the actual52-byte
ASCII diagnostic and the chosen legal-tag set[0,1], without field calls.

The literal0x6f86ca is exactly
core::option::Option<node::gossip_rpc::GossipStatus>; this is observed data,
not proof of recovered source type or public ABI. The referenced0x203f40 first
16 bytes are00000000000000000000000001000000. They are retained as opaque
supporting context, without assigning a Rust Location/range-descriptor layout.
The actual branch predicates independently prove that only0/1 are accepted.
All80300 actual8-byte RELA writes miss the code, literal and context intervals,
including writes starting before those intervals.

## Exact sequential scalar behavior

The two actual E8 calls at0x466c7de and0x466c7fe both resolve to0x466bd10.
The first status is compared to18 at0x466c7e8 before the second call can occur.
The second status is compared at0x466c808. On either failure the active scalar
error is forwarded, with all committed charges and cursor movement retained.
When the second fails, the first successful value is not a successful output.

Each scalar call uses the existing u64 theorem on its own current suffix:

- Mode lowDWORD1 precharges8. Overflow preserves the counter; otherwise the
  sum is stored before limit rejection. Budget error precedes reading a tag.
- Empty suffix is tag0/needed1 with no consumption.
- Byte0..250 is its value, consuming1. FB/FC/FD read little-endian2/4/8-byte
  payloads, total3/5/9, including nonminimal values.
- A short marked payload consumes its tag only and reports total-old_length.
- FE/FF return tag3/found4or12. A current suffix of at least9 bytes selects
  fast expected2 and consumes0; a suffix at most8 selects Reader expected3
  and consumes1.

There is no ordering/range predicate between the two scalar values. On two
successes, the native output stores branch marker1 at+8, first value at+16,
second value at+24 and success18. The chosen result is TagOne{first,second},
without guessing original field names. At most three ordered counter stores
occur: selector1, first8, second8. Their charge amounts are fixed memory-word
costs, independent of actual variable-width wire consumption.

## Excluded raw bytes

The selector's common error epilogue writes BYTE+1 and DWORD+4 from ECX,
QWORD+8 from RDX, QWORD+16=52 and QWORD+24=0x203f40. On budget and empty-input
errors, these can contain counter or unspecified entry-register bits and
inactive diagnostic words; tag2's QWORD+8=1 is not a logical needed field.
The projection retains only active tag0 needed1 or tag2 unit error. It does
not silently compare those extra bytes as raw output memory. On tag5 the
found selector and exact diagnostic are meaningful observations; native
addresses and opaque context layout are not projected. Scalar-forwarding
padding and inactive bytes are likewise excluded.

## Concrete boundary consequences

Mode1/C0/L17, selector1 followed by two 9-byte encodings of u64MAX succeeds,
stores[1,9,17] and consumes19 bytes. Wire length is not this budget's cost.
With L16 the second charge17 is retained but no byte of the second scalar is
consumed. With L8 the first charge9 is retained and no scalar tag is consumed.
Mode1/Cmax has no store or input change, even for empty/invalid selectors.
Selector0 in an admitted mode1 call stores only C+1 and ignores all suffix.
Modes whose low DWORD is not1 bypass all three charges, including full-QWORD
nonzero modes; upper-mode bits leave behavior unchanged at each fixed low word.

The agreed input TSV is id,mode_u64,counter_u64,limit_u64,wire_hex. Canonical
sorted JSONL has16 keys: id,tag,option_tag,first,second,needed,expected,found,
type_name,allowed_tags,counter_after,counter_writes,consumed,remaining,tail_hex,
phase. Only active values are present; other fields are null. Phases are
selector_error/none/first_error/second_error/some. The corpus uses pure unsigned
arithmetic, byte predicates and suffixes, not an opcode/PC/register evaluator.
No new field Rust or client has been read/authored before this seal. Original
types/compiler/ABI/pointer identity, whole gossip framing and component gates
remain unclaimed.
