# Independent qualified gossip-helper wire/state proof

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
New observed complete FDE windows are primary `0x466dc10..0x466dcf4`
(228 bytes/68 rows), specialized collection `0x4589a30..0x4589b2b`
(251/78), and validator `0x157a200..0x157a3f7` (503/143): 982 bytes/289 rows.
Existing prefix wrapper/Reader/error helper semantics are separately credited
context. No new native bytes are counted for those dependencies or the unused
u8 callback address. Source peer NATIVE-INTAKE, HELPER-INTAKE,
DATA-AND-IMPORTS and validator-table closure records bind actual bodies,
FDE/CIE, mappings, calls, data and RELA; FREEZE binds those exact records.

## Explicit qualified domain

The source peer's pre-source NORMAL-DOMAIN.md is part of this theorem. Inputs
are valid immutable separated nonwrapping byte slices of at most isize::MAX
bytes; live input/state/output/stack/allocated memory do not alias improperly.
Mode is an observed raw u64 word, limit/counter are unsigned u64 words. Their
names and the safe result representation are chosen labels, not recovered
original Rust types or valid source-level enum constructors.

For positive available lengthN, the selected actual allocator must return a
valid disjoint writable N-byte allocation or leave this ordinary-return domain.
The actual dynamic memcpy copies exactlyN disjoint bytes and preserves reader
and output state. Its N=0 call accesses no memory, including with dangling
nonnull destination1. Release accepts the actual allocation/size, returns
ordinarily and preserves reader/output/error metadata. These are functional
premises. The 7,906-byte allocator, TLS-dependent release/tail0x54c7550,
allocation-error dispatch, unwinding, allocation addresses and native ABI are
not claimed closed, stubbed or emulated. No fake allocation-fault outcome is
part of the authority. New-source allocation refusals require separate labels.

## Existing prefix context, used without copying an occupied API

The actual collection call0x4589a49 selects u64 wrapper0x466bd10. Its complete
229-byte native theorem is already retained in the separate outer-adapters
proof (PROOF.md SHAaf52027344e833b108048b0ec0f46afaf83056f61ab0caced49561b2e3355ccc),
on this same target digest. Accepted Reader/error-builder evidence closes its
slow calls. The independent wire authority uses these arithmetic equations;
it does not read any open PR implementation or import a repository evaluator.

Only `(mode & FFFFFFFF)==1` charges8 before reading the header. Overflow
rejects with rawtag2 before store/input change. Otherwise store counter+8,
then reject if that sum exceeds limit, retaining the store and input. On an
admitted header read:

- Empty input: tag0/needed1, consumes0.
- First byte0..250: value equals that byte, consumes1.
- FB/FC/FD: little-endian unsigned2/4/8-byte payload, total3/5/9 bytes.
  Nonminimal values are accepted. Payload shortage is `required_total-old_len`
  and consumes just the tag, leaving the entire payload suffix.
- FE/FF: rawtag3, found4/12. At original input length>=9 the fast path consumes0
  and expected is2. At length<=8 the Reader consumes1 and expected is3.

The complete raw modeQWORD is retained independently of this low-DWORD test.

## New collection stage and exact counter stores

If the header returns anything other than18, collection copies its error and
returns; primary likewise forwards it. Observe only active tag0 needed or tag3
expected/found fields, never copied inactive/padding bytes.

On prefix success, let N be its decoded length, C the post-header counter, and
R the unread input length. At0x4589a5c the payload gate tests the **full mode
QWORD for nonzero**. For nonzero mode, compute the mathematical sum C+N:

1. Sum>u64::MAX rejects tag2 before a payload counter store.
2. Otherwise store that sum at0x4589a6f, even forN=0.
3. Sum>limit rejects tag2, retaining the store. No payload is consumed.

ModeQWORD0 bypasses this payload charge. Next, R<N returns rawtag1 at0x4589aad
without a needed-word write and without consuming payload. All prefix effects
remain. Availability succeeds only ifN<=R<=isize::MAX, making the negative
length allocation branch unreachable on this ordinary valid-slice domain.

ForN>0, the actual allocator/copy contract applies. ForN=0 allocation is
skipped and the zero-length copy uses destination1. Only **after memcpy** do
0x4589aff..0x4589b06 advance the input pointer byN and set remaining toR-N.
The successful collection record has capacity=N and length=N. The supplied
u8-function address0x466bbb0 is unused by the entire specialized collection
body; there is no per-element decoder call or per-element charge.

Thus the counter_writes array in the chosen projection records zero, one or
two actual source-assignment events, in order. It is not inferred from final
counter inequality. For example mode2/C5/limit4/header00 consumes the header,
stores5 during payload+0, then returns tag2 with counter unchanged.

## Validation, consumption and release order

Primary calls the complete validator through actual RELATIVE slot0x576e3f8.
The separate UTF8-PROOF closes its full scalar/ASCII grammar and all256 table
entries, with no callees. It accepts exactly shortest Unicode scalar encodings
and returns the first failing scalar's start-byte offset with Some1/2/3 for a
present wrong continuation or None for an incomplete suffix.

The copied payload has already been consumed before validation. Valid bytes
produce rawtag18 and the owned capacity/pointer/length triple; the chosen
projection exposes the complete owned bytes, not physical pointer/capacity.
On validation error, capacity=N. SinceN<=isize::MAX, the primary NEG/JO branch
requiring capacity2^63 is unreachable. Capacity0 would skip release, but an
empty payload cannot fail this validator. Therefore every admitted UTF8 error
requests release ofN>0 bytes with flag0 **before** publishing rawtag6 and the
logical error metadata. This records a release request/order, not recovery of
jemalloc/TLS internals. Prefix+entire payload consumption and all counter
stores remain, and the complete original unread suffix is unchanged.

The validator writes BYTE presence at+16 and BYTE payload at+17. On None, the
payload may be stale BL (including EE/EF and F1..F3 transformed lead values).
Six following metadata bytes are not written. Neither inactive payload nor
padding enters the mathematical Option projection. No complete native-memory,
original ABI or nominal owned-string type equality is claimed.

## Independent authority and concrete state examples

The wire input TSV is id,mode_u64,counter_u64,limit_u64,wire_hex. Canonical
sorted JSONL has exactly15 keys: id,tag,needed,expected,found,valid_up_to,
error_len,data_hex,release_request_length,counter_after,counter_writes,consumed,
remaining,tail_hex,phase. Only active fields have values; others are null.
Phases are header_error/payload_budget/payload_short/invalid_utf8/ok.

- mode1/C0/L10/wire02c280cc: stores[8,10], success bytesc280, consumed3,
  unreadcc. L9 instead retains stores[8,10], tag2, consumes only header02.
- mode2/C5/L4/wire00: stores[5], tag2, consumes1 despite no counter change.
- mode0/Cmax/L0/wire01ff: no counter store, tag6/(index0,Some1), release
  request1, consumes2. No captured allocator failure is invented.
- Mode2^32 charges only payload; mode(2^32|1) charges both stages. Empty and
  nonminimal headers retain the same established ordering and fast/slow gates.

Expected records use only integer inequalities, Unicode scalar byte predicates
and suffixes. The generator is not an opcode/PC/register evaluator and invokes
no target, repository implementation module or new Rust. Its validator relation
is independently checked against Python's strict Unicode decoder. The complete
new source must be authored only after the final FREEZE hash is handed off.
No whole gossip response/caller/source identity/compiler/runtime/serialization
gate follows from this bounded qualified relation.
