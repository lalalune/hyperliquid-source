# Node94 0x466c770 normal logical state relation

No new Rust or input client has been authored for this question. This note is
derived from the authenticated complete 318-byte primary listing only, with
the established u64 wrapper/Reader/error theorem as separately credited
context. The independently authored oracle is owned by the Reader peer.

The exact body is 0x466c770..0x466c8ae, SHA-256
47be169576f57402f5681a43722cf6b25f16d52e33187c39a6a2ccf7990569fb.
There are two direct calls, at 0x466c7de and 0x466c7fe, both to 0x466bd10;
there are no other calls or allocation dependencies in the primary. Native
coordinates, pointer values and stack layout do not identify the original
Rust type or a public ABI.

The normal domain has valid immutable nonwrapping slices of at most isize::MAX,
separated mutable state/output, fixed code/data, and ordinary u64 helper returns.
Raw mode is observed through its low DWORD only; higher bits are invariant.
Counter and limit remain full unsigned QWORDs.

If low32(mode)=1, the selector precharge is one. Counter MAX rejects before
store. Otherwise c+1 is stored, and unsigned old c>=limit rejects. Since c<MAX,
old c>=limit is equivalent to c+1>limit; the failed-limit store remains. This
charge occurs before checking whether the selector is available. Other mode
classes leave counter untouched. Selector budget failure returns raw tag2.

No available byte returns raw tag0 with active needed1 and consumes nothing.
A present byte is zero-extended into ECX, and cursor/remaining are updated
before either selector comparison. Zero returns raw success18 and a QWORD
branch marker0 at output+8. No scalar helper is called. One invokes the real
u64 wrapper twice, strictly in order. The first result must be success18 before
the second call can occur. Each call contributes its actual accepted charge,
fast/slow consumption and active error behavior, under unchanged mode/limit.

If both calls succeed, output has raw tag18, QWORD branch marker1, then the
first and second unsigned values at +16/+24. If either fails, the generic
error is copied out; the first scalar value is not a successful output when
the second fails. Prior counter stores and consumed input are retained. The
32-byte native error-copy path contains unknown/inactive callee bytes, so its
logical relation includes active established fields rather than full memory.
There can be at most three counter assignments: selector, first wrapper,
second wrapper. Each must be recorded at its production assignment, not
inferred by comparing the initial/final counter.

Every other selector returns raw tag5 after consuming the selector and without
calling either scalar helper. Its literal pointer is 0x6f86ca and length52;
the exact ASCII bytes are core::option::Option<node::gossip_rpc::GossipStatus>.
This is an observed literal, not proof that the source API/type is recovered.
The two legal selector values [0,1] follow from branches independently of the
opaque context bytes at 0x203f40. Only the first16 context bytes are retained
as supporting data; their layout is not inferred. The earlier exploratory
24-byte window includes following data and is not a context-size claim.

The common selector-error path writes BYTE+1 from CL, DWORD+4 from ECX, QWORD+8
from RDX, QWORD+16=52 and QWORD+24=0x203f40. On an invalid selector these
observations bind the found selector/literal/context, without native address
identity in the chosen source API. On budget/shortage, several such writes are
inactive: RCX can carry old counter bits or otherwise unspecified entry data.
In particular the budget path writes QWORD+8=1, but this is not a logical needed
field for tag2. These inactive words/bytes and untouched output bytes are
explicitly outside the logical projection. No complete raw-memory equality is
claimed.

The proposed finite input protocol is id/mode64/counter64/limit64/wirehex.
The logical output is id,tag,option_tag,first,second,needed,expected,found,
type_name,allowed_tags,counter_after,counter_writes,consumed,remaining,tail_hex,
phase, with inactive values null. The names option_tag and type_name describe
the chosen projection and observed literal; no original enum layout, field
meaning beyond unsigned first/second, full gossip message, compiler or whole
component gate is asserted.
