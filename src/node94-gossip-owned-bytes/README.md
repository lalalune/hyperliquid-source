# Node #94 length-delimited validated bytes

This component reconstructs the qualified normal-return wire/state relation
of node #94's gossip payload helper at `0x466dc10..0x466dcf4`. It also implements
the byte validator at `0x157a200..0x157a3f7`. The complete new native scope is
228 + 251 + 503 = **982 bytes / 289 instruction rows**, including the actual
specialized byte-collection callee at `0x4589a30..0x4589b2b`.

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Names and safe data types are chosen descriptions. This is not a recovered
original String type, allocator layout, private ABI or whole gossip schema.

## Defined relation

`decode_owned_bytes` reads a little-endian variable-width length, charges and
copies that many bytes, consumes the complete copied payload, then validates
strict UTF-8. It returns an owned byte buffer on success. Invalid bytes report
the first failing sequence's start and optional error length after the entire
payload has been consumed and its new buffer dropped. No normalization,
terminator handling or display policy is imposed; NUL and noncharacters are
valid when their UTF-8 encoding is valid.

The header's fixed charge of 8 is enabled only when the raw mode's low DWORD
equals 1. The payload's charge of the decoded length is enabled when the full
mode QWORD is nonzero. Overflow rejects before a counter store; a nonoverflow
sum is stored before its limit comparison. Charging precedes payload
availability. A shortage leaves all available payload unread while retaining
the consumed prefix and charges. `CounterStores` records actual production
assignments in order, including a store of the same counter for length zero.

The existing real `hl-bincode-varint` crate supplies the accepted Reader and
fast-path implementation unchanged. A private header bridge composes that
dependency with this call's budget/context rules. Existing wrapper/Reader
semantics are credited context; no PR #1365 API or implementation is copied,
changed or counted as new recovery.

Raw logical tags are 18 for success, 0/2/3 for established header errors, 2 for
payload budget rejection, 1 for insufficient payload, and 6 for invalid UTF-8.
Only active logical fields are exposed. The validator's inactive Option payload
and six unwritten padding bytes are excluded. The safe owned value exposes byte
content and length, without asserting native allocation addresses or capacity.

`validate_bytes` separately exposes the complete validator's logical grammar
and first-error relation. Its independent scalar implementation checks Unicode
byte classes directly; it does not delegate validation to `from_utf8` or copy
captured instructions. The native aligned ASCII optimization is proved to have
the same value relation for all eight pointer residues.

## Domain and remaining gaps

The domain is x86-64 with 64-bit `usize`, immutable valid nonwrapping input
slices at most `isize::MAX`, separated live storage and ordinary returns.
Native allocation must supply a valid disjoint N-byte buffer, the actual memcpy
must copy exactly N bytes, and release must return without changing live
reader/output/error state. Real Rust allocation/copy/drop implements this source;
no fake allocator or captured machine-code object is linked.

These functional premises do not close the original 7,906-byte allocator,
TLS-sensitive release implementation/tail, allocation-error or unwind behavior.
Allocation refusal is not a new native error result. Native types, pointer/ABI
identity, inactive bytes, faults, aliases, concurrent mutation, original
compiler/machine bytes and full component gates remain outside the claim.

The independent 116,179-case validator and 45,320-case wire authorities were
sealed before new Rust, including exact counter stores and unread suffixes.
The input-only example has separate validator/wire modes; expected output is
owned by the runner. Small ordinary test fixtures are unchanged public rows
selected and frozen before source. Private holdouts remain unread by this author.

The component has a real standalone manifest with the existing local dependency.
It uses the admitted standard library for owned allocation; it is not a no_std
or recovered whole-node workspace claim. Actual build results are pending.
The expanded instruction-evaluator suite, captured program execution and hosted
CI have not run. All full component gates remain false.

New source/docs are independently authored MIT project work. Captured evidence
and upstream dependency material retain their original rights and notices.
No unlicensed inferred implementation is copied.
