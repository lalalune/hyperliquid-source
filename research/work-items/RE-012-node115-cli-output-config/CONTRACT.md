# Observed Node115 constructor contract

The target, coordinates, raw instruction evidence and non-claims in README.md
apply throughout. This is an observed native write relation under stable,
well-formed parsed objects, readable input strings, valid disjoint output,
stack and owned storage, ordinary allocation/copy contracts and normal
returning helper calls. It is not a safe interface for arbitrary pointers,
aliased state, malformed hash tables or concurrent mutation.

## Execution order and active bytes

`out` is entry RDI, parsed-state is RSI. At each query RDI is the saved state,
RSI the literal address and EDX its exact length. `presence(k)` calls
0x4e4c8e0 and retains AL. `value(k)` calls0x4e4ca30 and observes RAX/RDX.
The first six presence queries precede the optional value, then the remaining
six presence queries run, then the required style value. None is reordered to
pretend all validation happens before allocation.

| Output offset | Actual presence query |
| --- | --- |
|24|write-trades|
|25|write-fills|
|26|write-raw-book-diffs|
|27|write-order-statuses|
|28|write-misc-events|
|29|write-hip3-oracle-updates|
|30|write-system-and-core-writer-actions|
|31|disable-output-file-buffering|
|32|batch-by-block|
|33|stream-with-block-info|
|34|serve-evm-rpc|
|35|serve-info|

The first eight bytes are packed using saved stack values, dword shifts/OR,
MOVD/PINSRW and the MOVQ at0x564d60c. The last four are explicit scalar stores
at0x564d616/619/61d/621. Their actual displacement operands are re-read by the
collector; the complete packing block is retained, not replaced by prose.
The primary's success stores begin at0x564d5ad; no successful out write occurs
earlier in this body, apart from arbitrary effects of opaque helper aliases
excluded by the disjoint/normal helper premises.

## Optional owned value

`value(write-user-clearinghouse-states)` occurs at0x564d443.
A zero RAX uses R14=MIN64 and skips allocation; pointer scratch at rsp+0x10 is
not initialized on that path. Present length0 uses capacity/length0 and pointer1.
For a positive length below2^63, the normal nonnull allocation receives exactly
that length and the copy import gets destination, returned input pointer and
length. The destination is retained at rsp+0x10. Output offsets0 and16 both
receive R14; offset8 receives that pointer scratch. A string path, list syntax,
filter grammar, UTF-8 requirement and downstream meaning are not proved.

A high-bit length calls slot0x64df498 with EDI0. Null allocation calls the same
slot with EDI1. These are observed call edges, not independently proved
nonreturning contracts. In particular, the allocation failure call does not
itself have a following UD2 before the cleanup landing. No invented recoverable
Result/error API is supplied.

## Style value and failure

The required value lookup at0x564d544 tests RAX before reading the view.
Absent goes to the call at0x564d697 and then UD2. Supplied values compare
length21,14,7 in that order. Seven-byte actions uses overlapping dwords at
0/3 and tag0; recent-actions uses overlapping qwords at0/6 and tag2;
actions-and-responses uses16-byte constants at input0/5 and tag1. Exact bytes
and comparisons are recorded. Other lengths or mismatches reach the error
call at0x564d688 and UD2. These are case-sensitive byte relations, not
whitespace normalization or prefix acceptance.

On the qualified successful path tag36 is written after the12 presence bytes
and the three optional words. RAX returns the original out pointer. Padding,
unused trailing bytes, enclosing enum representation and a Rust ABI are not
established by this write span.

## Cleanup and helper boundaries

The primary LSDA starts at0x3bad94 and has omitted LPStart/type table.
Call-site[0x564d390,0x564d4a9) has no local landing;
[0x564d4a9,0x564d69d) names landing0x564d6ad;
[0x564d69d,0x564d6d8) has no local landing. At the cleanup landing,
twice R14 modulo2^64 decides whether to skip deallocation. Under the valid
owned-length premises, this skips absent MIN64 and empty0, while a positive
owned length loads the saved pointer and calls slot0x64df4a0 with length and
EDX0 before UnwindResume. This is a local unwind observation, not complete
transitive exception/allocator behavior or an atomic-output guarantee.

The complete pre-existing presence/value helpers are context. Presence can
match the selected child name before table membership, so it does not parse
the text false. Value probes the actual table, requires a nonempty value list
and follows conversion at0x64dfca8. Hash0x4e52640, table invariants, conversion,
allocation/deallocation and error callees remain unclosed. Symbol-qualified
imports and relocation targets are observations, not proofs of helper purity.

The selected command FDE0x5654bf0..0x5655d5c has actual calls at0x56550de and
0x56551e9 through slot0x64ebcb8. Each passes destination+8; on normal return
the caller writes qword2 or3. PR2034 identifies those arms as run-non-validator
and run-validator. Its broader command/parser claims are not re-owned here.
No complete caller, CLI execution, external side effect or downstream
user-clearinghouse writer behavior is claimed by the two edges.
