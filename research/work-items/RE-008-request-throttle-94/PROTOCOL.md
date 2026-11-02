# Frozen input-only comparison protocol

The future client receives only one line `C000000<TAB>hex_frame` per case.
IDs are opaque sequential labels; semantic names, domain labels and expected
values stay in cases.jsonl.gz and expected.tsv.gz outside the client process.
It must consume the whole frame, reject invalid option/count/short/trailing
encodings, and emit no successful output for malformed framing. A future
harness may impose a documented byte-size safety cap as transport policy.

All integers are little-endian. The frame is:

| Field | Encoding |
|---|---|
|magic|four bytes TH01|
|initial row count|u32|
|each initial row|round u64, hash32, timestamp12, sent byte0/1, reason count u16, reason bytes|
|step count|u32|
|each step|round u64, hash32, timestamp12, reason byte, delay option byte0/1, then u64 raw binary64 bits only for option1|

Timestamp12 is packed date i32, second u32 and nano u32. Initial keys are unique,
timestamps canonical, reasons strictly increasing byte values and sent is bool.
Bad initial-state encoding is a driver refusal, not a native result. Well-framed
step timestamps may be invalid to exercise the new safe policy. The client must
not silently reorder conflicting initial keys or accept duplicate reasons as an
oracle assumption. It may insert valid initial rows in any source-container order;
the expected state is the exact finite map relation.

For each input line the client emits the same ID, a tab and compact JSON array
of step outcomes with object keys sorted lexicographically, matching expected.tsv.
This serialization is a test transport, not a recovered native wire format.

Each valid-time outcome has keys `status`, `registered`, `deadline`, `request`,
`snapshot`. Status is held/request/deadline_range. Deadline is timestamp12's
three integer values or null on DeadlineRange. Request is `[round,hash_hex]`
only when emitted; otherwise null. Registered is true only when that call
created the row. Snapshot contains every row in `(unsigned round, byte hash)`
order with fields `round`, `hash`, `stamp`, sorted `reasons`, `sent`.
InvalidTime has only `status` and unchanged `snapshot`. History is retained at
each step; snapshots must not be references later mutated in place.

`deadline_range` and `invalid_time` are newly specified safe refusals, explicitly
outside native ordinary-return correspondence. Native-corresponding histories
are marked separately in cases metadata. Report native-composition and new-policy
mutant discrimination separately. Any later corpus/protocol amendment must retain
the original freeze, before/after identities, rationale and source-phase timing.

Expected generation uses exact integer binary64 rounding,400-year partitions and
a flat list/linear key relation. The intended source uses an actual BTreeMap and
closed day arithmetic. No expected files, semantic case names, target binary or
native exports enter the future source client. Reproduction metadata records
exact source and toolchain identities before any authorized compilation.
