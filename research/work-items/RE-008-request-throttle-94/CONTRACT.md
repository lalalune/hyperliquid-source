# Request throttle: one call and retained state

This is a conditional native value/state contract for node94
`44b8050..44b840a`, not a complete request lifecycle or network implementation.
All addresses are ELF virtual; ends are exclusive. Target SHA256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

The abstract state is a finite map from `(committed_round:u64, hash:[u8;32])`
to `(stamp:Timestamp, reasons:set<u8>, sent:bool)`. Only native tag1 keys are
admitted. A timestamp is the triple `(packed_date:i32, second:u32, nano:u32)`.
Its year is `packed_date >> 13`; ordinal is `(packed_date >> 4) & 511`.
The admitted calendar is proleptic Gregorian, year `-262143..=262142`, ordinal
`1..=365+leap(year)`, second `<86400`, nano `<1000000000`, and the low nibble
is the canonical flag derived in PROOF. Leap-second encodings are excluded.
All initial rows and every native-corresponding event have valid timestamps.

Inputs are event time, the current committed round, hash, a reason byte, and
either default delay or explicit binary64 delay bits. The native option test
uses only bit0; the safe interface will use an actual option. No semantic names
are assigned to the reason bytes. The five observed call sites use reasons0..5,
but the operation compares/inserts the full byte domain.

For an ordinary successful native call:

1. Look up the exact key. A missing key gets a row with event time as its stamp,
   empty reasons and `sent=false`. An existing row keeps its original stamp.
2. Insert the supplied reason, including when the later result is suppressed.
3. Default delay means exactly one second. For explicit delay, round the binary64
   product `delay*1e9` to nearest/ties-even. A nonfinite product maps to zero.
   Otherwise clamp to `[-2^63,+2^63]`, truncate toward zero and saturate to i64.
   Add these signed nanoseconds to the original stamp. The deadline must remain
   in the admitted calendar range for native correspondence.
4. If event time is before the deadline, or the row is already sent, return Held.
   Otherwise set `sent=true` and return Request with the exact key. Equality at
   the deadline admits a request. Registration and emission may occur in one
   call for explicit zero/negative/nonfinite-to-zero delay.

The result relation uses only active native fields: Held writes discriminant2;
Request copies key tag1, round at+8, hash at+16 and byte1 at+48. Copied padding
is not an output value. Deadline and registration status in the future safe API
are useful derived observations; they are not claimed additional native fields.
After every call the state snapshot exposes all rows, stamps, reason sets and
sent flags. Arbitrary call histories may move event time backward. No operation
here refreshes a stamp, clears sent, removes a row or changes the key's round.

## Native premises and new refusal policies

Native correspondence assumes exclusive access to the whole abstract state;
finite valid ordered B-trees with no duplicates, correct parent/child links,
counts and capacities; all required live/aligned/nonwrapping spans; disjoint
key/time/output/stack/map/logging storage; adequate allocations; and normal
return without unwinding, panic or asynchronous/foreign mutation. Root cardinality
increment and height growth cannot overflow. Existing reason nodes, row payloads,
their ownership and all moved buffers satisfy the explicit tree proof. Raw
allocator or reference-count equivalence to Rust containers is not claimed.

Imported memcpy copies exactly the requested disjoint byte span; memmove copies
as if through a temporary and permits overlap; neither writes elsewhere. memcmp
returns the unsigned-byte first-difference sign and zero exactly on equality,
without mutation. Those are explicit imported-interface premises, not proof of
the captured libc implementation. Allocator returns fresh, sufficiently sized,
aligned disjoint live spans or follows an excluded failure route. Locks grant
the displayed log/stat object access and release normally. Logging/stat helpers
may affect their own objects but preserve all key/time/row/tree/output and
caller-stack values used later, including pointers that escaped to prior calls.
Their original formatting, counters, reentrancy, scheduling and exception
effects are not implemented. SSE uses nearest/ties-even, gradual underflow
(FTZ/DAZ disabled), and masked exceptions.
No live threading or allocator success theorem is asserted.

The planned safe interface validates a supplied timestamp before any state
mutation. InvalidTime is a **new refusal**, outside native correspondence. If
deadline addition leaves the admitted date range, DeadlineRange is a **new
refusal after registration/reason insertion**; those changes remain and sent
is unchanged. It occurs even for an already-sent row because deadline formation
precedes the sent test. Native reaches a panic boundary in that situation;
this packet does not equate panic/unwind state with the safe refusal. Allocation
failure/ownership APIs will be pinned at the separate source gate. The corpus
marks entire histories containing either refusal as new-safe-policy examples.

Pruning, resetting a sent flag elsewhere, outbox consumption, wire encoding,
actual requests, log text, metrics, and full consensus behavior remain outside
this single-call operation. PR951 already recovered the default-delay outline.
