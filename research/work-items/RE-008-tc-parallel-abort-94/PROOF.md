# TC verification: conditional local abort and reduction

The target is node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF virtual addresses; ranges exclude their end.
This packet binds the complete bridge `0x4768f80..0x47694d3` and local fold
`0x476f3e0..0x476f6ed`. It does not replace Rayon, authenticate supplied
verifier results, recover a thread scheduler, or claim end-to-end TC validity.

`static/records.json` retains complete bytes, decoded instructions, actual
FDE/CIE records, LSDA pointers, direct and indirect transfers, RIP references,
and the E8 incoming-call scan. Supporting bodies are credited context, not
newly reconstructed algorithms. No captured instructions are executed or
interpreted. FDE ranges alone are not a whole-program function census.

## Existing gap and real caller

The existing `RE-008-block-admission-94` packet explicitly substitutes an
index-order loop at `0x4768f80`. Its README says several invalid votes can
produce a different error in the real parallel loop. The existing admission
crate similarly documents its stable input-order choice as an unresolved
boundary. Neither that stub nor our value projection proves a global native
error order.

The complete caller `0x47594f0..0x4759963` initializes a stack byte to zero at
`0x4759772`. Its address is stored in consumer field `+0x10`; the validator
history reference occupies consumer `+0x18`. At `0x475982b` the bridge receives
the vote pointer, actual row count, equal logical length, minimum one, and an
initial nonmigrated flag. At `0x475983e..0x4759843` it tests the returned tag.
Only identity reaches signer collection `0x4451690` and the relocation-backed
quorum helper at `0x4759865`. These existing verifiers and quorum helpers are
bound as context, not re-counted discoveries.

The ordinary signed-timeout verifier with its low ECX byte zero returns
identity `S = 0x800000000000002a`, missing-history tag
`0x8000000000000028`, or the signature-error tag `0x8000000000000001`.
The flag-zero branch bypasses the nested-QC verifier. This follows the full
`0x454aa10..0x454ad45` body under ordinary returning helper behavior; exceptions
and transitive verifier writes remain outside this relation. The fold also
contains a branch for `T = S+1`. It is retained in the local raw-value API,
without claiming the flag-zero verifier ordinarily produces it.

## Admitted domain and observations

The Rust component is a safe, dependency-free analysis projection. Its records
are values, not native ABI types. An 80-byte result contains a little-endian
tag followed by 72 supplied bytes. A 96-byte folder contains that result and
16 opaque bytes corresponding to native fields `+0x50/+0x58`.

To apply the relation to native memory, require a valid nonwrapping finite
span of 184-byte rows; all described state, output and callback result storage
must be accessible, stable and disjoint from each other and from control,
stack, TLS and callback-owned storage. Require every projected byte to be
defined. This deliberately strengthens native availability: inactive enum
payload bytes may be uninitialized in real Rust values. We do not infer their
values from machine copies. The all-defined raw-record API applies only when
the caller can supply such a correspondence; active enum-field behavior does
not require claiming the inactive bytes.

Each `Observation` supplies the 80 bytes returned by one ordinary verifier call
and the shared-byte value after that call. It is neither a cryptographic
answer nor a promise that an arbitrary observation sequence is obtainable
from Rayon. For the local sequential projection, any external change to the
byte between calls and the subsequent read is included in that supplied byte
observation. State/output interference is excluded. If an error writes one,
the projected final byte is one under no intervening write after this store.
Actual concurrent memory-model admissibility is not established here.

Drop is represented by its raw delegated argument, not by freeing anything.
Correspondence requires the native drop boundary to return ordinarily without
changing the projected records or flag. Exceptional cleanup, allocator and
ownership validity, MMIO, faults, concurrent mutation of other state, native
register/RSP/ABI observations, and panic/unwind execution are excluded.

## Local fold theorem

At entry, RSI identifies the 96-byte folder and RDX identifies a three-qword
producer. The producer's first two words are row start/end. Equality returns
the folder without calling the verifier or reading the shared byte. Otherwise
the leaf calls `0x454aa10` with ECX zero for its first row. It does not check
the shared byte before that call; the bridge has a separate entry check.

For each returned raw record R:

1. If tag(R) is T, `0x476f455..0x476f45a` returns the current folder. No local
   reduction, drop, cancellation store or cancellation read occurs.
2. If both current tag and tag(R) are S, the folder result remains unchanged.
3. If only the current tag is S, R becomes the folder result.
4. If the current tag differs from S, it remains the folder result. A second
   non-S record is delegated to `0x47328a0` at `0x476f592` before the flag store.
5. A non-S resulting folder writes byte one at `0x476f5dd`, stores the folder,
   and exits at `0x476f66c` without a shared-byte read.
6. Otherwise `0x476f66e` reads one byte. A nonzero value exits. Zero advances
   the row pointer by `0xb8`; only a non-end pointer repeats the call.

The 16 opaque folder bytes are preserved; the return copies all 96 bytes to
the supplied output. The copy and mutation ordering is subject to the disjoint
storage premise above. No arbitrary-alias equivalence is asserted.

An induction establishes this for every finite admitted span. Prior to each
continued iteration, the folder has its original identity result and every
previous observed byte was zero. A T marker, first error, or nonzero byte is
the first terminal event. An initially failed folder consumes at most one row
before stopping (or returns immediately for an empty span). Therefore the
independent oracle can choose the least terminal index as a set operation;
it does not need to emulate this loop.

## Bridge decision and result merge

The entry read `0x4768fb0` is byte width. Any nonzero byte returns identity by
writing only the first eight output bytes at `0x4768fc2`.

For a zero observed byte, let L be the logical length, P the producer count,
M the minimum, B the split budget, and W the supplied worker-count observation.
The midpoint is `h=floor(L/2)`. If `h<M`, or if the migrated byte is zero and
B is zero, the bridge selects the local fold. The native end delta is
`184*P mod 2^64`. Otherwise the new budget is `floor(B/2)` for an unmigrated
call, and `max(floor(B/2),W)` for a migrated call. The worker count is read only
on the latter eligible path. The subtraction at `0x4769151` checks `P-h` for
borrow; underflow goes to a panic boundary before task setup. The projection
reports that branch, without panicking. Otherwise the left/right counts are
h and P-h and the right pointer delta is `184*h mod 2^64`.

`plan` is a numerical one-step projection over all supplied u64 values and
bytes. Wrapping deltas are not permission to dereference wrapped pointers.
Ordinary native execution additionally requires valid producer and helper
domains. The real caller supplies L=P and M=1; the raw projection also exposes
the independently supplied mismatch/underflow paths rather than silently
assuming that invariant. Zero-filled unused plan fields are output-protocol
markers, not claims about native registers on those paths.

Scheduler boundaries `0x467a960`, `0x46aa2b0` and `0x46affd0` deliver two
80-byte child results to the bridge at stack offsets zero and `+0x50`.
Their complete bodies and the callback `0x4780ed0` are bound, but their task
execution order, scheduling policy and all transitive effects are not proved.
Conditional on ordinary returns with those child results, `0x476924d..0x4769483`
implements this complete truth table:

| Left tag S | Right tag S | Output writes | Delegated drop |
|---|---|---|---|
| yes | yes | S in bytes 0..8; old output 8..80 unchanged | none |
| no | yes | complete left record | none |
| yes | no | complete right record | none |
| no | no | complete left record | right, after output writes |

The selector is `cmove` at `0x4769449`; the both-error check precedes the drop
at `0x476947e`. This is left-child precedence for supplied results, not
smallest-input-index precedence. A right task may publish cancellation before
a left task starts, allowing that left task to return identity. Consequently
the table does not establish which invalid signature becomes the final error.
Likewise, successful completion of an isolated local fold with a nonzero
observed byte does not prove all its remaining records were verified.

## Public source comparison and atomicity

The target contains Rayon 1.10.0 and rayon-core 1.12.1 source-path strings.
Official Rayon tag v1.10.0 resolves to commit
`7543ed40c9a017dee32b3dc72b3ae819820e8366`; acquired files and both licenses are
in `sources/`. `try_reduce.rs` has an AtomicBool shared-full flag, local
first-error retention and left/right error reduction. `plumbing.rs` has the
minimum-length and stolen-job splitter and two-child bridge. These are
independent licensed primary sources for the algorithmic correspondence.

This is a structural correspondence, not exact source/crate/compiler identity.
The original enum/closure layout, local patches, crate lock and build flags
are not recovered. In particular, ordinary x86 byte MOV instructions do not
distinguish C++/Rust Relaxed from stronger source orderings. The public source
uses Relaxed, but that is not independently proven as the captured source's
ordering. No data-race safety or scheduler proof follows from a byte load.
The Rust component consumes observed values and performs no atomics or threads.

## Qualification boundary

The independent Python oracle and 6,780 inputs/expectations were frozen before
the Rust directory existed. It uses a terminal-index set, a merge truth table
and disjoint integer decision regions. The input-only client never reads an
expected file. Native host builds test this conditional value projection,
not captured execution or machine-code equality. Full counts, actual compiled
mutants, parser/comparator controls and preserved development failures are
reported in the validation records after execution.
