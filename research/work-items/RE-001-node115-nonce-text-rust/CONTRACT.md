# Node #115 nonce text value contract

This is the chosen source value contract. Its substantive semantic sections
below are retained verbatim from the independently reviewed precode revision3,
SHA-256 `c99dfc989cfb293bcde163ea50d46a05f2abef859316035b5e067e87420e849c`.
Historical proposal wording in those sections records the independently
frozen design, not native enum/type names or an execution claim. Current
implementation and validation results are documented separately in README.md
and actual run receipts. The original pre-source identities are recorded in
PRE-SOURCE-IDENTITIES.json.

## Purpose and exact native boundary

Implement one useful independently authored Rust component that converts a
byte prefix into a contiguous vector of canonical unsigned integers and then
checks the existing strict unsigned ordering relation. This closes an actual
missing source operation beyond the current ordering-only library. The new
component is a prefix decoder usable by a future state/input importer; it is
not a claim about a public nonce endpoint, replay policy or network admission.

The source basis is merged PR #1396's provider proof at current main
`8fd8db680ec4bfef40996e5616bce3d5156d0b86`. The target is node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Provider `0x1e29f50..0x1e2a28d` parses the values. Ordering wrapper
`0x2923da0..0x2923ee1` calls that provider and then applies the credited
relation. The provider does not itself sort, deduplicate or reject descending
values. The immediate outer caller `0x1ddf3b0..0x1ddf7bf` is context, not a new
composite two-field decoder: its first-field helper remains opaque.

Credit PR #1003 for the native ordering relation, PR #1694/current
`src/node115-nonce-ring` for its existing implementation, and PR #1396 for the
provider/numeric/growth/caller proof. New native-byte recovery credit is zero.
Do not include the separate open binder changes #2061/#2074/#2122/#2451 or
allocation-failure work #2127 in this claim.

## Chosen input domain

The proposed pure value interface accepts a valid immutable byte slice, a raw
mode byte and a raw depth byte. It interprets the start of that slice as the
selected native entry cursor. For an original interval with cursor c, use its
suffix beginning at c; a successful consumed count k corresponds to native
cursor c+k. The native premise remains `0 <= c <= length <= 2^63-1` with
nonwrapping valid storage. The source accepts arbitrary byte values, not just
UTF-8 text. A Rust slice supplies its own storage validity; no original parser
object or output pointer is accepted.

Mode zero performs the proved depth checks. Every nonzero raw mode byte
bypasses those checks. The full byte classes are supported, rather than an
unproved native Boolean or canonical enum domain. Depth is an unsigned byte;
zero and one are distinguished at their actual post-opening-byte branch.

There is no newly chosen grammar-size or nonce-policy limit. Host resource
failures and the boundary of the native successful-capacity theorem are
explicit outcomes below, rather than silently narrowing admitted inputs.

## Exact successful grammar and consumption

The selected prefix is:

```text
W '[' W (I (W ',' W I)*)? W ']'
W := zero or more bytes 09, 0a, 0d, 20
I := '0' | [1-9][0-9]* with mathematical value <= 2^64-1
```

All four whitespace bytes, including CR, are admitted. Other ASCII whitespace,
NUL, non-ASCII bytes and Unicode whitespace are not added to that set. Signs,
leading zeros on a multi-digit integer, fractions and exponent spellings do
not produce accepted integers, including negative zero. Decimal accumulation
must use the established full-width boundary, without wrapped overflow or
floating conversion. The successful numeric values preserve their input order.

Success consumes through the closing bracket and stops immediately after it.
Following whitespace or other bytes remain unconsumed. This is a prefix
contract; requiring complete input exhaustion would change it. An empty list
and a one-element list satisfy the ordering relation. All longer lists require
strict unsigned increase across every neighboring pair.

The entire selected sequence and its closing delimiter must be parsed before
ordering is classified. No early ordering failure may suppress a later parse
failure. For example, the malformed ending in `[2,1,]` is NotAdmitted
(and its covered native path ordinarily errors under the stated premises),
whereas a completed `[2,1]` reaches the ordering-invariant branch.
This is a semantic explanation, not a generated fixture corpus.

## Observable outcomes

These names and returned objects would be chosen source-interface values,
not recovered native enum names, object layouts or ABI results.

| Chosen outcome | Required meaning |
| --- | --- |
| Parsed | Own vector containing every parsed u64 in order, and the successful consumed-prefix byte count. All values are strictly increasing. |
| NotAdmitted | A logical source admission result: the selected byte spelling does not yield an accepted canonical-u64 sequence under the stated native value premises. Includes syntax, delimiter, leading-zero, negative, fractional, exponent and numeric-overflow spellings. This may correspond to a native ordinary error, a native failure branch, or unclosed helper termination; it does not assert that every such native invocation returns an ordinary parser error. |
| Depth-one rejection | After whitespace and an accepted opening bracket, mode zero with initial depth one takes the ordinary depth error and stores depth zero. This distinction is retained as a chosen observation; no error payload or cursor is exposed. |
| Depth-zero failure branch | After whitespace and an accepted opening bracket, mode zero with initial depth zero reaches the observed failure call before decrement. The source returns a chosen branch classification; it does not emulate the failure callee, assert it cannot return, or mislabel this as the ordinary parser-error sentinel. |
| Ordering-invariant failure branch | The provider completed a valid list, but the credited strict ordering predicate is false. Native ordering reaches its failure call/UD2 route instead of returning parser sentinel T. The source exposes that distinction without executing a trap. |
| Host capacity refusal | The source cannot represent/reserve the needed vector size, or the next append would exceed the already proved normal native capacity domain. This is an explicit safe-host resource policy, not a recovered native allocator-error result. |
| Host allocation failure | Actual fallible allocation/reservation by the source fails. This is a source resource outcome, not native OOM equivalence or a supplied fake allocator result. |

Depth checks occur only after the native opening-byte check. Thus raw depth
zero does not turn an empty input or an invalid opening byte into a depth-zero
failure classification. Mode nonzero bypasses both depth checks for every
depth. In mode zero, depth 2..255 is decremented and restored on the admitted
ordinary completion paths under the proof's helper-preservation premises.
The interface does not expose a general mutable parser-depth field; the
depth-one observation records its specifically proved transition.

Only Parsed exposes consumption. No failure outcome includes an exact native
error cursor, diagnostic string, pointer identity, resumable parser object or
native capacity/pointer pair. Parse/admission precedence is preserved by completing canonical-list
admission before ordering; this does not simulate the native provider's
error-side terminal behavior. Opaque error-message selection
and decoration are not fabricated as public diagnostic classes.

## Logical admission versus native ordinary-return correspondence

The proof closes the numeric envelope, not floating conversion. The exponent
helper `0x1d76760`, integer-overflow slot
`0x64e1340 -> 0x5c51b90`, and fraction-overflow slot
`0x64e1338 -> 0x5c52460` lead to outer tags zero or three; neither is an accepted
integer in this element consumer. Negative spellings also cannot produce an
accepted value. The source may therefore reject those spellings in this chosen
value projection without implementing or replacing their floating calculation.

This establishes non-admission, not universal native ordinary-error return.
The full classification body has a checked fraction-counter path at
`0x1d75fe3..0x1d75fe5` leading to a failure call at `0x1d761d5`; sufficiently
long fraction processing is not justified as an ordinary parser-error result.
Termination and cursor effects inside the opaque exponent/overflow helpers
are also unproved. Their non-admission does not establish that they return.

The source implements a total chosen admission policy for finite valid input
slices, subject to its explicit host resource outcomes. The native ordinary-
return correspondence is narrower: when native processing remains on the
admitted ordinary normal-return paths with the stated preservation and
native allocation premises, **and the own source passes its checked capacity
admission and all required fallible reservations succeed**, successful
values/consumption agree, and a native ordinary rejection maps to the chosen
NotAdmitted or depth-one observation. If native succeeds while the own host
cannot reserve storage, the source instead reports its explicit host resource
outcome; no successful-value correspondence or native allocation failure is
asserted for that run.
For a NotAdmitted source result, no reverse implication of native normal
termination is made. Other native numeric failure paths are not promoted to
one of the separately exposed depth/order branch observations.

No exact cursor movement, timing or error payload is asserted on non-success.
An implementation must not install fabricated numeric/error callbacks or
infer native cursor positions from its own simpler rejection path. If an
exact resumable error-state or complete failure-route contract becomes
required, those helpers, checked-counter routes and downstream error
construction must first be closed; this proposal does not satisfy that
stronger contract.

Ordinary error factories, especially `0x1d75420`, are assumed to return nonzero
valid readable error objects. The closer forwards the factory result unchanged;
allowing zero could make an invalid delimiter appear complete. Related type
and decoration boundaries include `0x1d76fd0`, `0x1d77b20`, the element type
error slots `0x64e0900/0x64e0910`, and disposer `0x1daeb80`. Their complete
semantics remain outside the value projection. No original diagnostic labels
are assigned to their raw class arguments.

## Storage and existing-ring integration

The native successful construction establishes initialized words only in
`P[0..N)`, with H=0, N<=C and C either zero or a power of two from 4 through
2^59. Unused allocation slots are not proved initialized. The current unsafe
ring function documents a stronger input precondition: capacity initialized
u64 words. Passing native C directly when N<C would fail that documented
contract even though the current implementation only reads count words.

Use the existing function through a private safe slice adapter with storage
from the source vector, capacity=N, head=0 and count=N. All N words are
initialized. For N=0/1 the function returns before a value comparison; for
N>=2 it reads precisely neighboring indices 0 through N-1. The predicate is
therefore the same as the native H=0, C>=N case. This is logical slice
compatibility, not migration of native C/P/H/N or a source-layout claim. No
change to the existing nonce-ring crate or its evidence packet is needed.

Source reservation must be genuinely fallible. Resource failure is separate
from parser rejection and ordering failure. Do not invent a fixed success
allocator, fake original addresses or original allocation/free callbacks.
Before an append, the established normal-domain bound and host size checks
must prevent overflow. The largest successful native capacity is 2^59; its
next doubling is outside the proof's ordinary successful domain. Recognizing
that boundary as Host capacity refusal adds no new native failure theorem and
does not take over PR #2127. Native capacity growth and source Vec allocation
policy are not required to be byte-for-byte or callback-for-callback identical.

## Native premises and limitations

The relation to captured code remains conditional on ordinary x86-64 behavior,
valid disjoint input/context/output/stack storage, immutable input, representable
arithmetic, no concurrency or asynchronous transfer, and ordinary ABI/callee
preservation. Numeric/error helpers preserve live ring state, input backing
bytes, mode/depth and caller prefix outside designated effects. Their normal
returns initialize consumed result fields. Allocation returns valid requested
storage and preserves initialized prefixes. No nonzero pointer is treated as
proof of validity. Cleanup instructions establish requests, not actual freeing.

Allocation failure, exceptions, unwinder action/type interpretation, arbitrary
helper clobbers, original parser/error ABI, complete callbacks, original
compiler identity, first-field decoding at `0x1e3e180`, public nonce policy and
whole-program reachability are not reconstructed. Only the named depth-zero and ordering routes receive separate chosen
failure-branch observations. Depth-zero identifies reaching the observed
failure call, whose normal-return behavior remains unknown. Other numeric
failure paths and unclosed helper termination can lie behind NotAdmitted;
no complete taxonomy or behavior of those routes is claimed. The component
must not be described as whole-call,
whole-parser-state or whole-node equivalence.

## Qualification status

The implementation must preserve every premise and limitation above. Frozen
inputs and expectations are maintained outside the input-only client. Actual
source builds, component tests, two-profile output comparisons and compiled
source controls require their own recorded results; this contract implies
none of those results. Linux execution, allocator-failure testing, native ABI
and error-state equivalence, byte equality and whole-node completion are not
claimed. Existing native/provider and ring evidence retains its original
credit and unresolved boundaries.
