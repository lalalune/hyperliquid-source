# Supplied-book premium value contract

This additive phase connects the already-qualified impact walk to the complete
premium arithmetic and one selected producer record. It extends PR1422; it is
not another discovery or contribution count. The published original20 are bound
by `ORIGINAL-DISTRIBUTION.json` and remain byte-for-byte unchanged. In particular,
the original positive-target theorem is not widened.

## Supplied values and abstraction

The planned dependency-free operation borrows two ordered entry slices over
**one common slot slice/count**, and takes
`asset: u64`, `oracle: u64`, `target: u64`, `scale: u8`, `mode: u8`, and
`divide_by_100: bool`. These are already-selected values, not an implementation
of metadata lookup, override hashing, membership construction or scheduling.
`asset` is echoed into one record. `target` is the selected override if present,
otherwise the native default; an override containing zero is not absence.
`divide_by_100` is the result of the actual selected-set search.

The two native calls keep the same RDI book/slab; only the tree pointer changes
from book+80 to book+98 hex. The API therefore has no separate per-side slab
count. Both sequences may refer to any common slot, including the same slot.
Its logical fields are:

| Logical field | Exact native role |
| --- | --- |
| entry `key: i64` | qword key; its unsigned magnitude is the price |
| entry `active: u8` | only bit0 controls admission |
| entry `head: u64` | initial slab index |
| slot `tag: u32` | only the native dword participates in equality with2 |
| slot `quantity: u64` | qword at native slot+c8 |
| slot `continuation: u64` | full qword, zero/nonzero |
| slot `next: u64` | next index, tested only when continuation is nonzero |

The entries are the actual complete in-order sequence recovered by the original
tree proof. They are never sorted by the implementation. A zero native root or
zero count is represented by an empty sequence. For a nonempty native view,
truthful count, valid height/parent/child links and readable stable storage must
induce exactly this sequence. A fabricated sequence has mathematical meaning
but no asserted correspondence to an invalid native tree. Slab length is the one
common native count; all fields retain the widths above. Multiple entries in
either sequence may reuse slots. Slice storage is readable for its lifetime and Rust's ordinary
valid-reference conditions apply; no native ABI/layout identity is claimed.

## Evaluation and new policy boundaries

1. If scale is greater than6, return `InvalidScale`. This is new safe policy,
   corresponding to an excluded native failure corridor, not its panic payload.
2. If raw oracle is zero, return absence before reading target or either book.
   The scale gate still precedes this return, just as3750d42..3750d95 does.
3. On a nonzero oracle, target zero returns `ZeroTarget`. This is new policy
   outside the unchanged native positive-target theorem; the native zero-target
   function is not asserted to have one uniform ordinary outcome.
4. Compute first impact, then second impact. Only after both ordinary values
   exist, return absence if either is zero. A reached cyclic chain produces
   `CycleFirst` or `CycleSecond`, also new policy outside the native theorem.
5. Otherwise compute the formula for the mode byte (zero versus any nonzero),
   apply optional division by100, then the finite clamp. Return the active
   premium bits and both raw impact values.

Cycle checking is lazy and per reached chain. It must not reject an unused
entry, an unvisited link, a trailing slot after tag2, an index ignored because
continuation is zero, or a book skipped by oracle zero. At most `slots.len()`
distinct valid indices can be read before repetition; a source implementation
may use that finite visit budget rather than allocating a visited set. The
independent oracle uses a set. Valid terminating native chains never refuse.
An invalid initial head returns ordinary impact zero; an invalid later next
index ends the current chain with its accumulated quantity. These are not
cycle refusals. Inactive bit0 and zero accumulated quantity also return zero.

The two-impact order is a source-review invariant on ordinary admitted inputs.
The output-only value corpus cannot distinguish skipping the second ordinary
calculation after a zero first value. A `CycleSecond` policy case may distinguish
the chosen safe API policy, but is not evidence of native call-order equivalence
on cyclic inputs. Diagnostic requests, allocation effects, traps, timing,
unwinding and floating-point exception flags are not output effects of this API.

## Active result and selected record

An ordinary result contains either absence, or
`Premium { bits: u64, first_impact: u64, second_impact: u64 }`.
All three fields of `Premium` are active. Absence does not invent values for the
two native words which are inactive on that path. The associated selected
record is exactly `(asset, tag, payload)`:

| Ordinary result | tag | payload |
| --- | --- | --- |
| absence | 1 | original raw oracle u64, not a floating conversion |
| active premium | 0 | premium binary64 bits |

No record is returned on policy refusal. The operation can return a small
`Evaluation` value containing this result and its record, with no allocation.
It does not implement producer filtering, an entire returned stream, append
ownership, storage or any economics/live admission policy.

## Native correspondence premises

`PROOF.md` supplies the addressed bridge. It is conditional on the authenticated
node94 target, finite truthful tree/slab views, stable target and metadata,
nonwrapping readable native addresses, valid disjoint stack/output storage,
ordinary return of called opaque helpers and their stated frame contracts.
The selected metadata/book/oracle/override/set results must equal the supplied
values. Actual copy/allocation helpers are not inferred from names or hashes.
The arithmetic assumes nearest-even binary64 SSE operations, masked exceptions,
and DAZ=FTZ=0 throughout. CPU/MXCSR has not been measured. The value theorem
does not reconstruct units, a live market policy, tree/hash construction,
scheduler completeness, source types, original compiler or ABI.

Every active result on this domain is finite in[-0.5,0.5] and never negative
zero. Intermediate XOR may produce negative zero before the source+0 MAX.
NaN, infinity, arbitrary signed zero and arbitrary float operands are not
public inputs. A future implementation must not silently broaden this domain
or advertise a generic floating-point library.
