# Independent pre-execution Rust source review

No actionable discrepancy was found in the complete reviewed `selected.rs`
SHA25643195ed0e6a44b34077729c1d80f35bf6dc3f22abb9ae67d428cd2172e1c1647
and the exact library integration. This is a source/effects review, not a
compiler result, test pass, native runtime comparison or publication approval.
The fixture transcriber and generated tests still require separate review.

The review read the complete431-line module, full lib.rs and source request,
the accepted native proof and the exact host policy/hand-authored fixtures.
All source-request pins and fixture-freeze entries were checked. The original
weighted_gate and embedded test block remain byte-exact; lib.rs only appends
the documented selected module declaration. target-smoke.tsv is unchanged.

## Admission and safety reasoning

- Lines112..183 maintain distinct whole-arena passes in the frozen order:
  Shape, Bounds, Links, Topology, Height, Representation. Shape's short-circuit
  bounds occupancy before `len()+1`; Bounds precedes every indexed parent or
  child access. Links uses `.get(parent_edge)` and exact reciprocal edges,
  rejecting repeated/shared children. The selected root has no parent and
  every other node has one.
- `depth` at101..109 permits at most N-1 edges to reach root and terminates
  with a refusal on cycles. The whole-arena pass ensures that disconnected
  reciprocal cycles cannot remain hidden. Equal leaf depth is checked only
  after connectivity. Zero-key internal nodes with one child are admitted.
- Representation uses checked total usize addition then u64 conversion and
  checked key/child-offset arithmetic. Shape already limits map/key payloads
  to11 and children to12; therefore child extents are at most416/328 and map
  weight end8+8*n is at most96. Not separately testing those constant implied
  inequalities is not a gap. Native base-address/nonalias conditions remain
  relational premises; the source neither accepts nor dereferences native
  pointers.
- Flat constructor236..257 checks Bounds before Representation and MapOrder.
  A zero capacity requires head=count0; positive capacity requires canonical
  head even when count0. Checked cap*32<=isize::MAX bounds translated offsets,
  while checked head+count protects all uses of `at`. Only active logical keys
  are inspected for order. Inactive storage is not silently made meaningful.
- TreeMapView299..310 checks complete structural map order after shared
  admission; KeyTreeView354..361 has no key sorting or uniqueness rule.
  All validated view/cursor fields are private and borrow plain immutable
  arrays/slices. Public raw node descriptors cannot mutate those slices while
  a safe view remains live. There is no alternate unchecked constructor.

## Traversal and lookup correspondence

`Walk`193..226 uses the actual tree. Its fresh state descends child0 to a leaf.
A key position at a leaf prepares index+1; a key in an internal node prepares
the leftmost leaf in child[index+1] before yielding the internal key itself.
On exhaustion the recorded reciprocal parent edge selects the next ancestor
separator, or continues ascending. Empty leaves/internal nodes use the same
rules. The admitted finite topology rules out an infinite leftmost descent
and the reciprocal-tree invariant gives every occurrence exactly one yield.
No injected sequence or weight callback replaces this traversal.

`segment_weight`269..273 chooses the final <= query candidate in the selected
sorted segment, then checks equality. For query below the first entry it
returns None; this agrees with the native found/missing projection even though
the native also constructs an unused insertion index. Flat lookup275..288
performs the physical-zero seam equality shortcut before selecting a segment.
It retains both duplicate behaviors and handles a second span of length1.

Tree lookup313..329 selects the first entry>=query in each reached node and
returns immediately on equality. Otherwise it takes child[index], with an
absent child denoting a leaf miss. Thus a root equality shadows equal child
entries, and the first equal in one node wins. Finite validated topology
supplies termination without a separate loop budget; its derived height is
the native exact-height premise. An empty internal node selects child0.

## Fold result and observable state

`next_key`390..401 returns immediately on remaining0, preserving last. For
positive remaining it decrements exactly once, advances the actual walker and
records the selected occurrence before returning a borrowed key. The `.expect`
is unreachable under the constructed total-count/topology invariant; it is
not a claimed native malformed-state outcome.

At414..430 the fold starts sum and consumed at0 each call. It consumes a key
before lookup, including misses, and increments consumed for that occurrence.
`overflowing_add` preserves the low64 result before returning Overflow;
there is no saturating/prior-sum substitution or post-carry prefetch. Consumed
cannot overflow because at most the initial u64 remaining count can yield.
Exhausted calls produce Complete0/consumed0 and retain last, matching the added
A05 third call. The public interface exposes only remaining and last_yielded;
there is no extra next/peek or native physical-cursor API.

The reviewed invariants support the frozen seam/root duplicate cases,
zero-key chain cases, unsorted/repeated K cases, and A05/K02 continuations.
This is manual source reasoning, not execution of those cases.

## Effects and remaining gate

The new module imports only core::cmp::Ordering and uses ordinary safe integer,
array and slice operations. No unsafe, allocator, I/O, network, filesystem,
foreign-call, inline-assembly, dynamic loader, native target address or expected
data access is present. Direct lib.rs inclusion adds only this module; the
existing cfg(test) block reads the fixed local TSV at compile time and was
not run here. No Cargo graph/build.rs/hooks are introduced.

Root still owns review/admission of the literal fixture transcriber, generated
test source, exact compiler commands and all actual qualification. This worker
ran no Rust, formatter, target, project script, reference model or tests.

## EXPAND

Review the transcriber as a literal-to-Rust projection with no expectation
calculation, then inspect the complete generated tests and linkage before
compilation. Preserve the original fixture and source identities if any later
execution reveals a real issue; report failures without relabeling them.
