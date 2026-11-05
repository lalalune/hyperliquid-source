# Checked selected fold: pre-source host-domain policy

This fixes the safe constructor domain and refusal ordering left open in
the byte-exact credited design-v1 inputs. It does not implement a reference,
evaluate instructions or promise native malformed-input behavior. Status and
sum below are a chosen value projection, not a native ABI declaration.

## Immutable structures and observations

The real library continues to borrow safe slices and uses no allocator or
unsafe code. Literal fixture node IDs are dense array indexes; node `id=i`
occupies array slot i. Keys are exactly20 bytes. Map entries contain a key
and arbitrary u64 weight. Children contain node IDs, and each nonroot carries
one `(node, edge)` parent reference. Empty root=None requires an empty arena;
an empty leaf root is also valid. No constructor accepts externally injected
lookup results, weight sequences, iterator status, sum or remaining count.

Validated `FlatMapView` and `TreeMapView` constructors are separate from a
validated `KeyTreeView`. A fixture's overall preparation validates the map
first, then the key tree, then creates the fresh cursor; this fixture-preparation
order is host policy, not native execution order. Production callers can use
the independent constructors in their own order. Do not expose a combined
native constructor failure result or rollback claim.

Every fold call starts sum0 and returns status1 on exhaustion or status0 on
the first unsigned carry, with the low64 sum including that failing addition.
Its `consumed` counts all keys actually yielded by the cursor during that call,
including misses and the failing occurrence. The only public cursor
observations are `remaining` and `last_yielded={node,index}` (or None before
any yield). `last_yielded` persists across calls and is not reset by a later
zero-consumption call. No next/peek API or inactive raw cursor bytes are exposed.
Continuation tests prove the next occurrence through a further actual fold.

Fixture `weight` and result `sum` are canonical decimal strings to preserve
all u64 values without a JSON floating-number interpretation; array indexes,
head/count and counts in these small literal fixtures are exact JSON integers.
This fixture representation is test data, not an admitted stdin protocol.
All inputs are literal. Named map/tree pools only share full supplied data;
they do not supply expected per-key matches or weights to an implementation.

## Constructor refusal categories and precedence

The following ordered passes define the first reported category. Within one
category no individual bad field/node is returned, so no extra location-order
promise is required. A constructor either returns its immutable validated view
or one error; it never mutates the supplied structures or creates a cursor.
These are deliberately new safe-domain refusals, not observed native errors.

For `FlatMapView::new(rows,head,count)`:

1. **Bounds**: count<=capacity; capacity0 requires head=count=0; positive
   capacity requires head<capacity even for count0.
2. **Representation**: checked capacity*32<=isize::MAX. Together with the
   Bounds pass this ensures canonical head+index and stride32 offsets fit
   the64-bit correspondence and capacity cannot be the tree sentinel2^63.
   Actual native base-address plus span nonwrapping remains a relational
   premise: borrowed value rows do not expose original native addresses.
3. **MapOrder**: active logical keys are weakly nondecreasing under unsigned
   lexicographic20-byte comparison. Inactive physical slots are ignored.

For both tree constructors:

1. **Shape**: each occupancy<=11; a node has no children or exactly
   occupancy+1 children. No minimum occupancy is imposed. Zero-key internal
   nodes with a single child are valid conditional topology.
2. **Bounds**: every supplied root, child and parent node ID is in range.
3. **Links**: root=None iff the arena is empty; a present root has no parent;
   every other node has a parent; every child edge and stored parent edge are
   exact reciprocals. A supplied parent edge outside its parent's children
   slice is Links. Repeated/shared children fail this reciprocity pass.
4. **Topology**: every node's parent chain reaches the selected root in at
   most N-1 parent edges. This rejects disconnected cycles/orphans after the
   local reciprocal-link checks. The operation is finite even for bad input.
5. **Height**: all leaf depths from the root are equal. Height is computed,
   not supplied. Empty topology has height0 as a host convention.
6. **Representation**: checked total occupancy fits both u64 and usize.
   For occupancy n, key-node key spans end at8+20*n<=232 and internal child
   spans end at232+8*(n+1)<=328. Map-node key spans end at96+20*n<=320,
   weight spans at8+8*n<=320, and internal child spans end at320+8*(n+1)<=416.
   These are the native leaf/internal extents232/328 and320/416; the earlier
   Shape pass already ensures the tighter metadata-separated key bounds.
   Source offset/count calculations use checked arithmetic. No aggregate
   arena N*maximum-node-size allocation restriction is imposed. Actual native
   node base-address plus extent nonwrapping remains a relational premise,
   since borrowed value nodes are not original native-address objects. No
   enormous artificial runtime fixture is claimed for an allocation-impossible
   bound.
7. For map trees only, **MapOrder**: complete structural in-order keys are
   weakly nondecreasing. Equal keys in one node or different nodes are retained.
   Key trees have no sorting or uniqueness pass.

Validate in these passes, not one node at a time with a different accidental
cross-category precedence. An allocation-free O(N^2+K) parent-chain/structural
scan is acceptable as proposed in design-v1. No recursion requirement or
arbitrary topology truncation is introduced.

## Scope and revised case plan

The28 named positive cases are A01..A09, F01..F07, T01..T05, K01..K05,
U01..U02. K04 has two separately literal depth8/depth9 fixtures. A05 and K02
each contain a second fold call using the same advanced cursor. A05 also has
a third, already-exhausted call that preserves last_yielded. Therefore the
plan contains29 positive fixtures and32 fold observations; these are authored
counts, not executed qualification results. F07 exercises a wrapped second
span of length1, T04 a zero-entry internal map node, T05 map occupancy11.
U02's first19 bytes are explicitly zero. Constructor-refusal fixtures are
separate and are not included in native-corresponding positive counts.

Native coherence, finite valid backing spans, immutable keys/weights, frame
preservation and ordinary correct20-byte memcmp remain the accepted premises.
The independent native reviewer found no contradiction for zero-key chains;
this still does not establish that a producer creates them. No recovered set
uniqueness, allocator, malformed-state panic, outer policy or full-node claim.

## EXPAND

Independently hand-check the literal fixtures and refusal precedence before
any source admission. Test future Rust only against unchanged frozen values;
do not generate these expected values from that implementation or a native
instruction evaluator. Root owns the later authoring and execution decision.
