# Complete stored-triple proof

Target node #94 has SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete 106-byte leaf is `[0x1b26100,0x1b2616a)`, with 29
instructions, no callees and three return paths. RDI is a pointer to
three output qwords; RSI points to three input qwords: first node,
initial index and key. The output pointer is copied to RAX and retained
as the original return value. This API projects the three stored values,
not RAX's pointer value or its calling convention.

## Memory domain and safe map

A `Node` snapshot supplies an opaque nonzero ID, successor ID, and
unsigned words at original offsets 0xe4 and 0xe6. Successor zero means
null. IDs can retain observed pointer bits, but are never dereferenced
by Rust. A supplied map has unique nonzero IDs; synthetic IDs do not
claim that those numerical addresses are valid native pointers.

The target relation assumes stable readable input record/nodes and a
valid output area. A successful projection needs snapshots of every
node actually read, not every possible successor. An initial or later
stopping gate can make a missing later snapshot irrelevant. The API
prevalidates map uniqueness/nonzero IDs, then resolves only reached nodes.
`InvalidNodeMap` and `MissingNode(id)` are new information/admission
refusals, not recovered target errors, faults or returns.

The index and key are arbitrary u64 values and both words arbitrary u16
values. Finite maps can contain chains, unreachable nodes and cycles.
Volatile/concurrent mutation, pointer validity, actual output stores and
their post-call aliasing effects remain outside this value projection.
All target output stores follow the final reads, so output aliases do
not change the selected triple; they can change original input memory
after selection, which this read-only API does not reproduce.

## Exact three-path relation

Let v0 be the first node, i the initial index and k the full u64 key.
The entry `movzwl` promotes `word_e6(v0)` to u64. `cmp rsi,rdi` with
unsigned `jae` continues exactly when k>=word_e6(v0). Therefore:

1. If k<word_e6(v0), the three stored qwords are `[v0,i,k]`.
2. Otherwise follow successor edges. On each nonnull edge `v(j−1)->vj`,
   the index increments modulo 2^64. The previous node's word_e4 is
   loaded into ESI, zeroing the upper half of RSI. The 16-bit unsigned
   comparison continues exactly when `word_e4(v(j−1)) >= word_e6(vj)`.
   At the first strict failure the triple is
   `[vj,(i+j) mod 2^64,zero_extend(word_e4(v(j−1)))]`.
3. If vm has a null successor before any stopping edge, the triple is
   `[0,vm,(i+m) mod 2^64]`. The null edge does not increment the index.

The input key survives only path 1. A later stop's third qword is the
previous node's gate word, not the original key. Exhaustion's second
and third qwords are the last node and last index. The store order on
exhaustion is offsets 8,16,0; the returned array describes final qword
values and does not claim to perform those stores.

All relevant comparisons are unsigned. The initial comparison is full
64-bit; truncating a high key to 16 bits can incorrectly select path 1.
Later comparisons are unsigned16 and never signed i16. `INC RCX` wraps
at 2^64 and no later branch consumes its overflow flag. Rust's explicit
`wrapping_add(1)` therefore preserves the only counter arithmetic.

## Iterative Rust and the finite cycle bound

After the initial gate fails, the loop invariant is: `current` is the
node reached after j completed nonnull edges, index is `(i+j) mod 2^64`,
and every traversed edge has failed the strict stopping predicate.
A null successor returns path 3. A nonnull successor is resolved, the
index increments and the previous gate is compared with the successor's
word_e6. A strict failure returns path 2. Otherwise assigning current
to the successor preserves the invariant.

For an N-node map, N nonnull transitions produce N+1 node occurrences.
Some ID must repeat. Stable successor links make this a reachable cycle,
and each cycle edge, including its closing edge, has already been
tested without stopping. No future traversal can change an edge's
predicate. The index never controls a gate, so even counter wrapping
cannot make it stop later. Thus after N failed nonnull edges the
original walk would not return under the stated stable-memory premises.
The safe API returns `NonterminatingCycle`; this is explicitly a new
refusal, not an invented original stored triple.

Crucially, the gate on the Nth edge is tested before that refusal.
For a one-node self-cycle with e4=0, e6=1 and key=1, the initial gate
continues but the self-edge stops, producing `[node,i+1,0]`. Rejecting
the repeated ID before this edge's gate would be wrong. Similarly the
first return to the root of a longer cycle may be the stopping edge.
The initial key gate is never reapplied on such a revisit.

The Rust loop is bounded by `nodes.len()`. Slice validation/lookup uses
only safe iteration and an in-bounds `[..i]` prefix. It allocates nothing,
performs no pointer arithmetic, and all u64 index arithmetic is explicit
wrapping. An empty map fails root lookup before entering the loop. Its
linear lookups and map admission need O(N²) work in the worst case;
performance equivalence to the original pointer walk is not claimed.

## Independent orbit and first-barrier oracle

The oracle is frozen before Rust. After the initial gate it constructs
the entire functional-graph orbit independent of edge gate outcomes,
including the first cycle-closing edge. It records a null, missing-node
or repeat terminal; missing successors are recorded rather than raised
immediately. It then forms the list of all strict edge barriers and
selects the earliest by edge number. This permits an earlier barrier
to outrank a later missing node or cycle that the target never reaches.

If no barrier exists, a null terminal yields the last node and orbit
length minus one; a missing terminal yields the safe information
refusal; a repeated terminal yields the proved nontermination refusal.
The arithmetic uses unbounded integer indices followed by modulo 2^64,
independently of Rust's bounded loop and wrapping increments. No
register, flag, instruction or captured-code evaluator is used.

The native corpus includes every successor assignment on one through
three labeled nodes crossed with four gate-word pairs, plus u16 power,
sign and equality boundaries, longer chains/cycles, final closing-edge
stops, map permutations and unreachable/missing successors. These
finite cases support the general invariant and cycle proof, not a
claim to enumerate every finite graph.

## Static closure and remaining limits

The leaf body, six following padding bytes and eight preceding gap bytes
are pinned. Its FDE at `.eh_frame+0x2e56c` uses CIE0. The complete
957-byte caller `[0x25767b0,0x2576b6d)` has 213 decoded instructions and
its own zPLR CIE at `.eh_frame+0x2dc714`, reached by the actual backward
CIE pointer from FDE `+0x3eb2cc`. Both CIEs and both complete FDE records
are retained. This does not assume the caller shares the leaf's CIE.

The call at 0x2576999 is a decoded boundary; immediate setup supplies
RDI=R13 and RSI=R15. All 80,300 relocation records and all 70,370,352
.text bytes are scanned for naming addends/direct-e8 candidates, finding
zero naming relocations and this one direct site. Indirect references
and complete caller behavior, including exception handling, are not
closed. The leaf has no helper or constant-table dependencies. Node
identity/type, field meanings, ownership and wider caller purpose
remain unknown. No component gate or target-byte equivalence is claimed.
