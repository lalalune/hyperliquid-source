# Complete map relation, split and cleanup proof

This proves a finite map relation under CONTRACT.md's explicit memory/call
premises. It does not assume a library type name or an opaque insertion helper
that already implements a map. All three fresh map readers have the same key
and active-value representation, but different complete code bodies and cleanup
paths remain bound separately.

## Node representation and search

The three full insertion bodies are 493ded0..493e1ba, 4939020..493930a and
49300b0..493039a, each 746 bytes. The first is used for addresses below. Their
instruction-relative control layout and all memory operations agree; their
rel32/RIP operands resolve to the same shared/helper/import targets. Full raw
bodies are admitted separately, not replaced with a name-based alias.

A leaf allocation is 0x400 bytes; an internal allocation is 0x460. Parent pointer
is +0, 11 value slots are +8+72*i, 11 key slots are +0x320+20*i, parent edge index
is u16 at +0x3fc, key count u16 at +0x3fe. Internal child pointers are the 12 slots
+0x400+8*i. Each key is exactly 20 initialized bytes. A logical signature has
8 little-endian decoded u64 values and one arbitrary byte; seven stored padding
bytes in its 72-byte slot are never observed by this contract.

An empty map is root=0, length=0; height is inactive. Nonempty invariants:
strictly increasing unsigned lexicographic keys within each node, unique keys
globally, each internal node has n+1 children covering precisely its n+1 search
gaps, all leaves have the indicated common depth, parent/edge links agree,
nonroot key counts are 5..11, root count 1..11, and map length is the sum of node
key counts. Every live span is valid/nonwrapping/disjoint except explicit move
ranges. Allocation frames preserve every existing span and the escaped Reader.

At493df07 count is loaded; RBX starts -1, R15 starts0x320 and R14 starts node-0x40.
The loop compares the new20-byte key against key[i] by memcmp493df58, reduces
its i32 sign to -1/0/1 (493df5e..6b), and advances value address by72 and index by1.
Strictly positive repeats. Equality reaches493dfb2 with the matching value
slot: old72bytes are copied to the optional result, then all72bytes of the new
value replace it (493dfe2..e00c), with no length increment. The old key remains;
it is byte-equal to the new key. Old/new values own no heap objects, so ignoring
the returned old inline value requires no destructor callback assumption.

The first negative comparison or exhausted node identifies the unique gap i.
If height>0,493df9a..dfad descends child[i] and subtracts height1. If height0,
search stops at that leaf and gap. Bounds i in0..n and finite common depth ensure
termination. The helper receives only a vacant leaf gap; it never compares or
replaces existing keys. Fresh-root493e0da..e171 allocates0x400, installs parent0,
count0/rootheight0, writes key/value slot0, increments count to1 and map length1.
Allocation failure and assertions are explicit excluded paths, not inferred
nonreturning functions. The bounds guard count<11 succeeds because count=0.

## Nonfull leaf insertion

At42179a0..79f9 the selected leaf's count n is tested against11. For n<11,
4217a2c..7ab3 moves suffix keys i..n-1 right by20 and values right by72, using
memmove with exact `(n-i)*20` and `(n-i)*72` lengths. If i=n those moves are
skipped. The new key/value is written to i, and count becomes n+1 at4217b03.
This is precisely sequence insertion, preserving paired keys and values,
strict order and all other nodes. Return421873f describes the inserted value
handle; callers ignore it and increment map length once at493e171. No index
or count arithmetic can overflow for 0<=i<=n<=10.

## Full leaf split

For n=11, the old promoted pivot p, chosen side and new-side gap j are:

| Old gap i | p | Side | j |
| --- | ---: | --- | ---: |
| 0..4 | 4 | old left | i |
| 5 | 5 | old left | 5 |
| 6 | 5 | new right | 0 |
| 7..11 | 6 | new right | i-7 |

The exact selection is42179fd..7b59. A fresh leaf is allocated at4217b62.
4217b8d..7c7e saves the old key/value at p, copies old suffix p+1..10 into the
new right node, sets right count10-p and old countp. The copy byte lengths are
20*(10-p) and72*(10-p); these source/destination spans are disjoint. The guard
10-p<12 succeeds for p in4..6.4217cf4..7dfb chooses the table's side and inserts
the new pair using the same suffix moves, then stores the selected count+1.
Both resulting child counts are5/6 or6/5. Inorder concatenation
`left ++ [old pivot] ++ right` equals insertion into the original 11 pairs at i.
Neither active value bytes nor key bytes are dropped, duplicated or reordered.
The promoted pivot owns only inline data; the old slot beyond reduced count is
inactive and never interpreted as another live owner.

## Full parent cascade and internal child edges

The pending record consists of old left node L, promoted pair K,V and fresh
right node R. At4217e59/7ec7 the left node's parent pointer and its parent-edge
index identify the only parent gap where that record belongs. The preserved
height comparison4217edb checks the invariant; it is not a new input constraint.

If parent count<11,4218523..873a inserts K,V at edge index i; key/value suffix
moves match the leaf proof. It moves the old child suffix i+1..n right one slot,
then stores R at child[i+1] (4218672) and count n+1. All shifted/new children have
parent and edge indices rewritten (421868a..8738), including the scalar remainder
and four-at-a-time loops. Left child[i] remains L. The unrolled loop covers exactly
the same half-open range i+1..n+1; no child pointer outside the initialized range
is accessed. This preserves the inorder relation and common subtree depth.

If parent count=11,4217f0b..7f60 uses exactly the leaf split pivot/side/gap table
for the pending gap i. Allocation at4217f65 requests0x460.4217f92..8097 saves its
promoted pair, copies paired key/value suffix and reduces counts. The right
child suffix p+1..11 (10-p+1 child pointers) is copied at421813f;4218150..8174
repairs all those children's parent/indices. The arithmetic checks at421810b
and421811c follow from old count11 and right count10-p.

42181d6..8347 then inserts the pending K,V and R into the selected half, shifting
its key/value/child suffix and repairing every changed child link in4218355..83f8.
The newly promoted old parent pair and new right internal node become the next
pending record.4217e70 repeats at the old parent's parent. Each iteration climbs
one existing parent and does not revisit a child. Thus at most the initial tree
height+1 splits occur, with exactly one fresh node per split.

When the parent pointer is null,42183ff..851e allocates a fresh internal root,
sets old root as child0, height+1, installs pending K,V at slot0 and R as child1,
sets both parent links/edge indices and root count1. Height comparison and count
checks follow from the maintained pending-record invariant. The optional return
handle identifies the original inserted leaf slot; map relation and length do
not depend on its concrete address. The insertion caller increments map length
exactly once, regardless of cascade depth. Duplicate replacement never reaches
that increment.

## Count, height and termination bounds

Every successfully decoded wire row consumes at least29 bytes:20-byte key,
eight one-byte scalar encodings and one raw byte. Therefore successful distinct
entries m <= completed rows <= input_length/29 <= (2^63-1)/29. Map length never
wraps u64. An internally created balanced tree of that many entries has height
well below64: each new nonroot child has at least5 keys, and each internal root
has at least2 subtrees. This bounds every stored height increment and traversal
counter. The initial wire count N may be u64 MAX; it is a remaining-row loop
counter, not an allocation length. If enabled its96*N reservation may fail; if
disabled, finite input guarantees a row read eventually fails before an
unbounded number of successful iterations. No extra count policy is attributed
to native code. Host allocation exhaustion remains outside correspondence.

## Ordinary error cleanup and owner separation

Map496ec70 and496f370 construct a destructive traversal on their accumulated map
and call494e540 until its returned node pointer is zero. Wrapper4900220 performs
the same loop for their LSDA cleanup;4908500 does so for the first complete map
of a failing product. Map496f030 calls49b5c50 directly on ordinary failure and
its LSDA landing path. These are complete bodies, not calls to an assumed
opaque collection destructor.

494e540 keeps front state at+0..+0x18 and remaining key count+0x40. With count>0
it decrements count, lazily descends child0 to the first leaf (494e576..60f),
and either advances the next leaf slot or crosses the separator to child[i+1]
and descends its left edge (494e631..67e/758..7cd). Exhausted nodes are freed
while climbing their saved parent/edge links (494e710..746); leaf size0x400,
internal size0x460. It returns the existing value handle without reading or
dropping any value payload. Since callers discard those inline values, there
is no hidden key/value callback. For remaining count0,494e689..89f clears the
front tag, descends an uninitialized front if needed, and frees the final
rightmost ancestor chain, returning zero. Root-null with nonzero remaining and
invalid front tags lead to the bound diagnostic/trap paths and are unreachable
from the proved insertion/count invariants.

49b5c50 inlines the same complete traversal: no root returns immediately;
positive map length counts inorder visits, frees exhausted descendants during
ascents, and finally frees the remaining ancestor chain. Its native wrapping
counter in49b5f16 selects0x400 only for the first leaf, then0x460 for ancestors;
this is bookkeeping, not arithmetic on input values. Both traversals free each
node exactly once: nodes are freed only after their final child/key visit,
and subsequent traversal uses the saved live parent link. By induction over
inorder position, already freed subtrees cannot be re-entered. No map pointer is
returned on decode failure. Allocator behavior/frame effects remain premises;
this proof does not promise cleanup if deallocation unwinds or fails.

Map reader error handlers preserve the active error in disjoint output before
cleanup. Product49784e0 cleans its already successful first map when its second
map fails; the second map has already cleaned its partial tree. Outer4674820
then frees its separately owned byte vector. The allocations are disjoint and
there is no double ownership of any map root across these stages. A successful
boxed three-record aggregate is created only after all three fixed records
succeed; its scalar/fixed local prefixes require no heap cleanup on early error.
LSDA metadata is retained separately; this ordinary-return proof does not claim
a complete unwind/runtime personality theorem.
