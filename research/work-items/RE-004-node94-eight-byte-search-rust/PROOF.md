# Complete search-leaf proof on valid qword slices

Target: node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The full leaf is `[0x52ca970,0x52ca9e3)`, 115 bytes and 36 instructions.
The body has five conditional branches (`jb`, `jle`, `jae`, `jg`, `je`),
one unconditional `jmp`, three returns, and three internal NOPs. The old
packet's prose says six conditional branches; the retained actual bytes
and the new complete decode establish five. Thirteen external `int3`
bytes are padding. Nothing in the old packet is modified.

## Domain and initial fields

The target reads the low/high table pointers at descriptor offsets 0 and
8, and the u64 limit at offset 0x18. RSI is the u64 query. No field at
offset 0x10 is read, no memory is written, and no function is called.
The API supplies the table as `&[u64]` plus independent key and limit.

The admitted original memory interpretation is a stable, readable,
contiguous array of N qwords, with nonwrapping span `hi−lo = 8N < 2^63`.
On the supported 32/64-bit hosts, an ordinary valid Rust `[u64]` slice
satisfies this byte-size restriction. This is a projection of those
memory premises, not recovery of a source signature or original pointer
ABI. Invalid, negative, nonmultiple-of-eight or wrapping raw pointer
differences are excluded. Original behavior on those differences is not
replaced with an invented result. Volatile/concurrently changed memory
is also excluded. Every u64 key/limit and every entry ordering is admitted.

Under these premises the target's arithmetic `sar(span,3)` is exactly N.
No sign bit is set. The first branch is an unsigned `key < limit` branch
to the search. Its complement immediately returns `(N−1) mod 2^64`.
For N=0 this is `u64::MAX`, including key==limit==0. No entry is read on
this shortcut. Only when key<limit does `span <= 0` return zero for N=0.
The Rust checks `key >= limit` before its initially empty search interval,
preserving the order and the wrapping subtraction.

## Loop equivalence, bounds, and termination

For the search path with N>0, maintain `0 <= L < H <= N` and C=H−L.
At the original loop entry, RAX is `lo0+8L`, RDX=C and R8=lo0.
Since C is positive and below 2^63, SAR by one equals integer division
by two. The probe index is `P=L+floor(C/2)`, so `L <= P < H`.

If `entries[P] < key` unsigned, the target moves the low pointer to
`lo0+8(P+1)` and count to `H−P−1`. For positive count it repeats; for
zero it returns `(lo−lo0)/8 = P+1 = H`. Rust sets L=P+1 and either
repeats or exits with the same result.

If `entries[P] >= key`, the target replaces count by `floor(C/2)` and
retains L. With a nonzero midpoint this is H=P and the same next
interval. With midpoint zero, P=L, and the target immediately returns
L; Rust sets H=L and exits with L. Thus each branch preserves exactly
the target's next probe or final result, with no sortedness premise.

Both nonterminal interval lengths are strictly smaller than C. The two
possible new lengths are `floor(C/2)` and `C−floor(C/2)−1`; both are
nonnegative. Therefore the loop terminates for every table. `high-low`
cannot underflow, `low+(high-low)/2 < high <= N` cannot overflow, and
`mid+1 <= high` is safe. Every entry read is in bounds. No scaling or
pointer arithmetic is needed in Rust. At exit the raw search result is
in `[0,N]`, converting exactly from usize to u64 on the supported hosts.
The separate shortcut's only wrap is the explicitly preserved N=0 case.

For a nondecreasing table, the usual additional invariant holds: all
indices below L have entry<key, and all indices at or above H have
entry>=key. At L=H the result is exactly the number of entries<key,
including duplicate keys. This interpretation applies only to the search
path; the limit shortcut can override it.

An unsorted table need not return the first match. For `[0,0,0,1,0]`,
key=1 and limit=2, the target probes indices 2 and 4 and returns 5.
A linear first-match rule returns 3. Changing the midpoint from the
upper to lower middle can also change unsorted results while leaving
the sorted lower-bound interpretation intact. The native tests detect
both substitutions.

## Independent oracle: all terminal index intervals

The oracle is not another query-driven search. It recursively expands
the entire midpoint decision tree, including both children of every
internal node, before considering the query. It produces N+1 leaves,
one for each terminal index in `[0,N]`.

Each left edge contributes `key <= entries[P]`; each right edge
contributes `key > entries[P]`. Intersecting those constraints gives a
leaf interval `(A,B]`, where A is the maximum right-edge entry (or −1
if none) and B is the minimum left-edge entry (or `2^64−1` if none).
Empty intersections are retained as empty leaf intervals. Duplicate
and unsorted entries require no special case.

At every node the two child constraints partition the parent's key
interval into disjoint, exhaustive pieces. Induction to the leaves
therefore establishes that every u64 query belongs to exactly one
nonempty leaf interval. The oracle checks this property for every
fixture table by sorting nonempty intervals and checking exact
adjacency from −1 to `2^64−1`; then it linearly examines all leaves
to select the unique result. The limit shortcut is handled separately.
For sorted search cases a third, linear count of entries<key must agree.

This symbolic interval construction evaluates no captured instructions,
registers, architectural flags or emulated code. The source and all
expectations were frozen before Rust source was created. Native wrong
variants exercise the distinctions between this raw decision rule,
upper-bound search and linear first-match interpretation.

## Dependency and caller limits

The leaf has no external table constants, relocated constants or callees;
the table/limit are explicit runtime inputs. Full target identity, body,
CIE/FDE and padding are checked. The complete 131-byte caller FDE
`[0x52cab00,0x52cab83)` decodes to 39 instructions. Its call at 0x52cab17
is qualified as an instruction boundary, and the preceding RIP-relative
LEA supplies descriptor address 0x578e240. That address is in NOBITS
`.bss`, so the initialized table pointers and limit cannot be recovered
from file bytes here. This contribution invents none of those values.

The existing direct-e8 scan is repeated across all 70,370,352 .text
bytes, finding this one site; all 80,300 RELA records are checked for
absence of a naming addend. These scans do not constitute a complete
indirect-reference census. The caller's later counters, initialization,
meaning of the limit and source-level ownership remain unclaimed.

This proof concerns the complete leaf's returned value under the stated
memory projection. Original ABI, fault behavior outside the domain,
whole-program behavior and target machine-code identity remain open.
