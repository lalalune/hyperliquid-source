# Conditional native proof

Read CONTRACT first. GNU and LLVM decode the same complete byte partitions of
nine subject/helper FDEs and three full caller contexts. The collector binds
ELF/file mappings, FDE/CIE/backrefs/extents, raw instruction obligations, data
and every selected RIP/RELA reference. This authenticates the proof's premises;
it is not execution, an automatic equivalence proof or a proof that runtime
memory has the admitted shape. Calls are conservatively allowed to return in
CFG checks; no panic/noreturn behavior is invented to force dominance.

## 1. Key search and occupied entries

Main `44b8078..44b80d4` copies state+198, the supplied32-byte hash and tag1 to
a48-byte key. Bytes1..7 are inactive padding. It loads root/height at state+1d0/
1d8 and calls `42b91f0` only when root is nonzero. The full search has a separate
tag0 arm, exported but excluded from this operation's owned tag1 map relation.
At `42b9266..42b92a6`, it first compares the key tag, then round **unsigned**
(`seta/sbb`), then memcmp over exactly32bytes. Normalization yields -1/0/+1;
the scan continues only for +1, stops on equality, or selects the first greater
key's left child. Exhausting a node selects its final child. `42b92da..42b92f6`
decrements height and descends through child array+3d8. At height0, a miss
returns the vacant leaf/index handle; equality returns its node/index handle.
This is exact ordered lookup by induction on finite height, under comparator
and tree separation premises. The exported alternate arm is not silently used
to claim other-key semantics.

Main adapts the result to the entry helper. `495874d..495875a` recognizes an
occupied entry with tag2 and jumps directly to `495899c`. It makes no calls,
changes no row fields and returns `node+0x218+40*index`. Its return path is
checked independently by the conservative CFG. There is no timestamp refresh.

## 2. New rows and exact ownership

Vacant entry `495875f..4958855` retains the key/entry descriptor, requests a
registration log and stat4 under two separate lock scopes, then reads all12
event-time bytes, stores sent0 and initializes an empty reason tree (root0,
count0; inactive empty-tree height is not an active value). The timing of that
read matters: prior escaped event/key pointers are covered by the preservation
premise. It must not be inferred from an absence of explicit stores in main.

For an empty map, `49588f6..4958990` allocates0x3d8 bytes, initializes root-parent0,
count0, root height0, then writes the48-byte key and40-byte row. For a nonempty
vacant leaf, `4958886..49588d7` passes the exact same key and row to `41e1ea0`.
After either branch, `4958998` increments map cardinality once. The returned
handle is converted to the row pointer at `495899c..49589a4`. The helper moves
row bytes; it does not clone or free reason ownership on an ordinary path.
Existing rows retain their complete active values. Adequate fresh allocation
and valid ownership are explicit premises; raw native layout is not a Rust ABI.

## 3. General map insertion, including cascading splits

The complete `41e1ea0..41e3145` body is in scope. Leaf key/value widths are48/40,
key base0, value base+218, parent+210, parent index+3d0, count+3d2. Internal
children start+3d8, capacity12; leaf/internal allocation sizes are0x3d8/0x438.
All nodes have capacity11; a valid nonroot has5..11 keys, and all leaves have
equal height. Values and child spans are live, disjoint except intentional
in-node memmoves, and separated from inputs, stack, metadata and fresh nodes.

For count n<11 and insertion gap i in0..n, `41e1efa..41e2089` moves keys i..n
one48-byte slot right and values one40-byte slot right when necessary, writes
the new pair at i and increments node count. Thus its inorder pair sequence is
`old[:i] + [new] + old[i:]`. Key and value remain paired; insertion at the end
uses the same write block with zero suffix. The return handle names that pair.

For a full node, the branches at `41e1ed5..41e20a6` choose an **old-key** pivot:

| Gap i | Old pivot p | New pair destination |
|---|---:|---|
|0..4|4|left at i|
|5|5|left at5|
|6|5|right at0|
|7..11|6|right at i-7|

`41e2100..41e21e1` retains old pair p, moves the suffix p+1..10 to a fresh
right node and shrinks the old node to p keys. `41e223b..41e23aa` inserts the new
pair into the selected half using the same shift/write relation. Both resulting
nodes have5 or6 keys, and concatenating left, promoted old pair, right gives
the original ordered sequence with exactly one new pair. Original payload
ownership is moved, neither duplicated logically nor dropped. The saved handle
at stack+118/+b0/+10 identifies the **new** pair throughout upward propagation;
`41e2f1f..41e2f3b` returns that handle, not the promoted separator's row.

`41e24a2..41e2b0d` ascends via the old node's parent and stored child index. A
nonfull parent (`41e2cdd..41e2f18`) shifts its suffix keys/values plus children,
inserts the promoted pair at child index i and the new right edge at i+1,
increments count and repairs every affected child's parent/index. A full parent
uses the same pivot table (`41e2518..41e2576`), partitions pair and edge arrays,
repairs the copied suffix's child links (`41e2752..41e2788`), inserts the lower
separator/right edge (`41e27d3..41e2958`), repairs affected child links
(`41e2960..41e2a2f`), and repeats with its own old separator. The scalar/remainder
and four-child loops cover exactly each affected index once.

At a root split, `41e2b96..41e2cd0` allocates a fresh internal root, makes the old
root child0 and new right node child1 around the promoted pair, sets both parent
links/indices, and increments height once. Each ascent decreases remaining
parent depth, so a finite valid tree terminates at a nonfull parent or root.
The inorder induction proves map insertion for arbitrary admitted height,
including a full-root cascade. It does not leave generic insertion opaque.
The66 nonfull gaps and12 full-gap sequence/edge identities are checked with
symbolic objects by certificates.py; those finite identities supplement this
height induction rather than evaluating captured instructions. Panic and unwind
tails remain exported; no successful-call claim includes their execution.

## 4. General reason-set insertion

`492d4b0..492d638` searches byte keys at node+c, count+a, children+18. Bytes are
zero-extended before the comparison, so the sign instructions compare values
in0..255. Equal keys return1 without mutation. A miss allocates an empty24-byte
leaf or invokes complete `4235420..4235b88`, then increments cardinality once
and returns0. Main ignores that boolean. No reason outside0..255 is invented.

The generic reason inserter has the same capacity11 pivot table
(`423548a..42354e3` and `4235600..4235652`). Its key width is1 and values are
unit-like: no payload bytes need movement. Nonfull insertion is
`423543e..4235481`; leaf split/copy/insert is `42354e6..42355a3`; parent
split/edge-copy/repair is `42355d4..4235842`; root creation is
`423584a..42358de`; nonfull parent insertion/repair is `4235914..4235a43`.
Parent/index/count are+0/+8/+a; internal size0x78 contains12 pointers. The same
sequence/edge identities and height induction prove exact set union with the
new byte, not merely a leaf-only fixture. At most256 distinct reason keys exist.

## 5. Delay conversion for every binary64 input class

Main `44b820b..44b8219` selects the1.0 literal when option bit0 is clear.
Otherwise the supplied bits survive. `1459cb6` multiplies by the exact binary64
1e9 literal. Under nearest/ties-even with gradual underflow, a finite binary64 is exactly
`sign * significand * 2^power`; its product is integer
`significand*1000000000` times the same power. Rounding that integer at53
significand bits (or the minimum-subnormal quantum), with a tie increment iff
the retained integer is odd, is precisely the operation in corpus.delay_ns.
Rounding carry and product overflow are handled before signed conversion.

At `1459cbe..1459ce1`, the absolute product bits exceed the largest finite
encoding iff the product is infinity or NaN. In either case XMM1 remains+0.
This includes an initially finite delay whose multiplication overflows; it
does **not** saturate that overflow to i64. Any NaN sign/payload follows the
same zero class under the masked-exception premise. For finite products,
`1459ce3..1459d0d` clamps to[-2^63,+2^63]. `1459d11..1459d28` truncates and
repairs the positive2^63 endpoint to i64MAX; negative2^63 remains i64MIN.
Therefore the integer oracle's magnitude truncation/saturation agrees for all
finite/subnormal/zero/NaN/infinity classes. Sampled host IEEE checks only
challenge this derivation;13,216 examples are not called an all-bit proof.

The reciprocal M=0x112e0be826d694b3, shift90 gives division by1e9. Its positive
error `M*d-2^90=100875776` satisfies `error*2^63 < 2^90`; thus its rounding
error is less than one divisor unit for every i64 magnitude. Signed-high
product, arithmetic shift and sign correction give truncation toward zero.
`1459d4a..1459d64` makes the residual Euclidean: seconds=floor(ns/1e9),
nanos in0..999999999. This is a full-range inequality, not sampled division.

## 6. Time and calendar composition

On canonical non-leap-second input, `15206e0..152078d` normalizes signed seconds
and residual nanos, adds to second/nano, then borrows or carries one second.
Its leap-second branch is retained but outside the admitted subset. Additions
cannot overflow: the converted ns is i64, hence seconds magnitude is below
9.224e9; adding a valid second0..86399 is far below i64 limits, and signed nanos
stay strictly within i32. The reciprocal0x1845c8a0ce512957/2^77 divides by86400;
the certificate proves its signed range inequality. It returns remainder
second0..86399, nano0..999999999 and carry that is an integral multiple of86400.
`1459d7b..1459d95`'s much wider carry bound admits this entire delta range.
The day offset magnitude is at most106753, safely an i32.

For the calendar, let L(y)=1 exactly when4 divides y and either100 does not or
400 does. The401-byte table at250354 equals the number of leap years in[0,y)
for y=0..400; the400-byte table at2504e5 equals
`((days_before_year(y)+3) mod7)+1 + (0 if L(y) else8)`.
Both whole tables are compared to independently constructed Gregorian cycles,
not assumed from names. Canonical packed dates use these low-nibble flags.
Because146097 is divisible by7, this flag pattern repeats for negative years
with Euclidean400-year normalization. Signed packed-date order agrees with
calendar order on the admitted subset; the full524,286-year boundary relation
is checked separately from the closed-form day identity.

`151f873..151f8a0` first tries ordinal+day_offset in the same year using the
common/leap bit. Otherwise it computes Euclidean400-year cycle and within-cycle
day via the prefix table. The year reciprocal and the cycle-day reciprocal
have explicit sufficient error bounds in certificates.json. After normalization,
the day is0..146096. The multiplier/shift sequence at151f939..151f94e equals
floor(day/365) on this complete finite domain. At most one predecessor-year
correction gives the unique year/ordinal partition. All146097 cases are checked;
the manual decomposition reduces every admitted year and offset to that domain.
No representation is inferred from the helper name or an external Chrono source.

`151f9f9..151fa05` restricts a computed result to years-262143..262142 and the
final ordinal/flag guard enforces the canonical result. The same-year path
preserves the canonical flags. On admitted inputs all table accesses and
intermediate signed arithmetic are bounded; date overflow may return0 and
`1459dc8` takes a panic boundary. CONTRACT separates that from the planned new
DeadlineRange refusal. Thus, for an in-range deadline, the complete composition
is exact integer nanosecond addition on canonical Gregorian time.

PR1473 already owns a standalone date-add proof/source at this exact FDE.
This composition credits that prior work but imports/copies no unmerged source
or runtime dependency. The bridge and independent cycle oracle here are derived
from captured tables/instructions and elementary Gregorian arithmetic.

## 7. One-shot decision, frame and caller boundaries

Main always inserts reason at44b8206 before deadline formation44b824b. It compares
packed date signed, then second and nano unsigned; equality passes. It suppresses
only for time-before-deadline or sent byte1. On the admitted initialized boolean
domain, these are exactly the CONTRACT predicates. The admitted tree/row state
cannot change during the external log/lock/stat calls except the displayed
stores. This explicit frame includes already escaped row and key pointers.

Emission log44b82f5 and its lock release precede sent1 at44b830b. The second
lock scope/stat5/release precedes active result copies44b833f..44b835e. Failure,
panic or blocked lock operations do not yield a proved ordinary result.
Registration log/stat4 similarly precede new stamp initialization. We prove
the displayed ordered requests to these helpers and their required frame,
not their arbitrary internals, formatted output or runtime lock correctness.
The conservative CFG independently checks seven nonvacuous ordering facts.

Five decoded direct call sites are retained within complete caller FDEs:
commit44acbfd/44acc87/44ad05e select default and reasons1/0/2;
vote44ab377 merges explicit0.15s/reason3 or4; proposal44b570e explicitly selects
zero/reason5. The vote constant is the captured binary64 encoding, not an exact
rational0.15 input before multiplication. Each caller checks Held tag2 before
its subsequent actions. These demonstrate actual uses; they do not establish
complete caller control flow, all indirect callers, outbox readers or network
meaning. The original one-second commit outline belongs to merged PR951.

The proof concludes one exact abstract state step under its stated premises.
Finite expected histories, symbolic identities, corrupted native controls and
two decoder reproductions provide different checks of that proof; none execute
the captured program or remove the stated external-frame assumptions.
