# One user's funding-worker values, node #94

This is a conditional value proof of the complete worker
`[0x3757610,0x375809a)` and its selected leaf caller
`[0x3766a10,0x3766ba4)`. It does not prove whole settlement, scheduling,
economic units, or the identity of an original source type. Addresses are linked
ELF VAs; node SHA-256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
`native/` retains seven complete FDEs, both native decoders, actual FDE/CIE
bytes, separate LSDA call-site records and complete structural CFG tables.
Context bodies are retained for dependencies, not counted as newly recovered
worker semantics. Every normal/exceptional decoded block is inventoried;
structural coverage alone is not a proof of dynamic reachability.

## Contract and premises

The worker receives output in RDI, captures in RSI, a 20-byte address at RDX,
and mutable per-user state at RCX. Captures hold five pointers at offsets
0,8,16,24,32: address-set descriptor, eligibility-bypass byte, 12 raw time
bytes, 96-byte-row descriptor, and u64-to-raw-binary64 rate map. User word0
is a signed balance; +8/+16/+24 are the position-tree root/height/count.
Position keys are u64, and each 64-byte value contains raw tag DWORD0,
signed local balance +8, signed size +16, and signed accumulators +24,+32,+40.
Other position bytes are unchanged by the worker's own stores.

The theorem requires valid, finite, stable native trees: strictly ordered unique
keys, node lengths at most 11, correct parent/edge/height links and exact item
counts. Every traversed pointer/load/store has its required extent, alignment
and lifetime. Address/metadata/rate/time inputs remain stable. The mutable
user/position/output/vector spans are disjoint from those inputs, each other,
the native stack and globals touched by opaque helpers. Distinct position
values do not alias. Descriptor arithmetic and native byte extents fit the
address space and signed allocation bound; no concurrency changes them.
The original cannot establish these premises merely by checking a root/count.

All external calls that the successful value path uses must return normally,
obey their machine ABI, preserve caller-owned stack/input/state outside their
declared effects, and preserve the floating-point control bits specified below.
Allocator contracts are stated separately; no behavior is inferred from names.
The theorem stops at worker return or the caller's immediate append boundary.
Later consumers, scheduler completeness and preservation after later opaque
calls are not part of it. Failures can follow earlier state updates; there is
no rollback claim and no successful value contract for an unwind or trap.

## Eligibility and tree traversal

At `375764a..3757651`, any nonzero bypass byte admits the worker. Otherwise
`3757d56..3757dfc` searches the address set. Its root/height are descriptor
+0/+8; each node has 20-byte keys at +8, u16 length at +0xe6, children
at +0xe8. The imported comparator's exact contract is a normal return whose
signed low32 result has the unsigned-byte lexicographic ordering of exactly
20 input bytes and no input mutation. Actual `GLOB_DAT` slot `576e488`,
symbol index 12, names `memcmp`; that binding is evidence, not the contract's
proof. The code sign-extends EAX and normalizes its sign, scans until the
first key not less than the address, returns on equality, or descends child
at that key index. An exhausted node selects its last child. Height zero
miss terminates. Null root misses. A miss writes only QWORD output+0x38=2;
other output bytes are inactive. It never reaches the mutation loop.

On admission, time is snapshotted as DWORD +0 and QWORD +4, metadata pointer
and row count come from descriptor +8/+16, and a fresh row vector is
(capacity,pointer,length)=(0,8,0). If root==0 OR count==0, it returns an empty
accepted result; under a well-formed tree this is exactly an empty tree.
The position-node layout follows its actual addressing: 11 contiguous
64-byte values at +0; parent pointer +0x2c0; 11 u64 keys +0x2c8;
u16 parent-edge +0x320, u16 length +0x322, and children +0x328.

`3757733..37578de` descends the leftmost child exactly H times: H mod8
single steps followed by groups of eight. The leaf index starts at zero.
At `375779a..3757926`, an unconsumed local index identifies the next item;
an exhausted node ascends parents until its child-edge is below the parent
length. The parent item at that edge is next. The ascent counter k is the
number of levels between this item and leaves. For k>0,
`375792f..37579b1` prepares the next cursor by descending the item's right
child then k-1 leftmost children, again in exact remainder/groups-of-eight
steps. Crucially RCX/RDX still identify the current parent item while
RBX/R14 identify the next leaf cursor. For k==0, `37579d0` increments the
current leaf index. The first path's root/height and subsequent cursor state
therefore enumerate the tree's in-order items exactly once. Empty leaves
take the ascent path. The exact remaining count decrements once per examined
item at `375771f`; its last item ends before another ascent. Too-large counts
or broken links can reach invariant-failure calls `3758022`/`375803a` and
are outside the well-formed theorem.

Rates use root/height +0/+8, u64 keys node+8, raw binary64 values +0x60,
u16 length +0xba and children +0xc0. The scan at `3757a09..3757a75` compares
unsigned keys, finds equality or descends the first greater-key child, with
last-child fallback and height-zero miss. Null/missing rates skip the item.
`UCOMISD` plus JNE/JP at `3757700..375771a` skips both signed zero rates;
unordered NaNs proceed. No size, price or time guard precedes this decision.

## Index, checked integer product and floating-point amount

Let a be the unsigned asset key, q=floor(a/10000), r=a mod10000.
The reciprocal sequence at `37577c6..37577e4` computes r exactly for all
u64 a. With M=0x346dc5d63886594b, M*10000=2^75+432. Writing a=10000q+r,
the residual 432q+M*r is nonnegative and less than 2^75 for
q<=1844674407370955 and r<=9999. Thus high64(M*a)>>11=q and the subtraction
is the ordinary remainder. The 96*r byte index is bounded by 959904.

The precise guard order is: rate present/nonzero; r<metadata_count;
position size!=0; metadata row's first signed word p>=0;
signed product n=p*size representable in i64. The bounds call is at
`3758062`; negative p and overflowing IMUL share `375802b`. Size zero still
requires an in-bounds metadata index, but does not read that metadata word.
The checked product n, including possible i64::MIN, is retained separately
from the amount. It is not the absolute position size or a proven monetary unit.

The floating-point contract requires SSE2 binary64 with round-to-nearest,
ties-to-even for CVTSI2SD and MULSD, DAZ=0, FTZ=0, and all six SSE exception
masks set: `(MXCSR & 0xffc0)==0x1f80` throughout this operation and returning
helpers. Status flags may change and are not outputs. No evidence here proves
that every real caller establishes these controls. Other rounding modes,
unmasked exceptions and flush modes are excluded rather than silently treated
as equivalent. Intel's architecture manual defines these control and instruction
semantics; the proof uses them as machine assumptions, not an emulator.

At `3757830` n is first rounded to binary64, THEN multiplied by the raw rate
at `3757835`, with a second binary64 rounding. It is not a single exact integer
times rate rounded only once. The magnitude-bit comparison against maximum
finite binary64 (`375783b..3757854`) sends any resulting NaN or infinity to
XMM1=+0. Finite values are clamped to [-2^63,+2^63] by the comparisons and
MAXSD/MINSD at `375785a..3757aa6`. Under the preceding finite test there is no
NaN operand-selection ambiguity in that clamp. CVTTSD2SI truncates toward
zero. For +2^63 the masked invalid conversion yields the indefinite integer,
then the comparison with 0x43dfffffffffffff (largest binary64 below +2^63)
selects i64::MAX. The final self-comparison preserves the integer on ordered
input. The equivalent amount is therefore:

- if the rounded multiply is nonfinite, m=0;
- if finite x>=+2^63, m=i64::MAX;
- if finite x<=-2^63, m=i64::MIN;
- otherwise m=trunc(x).

`3757adc..3757adf` rejects m==i64::MIN via `3758049` BEFORE the raw time
DWORD gate. Thus finite negative overflow rejects, whereas negative infinity
maps to zero and can emit a zero-amount row. NaN rates, including signaling
payloads under masked exceptions, preserve their original raw rate bytes in
the emitted row; only the multiplication result's class affects m. MOVSD
loads/stores and UCOMISD do not replace that saved rate with a canonical NaN.
The proof does not expose the multiplication's NaN payload or SSE status flags.

## Mutation order, diagnostics and emitted records

When the snapshotted raw time DWORD is zero, `3757aef` skips all state stores
and row emission, but all earlier index/product/amount rejection still applies.
No source-level time validity or meaning is inferred. Otherwise m!=MIN permits
exact negation. Raw position DWORD==1 selects its local balance at +8;
every other DWORD selects user word0. That selected balance is updated by
signed saturating subtraction of m. Then the position accumulators +24,+32,+40
are updated in that exact order by signed saturating addition of m. Later
operations use the state left by earlier positions; the user-balance register
is saved/restored across helpers and updated after a user-balance subtraction.

Every overflow first calls slot `5773190` with EDI=0 and a 20-byte descriptor
at `56f1cf8` for subtraction or `56f1c50` for addition; only after a normal
return does the saturated store occur. For addition, the wrapped result sign
selects MAX for positive overflow and MIN for negative overflow (SAR/XOR with
MIN); CMOVNO handles the recomputed nonoverflow result. For subtraction, the
wrapped subtraction's sign chooses MAX or MIN, followed by CMOVO. These are
integer flag identities, not a claim about an opaque helper's behavior.

Slot `5773190` binds `358dcd0`. Its complete body shows global initialization,
lock acquisition/release and a call to `3396b10`; its transitive effects are
unclosed. Required frame contract: it preserves all worker inputs, live row
bytes, the mutable balances/positions, caller stack locals and MXCSR controls,
apart from permitted ABI register clobbers. The descriptor is readable/stable;
normal return/liveness is a premise. We prove the ordered call requests and
post-return stores, not diagnostic delivery, counters, no deadlock, or a
transitive frame theorem. No source or value oracle may silently omit this limit.

After the four updates, capacity is checked and grown if needed. Then a 72-byte
row is stored in order: +0 u64 asset; +8 signed -m; +16 original signed size;
+24 original raw rate u64; +32 checked signed product n; +40 address20;
+60 raw time DWORD; +64 remaining raw time8. The row length increments last.
All 72 bytes are active. Allocation failure can therefore happen after state
changes. The successful theorem requires allocation success, not rollback.

## Row-vector growth and memory ownership

`32d6660` grows 72-byte elements, and `32d5cc0` grows the caller's 104-byte
elements. Both select C=max(2*old_capacity,4), request alignment8 and the exact
stride through `32d6740`, then on status!=1 store the returned pointer and C
without changing length. Under valid old byte extents, doubling cannot wrap.
The bridge rounds stride to alignment, checks full unsigned multiplication
overflow and `bytes<=2^63-alignment`, and records failure status1 otherwise.
For these inputs C>=4, alignment8 and bytes>=alignment: capacity0 uses slot
`576dfd8` with RDI=bytes; nonzero capacity uses `576e030` with RDI=old pointer,
RSI=bytes. The other alignment paths are completely inventoried but not used
by the selected calls. The bridge records status0 only for a nonnull pointer;
null records status1/alignment/bytes. Status1 reaches the wrapper's error call
via `576dfb8`, with no claimed normal continuation beyond its FDE.

Required allocator contract: successful fresh allocation returns a unique,
aligned, writable span of requested bytes; successful resize returns such a
span preserving the previous live prefix exactly, transfers its ownership,
and leaves all other input/state/stack spans and MXCSR controls unchanged.
No inference from allocator names proves this. Native capacity fits its signed
byte bound, length<=capacity, all initialized row bytes survive resize, and
record-count increment/stride arithmetic do not wrap. These premises establish
the append invariant by induction, including growth from (0,8,0). Reuse of a
pointer in place is permitted only for resizing its own allocation. No actual
allocation identity, global memory lifetime or eventual free is claimed.

## Summary and caller consumption

If no row was emitted, tag=0 and sum=0. Selected-maximum fields and padding
are inactive and may contain old stack/register values: no deterministic full
104-byte representation is claimed. For at least one row, tag=1. Start the sum
with row0's signed amount, then process rows in emitted order using signed
saturating addition of each amount. The actual sequence negates the current
row amount and subtracts it (`3757f91..3757ffc`), with subtraction diagnostic
calls on overflow before recomputation/store. Each row amount!=MIN follows
from m!=MIN and m<=MAX; the guards at `3757e23`/`3757f7e` also state this
invariant explicitly. Saturating aggregation is not reassociated.

For maximum selection the candidate is the UNSIGNED magnitude of row+32 n.
NEG/CMOVS at `3757e30..3757e3a` and `3757fa3..3757fa9` produce |n| in u64,
including 2^63 for n==MIN. JAE at `3757fb0` retains the existing candidate
on equality. Therefore the first emitted row with maximal |checked product|
wins. Its asset and 20-byte address are copied. This closes the old inferred
"size" label in #899 to an exact numeric product; it does not establish units.

Active output fields are address20 at +0, vector capacity +24, pointer +32,
length +40, signed sum +48, tag +56, and (tag1 only) selected asset +64,
unsigned magnitude +72 and selected address20 +80. Bytes +20..23 and +100..103
are padding/inactive. Rejection tag2 activates only its tag field.

The complete leaf caller iterates a supplied contiguous range of 16-byte
(address pointer,user pointer) pairs. Its endpoint must be reachable by exact
16-byte increments without wrap; writable users are mutually disjoint and
all lifetimes/frames above hold. It invokes the worker at `3766a93` using
the capture pointer reached through its environment. At `3766a98` it compares
only the low32 bits at worker output+56 with 2. Actual worker tags are 0/1/2.
Tag2 is skipped. For tag0/1 it grows its 104-byte vector if necessary and
copies the returned descriptor and result payload at `3766ad0..3766b14`.
The active value fields above transfer unchanged; copied inactive bytes are
not newly defined values. Ownership of the returned row vector moves into
that caller element on normal append. The loop increments its pair pointer
and writes back the output vector descriptor/environment. This proves the
selected finite supplied range, not how a scheduler obtains or partitions it.

The credited host `3703f20` constructs the five capture fields at
`3703f3c..3703f7e`: source object +0x158, +0x1a0, incoming RCX,
source+0x60, incoming R8. This is dataflow context only. The collection chain
and later 80-byte outer rows from #899 are not re-proved or assumed to be
104-byte worker rows. No whole-user-set/order/completeness claim follows.

## Exceptional structure and exclusions

`native/cfg.tsv` covers all decoded blocks including landing pads. Transfers
have conditional normal-return edges even for likely nonreturning calls;
LSDA landing metadata is separate and does not imply a normal CFG edge.
Worker panic/invariant calls end at UD2; the unwind-only suffix
`375806a..375809a` conditionally requests disposal of capacity*72 bytes via
`576e010` and calls `5660110`. Leaf cleanup `3766b66..3766ba4` conditionally
requests disposal of the just-produced row allocation, calls `385ee20` or
`3762490`, then resumes through `5660110`; double-unwind handling is opaque.
These requests do not prove actual frees, rollback, exception types or lifetime
closure. The allocator bridge and diagnostic contexts retain their full
branch/LSDA inventories with the same distinction.

This contribution cannot infer validity of arbitrary enum tags, prices, counts,
time words, or economic states from observed branches. Native node execution,
ABI equivalence, gas/latency, all-thread behavior, full settlement and all risk
component gates remain unclaimed. A future supplied-state Rust API may recover
these bounded value operations only after an independent exact-rational IEEE
oracle and source plan are frozen and reviewed.

## Prior work and ISA sources

- [#899](https://github.com/lalalune/hyperliquid-source/pull/899) and
  `RE-007-distribute-funding-94` recover surrounding consumption and leave this
  worker opaque. Their context credit remains; these bytes are not additive
  whole-component coverage. Closed, unmerged
  [#753](https://github.com/lalalune/hyperliquid-source/pull/753) bound worker
  bytes without this value theorem. #860 recovers the separate rate producer.
- Static collection/checker scaffolding is locally adapted from this project's
  MIT `RE-007-funding-sample-storage-94` packet. It imports only existing shared
  ELF/FDE parsers, not an unmerged packet at reproduction time. No unlicensed
  inferred source was copied or used as implementation authority.
- [Intel SDM](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf),
  Vol.1 SSE exception/control sections and Vol.2 CVTSI2SD, MULSD, UCOMISD,
  CVTTSD2SI, MAXSD/MINSD: architecture semantics underlying the explicit machine
  premises. [Intel FTZ/DAZ documentation](https://www.intel.com/content/www/us/en/docs/fortran-compiler/developer-guide-reference/2024-2/set-the-ftz-and-daz-flags.html)
  identifies these controls; this packet does not infer the running node's values.
