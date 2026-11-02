# Conditional impact-to-premium relation

Read `CONTRACT.md` first. This is an additive proof for existing PR1422. The
original20 distribution, including the coordinator's original review, is bound
without mutation. The previous impact proof owns the tree/slab discovery and
positive-target theorem; prior #860 owns the premium formula context; #1502
owns the selected producer/storage context. This phase connects their value
boundaries and closes numeric details needed for a supplied-book implementation.
No captured instructions are executed or interpreted to produce expectations.

## 1. Evidence and premises

Target node94 SHA256 is
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete selected FDEs are impact3c027d0..3c02db8 (1512B),
premium3750ce0..37511c0 (1248B) and producer251c420..251c673 (595B).
Both native providers cover3355B/811 rows. `native/records.json`, CFG,
transfers and RIP tables retain every structural branch/call, exact FDE/CIE
and index link, and separate LSDA callsite metadata. The ordinary CFG includes
landing-pad instructions but does not turn LSDA records into normal edges or
claim exception reachability. Neither decoder proves semantics. Complete byte
agreement and independent PT_LOAD mapping support the manual proof below.

All ordinary-path addresses used below are linked ELF VAs. `spec.json` binds
the old impact anchors plus newly used premium/producer corridors,15 numeric
literal spans, and selected symbol-index-zero RELATIVE records. Every SHT_RELA
table is scanned for eight-byte overlap with those numeric spans; neither
`.rela.dyn` nor `.rela.plt` writes any of them. Opaque callee body identities
are identity evidence only. The complete bodies are freshly retained for a
standalone additive audit; they are not new discovery/byte credit.

Native inputs satisfy valid/stable/nonwrapping readable storage for every
access. Entry stack frames and writable return/output regions are disjoint from
that storage and from each other except for the explicitly passed result
buffer. At entry RSP=S, each selected body saves48 bytes of registers and
reserves its shown local region: impact58 hex bytes, premium/producer48 hex
bytes. Thus its own saved/local frame is[S-88hex,S) for impact and
[S-78hex,S) for premium/producer; each called function needs its own valid
additional lower frame. Return addresses at[S,S+8) and saved state remain valid. Indirect calls
use their exact bound slots. Called diagnostics/hash/growth/failure routines
are not assumed pure just because of names: for each claimed ordinary return,
the explicit live input, target, metadata, stack, output and callee-preserved
register values must be preserved except the designated result/growth region.
They must not alter the floating environment. No claim covers violating calls.

For premium's two impact calls, use the whole prior impact theorem, including
normal-return diagnostic preservation, and preserve the saved oracle vector,
selected target, metadata row, mode byte, first result across the second call,
and writable premium output. Scale is read before and after the calls; it must
be stable. The native hash result and valid probing path select exactly the
supplied target; the valid selected-set traversal yields exactly the supplied
membership. No general hash/table/allocator semantics are inferred.

For the producer projection, the selected asset is not skipped, both list
bounds pass, and its selected metadata/book/oracle inputs match the supplied
ones. If growth is called, require successful return with a disjoint valid
writable allocation for at least `(old_length+1)*24` bytes, exact preservation
of old initialized bytes and unrelated live frame/input values, and updated
vector pointer/capacity sufficient for the one write. This is a copy/allocation
contract, not a recovered allocator or failure guarantee. The value API emits
one record without performing native allocation. Exceptional cleanup, destructor
behavior and actual memory release are outside this projection.

The complete22 callsites fall into the following groups. The transfer table
retains each instruction and exact destination/slot; this table supplies the
semantic boundary rather than relying on a recovered symbol name.

| Sites | Exact target relation | Scope/premise |
| --- | --- | --- |
| impact3c02a97,b82,bbb,bff,c6c,d5b,d8d | slot5773190 ->358dcd0 | code0 diagnostic request; preserve the explicitly saved/restored live values, target, slabs, tree and frame; ordinary return conditional |
| impact3c02d32; premium37511a6 | slot576e8b8 ->4ee3b20 | optional failure/zero-oracle diagnostic; preserve output/frame and input values on ordinary return |
| impact3c02d44; premium3751165 | slot576e470 ->157a9f0 | invalid parent or metadata corridor excluded from ordinary theorem; no fabricated panic/error value |
| premium37511ba | slot576e150 ->157b520 | invalid scale corridor excluded; safe `InvalidScale` is separately chosen policy |
| premium3750dd6 | direct399c4a0 | supplied valid selected-target relation plus frame preservation; hash/seed/probe implementation not claimed |
| premium3750ec3,3750ed9 | direct3c027d0 | complete old impact theorem, same target and shared slab; retain first result across second call |
| producer251c586 | slot57745a8 ->3750ce0 | complete active/absent relation proved here |
| producer251c5da | slot57745b0 ->454e460 | successful exact-copy/allocation/frame contract above; not a recovered growth implementation |
| producer251c60f,251c61e | slot576dfc8 ->157b64f | excluded metadata-list bound failures |
| producer251c665 | slot576e010 ->54c8cb0 | exceptional cleanup request outside ordinary result claim; no assertion memory was freed |
| producer251c651,251c66e | direct PLT5660110 | exceptional path outside theorem; name/PLT entry is not an unwinding proof |

For each impact diagnostic, the old proof and native save/reload sequences
identify which caller-saved values are spilled around that call; do not assume
all caller-saved registers survive. The frame premise protects the live saved
bytes and the native callee-preserved registers. The universal T>0 proof below
excludes some overflow corridors, but their calls remain in this full census.

## 2. Complete ordered walk, using the unchanged prior theorem

Let U=2^64-1 and M=2^63-2. For this section T is stable and1<=T<=U.
The valid native tree's actual in-order sequence is supplied without re-sort.
The original full proof covers initial left descent, including its height
remainder/eight-step groups (3c02840..3c028d2), leaf length even on the first
leaf (3c028d2/3c028dd), parent ascent using+160/+1c0 (3c028f0..3c02917),
right-child selection+1d0 and left descent (3c02917..3c029e0), and leaf
increment (3c029e0). Count decreases once per selected level. Truthful finite
height/links/count make that sequence complete, including internal-node keys;
no source key-order convention is required. Null parent on required ascent
reaches the excluded failure helper/UD2 at3c02d3d.

Entry root or count zero returns0 before height use (3c027de..3c027ff).
For a selected key, NEG/CMOVS at3c029ec..3c02a02 gives unsigned magnitude
`p`, including i64MIN ->2^63 without a signed-absolute overflow. Bit0 must be
set and the initial head must be less than slab count (3c02a02..3c02a1e), or
ordinary result is0, under diagnostic-preservation premises. Slot address
uses stride248, tag comparison is a dword equal to2, quantity is+c8, full
qword continuation is+10 and next index+18 (3c02a30..3c02a56).

Tag2 stops before reading its quantity into the sum. Otherwise quantities add
with saturation atU; each unsigned carry requests the bound diagnostic and
then recomputes saturation (3c02a56..3c02ae0). With continuation zero the
next word is not followed. With continuation nonzero, an out-of-range later
next index terminates with the accumulated quantity. This differs from an
invalid initial head. Under finite reached-chain premises, quantity is exactly
`q=min(U,sum(reached non-tag2 quantities))`; nonnegative saturated addition is
associative, justifying the independent oracle's unbounded sum. q=0 returns0.

The entire unsigned128 product p*q is formed before any partial fill, and must
have high word0 and low word<=M (3c02af1..3c02b05). A low-word-only test or
testing only the eventual partial product is a different algorithm. For valid
levels let c=p*q. Write S for preceding accumulated cost and Q for preceding
saturated quantity. The invariant on every continuation is S<T, so that
preceding costs have not saturated. Candidate `min(U,S+c)` crosses iff exact
`S+c>=T`, since T<=U. If below T, continue with exact S+c and
`min(U,Q+q)` (3c02b05..3c02b50). If count exhausts, return0.

At the first crossing, S<T implies remainder R=T-S>0 and p>0: c=0 cannot
cross. The native32/64 divide selection at3c02c78 computes the same unsigned
`n=floor(R/p)`; its32-bit arm is selected only when both operands fit32 bits.
Since R<=p*q,0<=n<=q. Final A=S+p*n<=T; B=min(U,Q+n). The repeated product
cap and remaining-subtraction/final-cost saturation failure branches are
structurally retained but unreachable here: p*n<=p*q<=M, R>0 and A<=T<=U.
Candidate-cost and quantity saturation requests can be reached and retain
their normal-return frame premises. At3c02ccb the exact guard
`(B-1 mod2^64)>=A` returns0 unless1<=B<=A. On acceptance3c02cd8 returns
`floor(A/B)` using equivalent32/64 division. It is positive. Zero-price
levels may have contributed quantity before crossing; they are not discarded.

The independent oracle computes exact prefix sums and the first crossing,
rather than reproduce native running saturations/registers. It checks only
visited levels/chains. A set detects a repeated reached slot; planned source
may instead exhaust a per-chain slot-count budget. Both are new safe refusals
outside finite native chains. Reuse of a slot in another level is allowed.
Target0 is not assigned a native ordinary value: e.g. a first positive-q
zero-price level can reach division by0, whereas other paths return0. The
safe API excludes this nonzero-oracle domain explicitly. Earlier root/count
or other failures do not imply a uniform native zero-target behavior.

## 3. Selection, scale gate and oracle-zero order

3750cf4 reads the mode byte. 3750d01..3750d36 checks the asset's quotient
against metadata+30 and remainder against metadata+10, then selects the
48-byte row and scale byte+2a. The multiplier is346dc5d63886594b hex:
M0*10000=2^75+432. For x=10000q+r with0<=r<10000 and
q<=1844674407370955, `432q+M0*r<2^75`; hence
`high64(M0*x)>>11=q` for every u64 x. The subtraction is the ordinary
remainder, not a signed division. Metadata selection is an explicit API
boundary; this identity is context, not a new public map API.

The first scale check at3750d48 rejects values>=7 before oracle zero is tested.
For admitted scale s, D=10^(6-s), taken from584b08, is exactly represented
and lies in[1,10^6]. After the unsigned conversion proved below,
3750d84 divides by D. 3750d89..3750daa returns absence on zero before target
lookup or either impact call; only output+8 is written0. The raw oracle is
zero iff this scaled finite value is zero. Thus a valid-scale zero oracle
can bypass target0/cyclic/unused book state, but cannot bypass the scale gate.

With nonzero oracle,3750db4..3750eab selects an override if present, otherwise
tracker+b0; an existing override value0 is still selected. The finite valid
hash/probe result is supplied, not reimplemented. The first call at3750ec3
uses tree book+80, the second at3750ed9 tree book+98, both with the same stack
target and the same RDI book containing one slab pointer/count. Accordingly
the abstraction has one common slot slice for both entry sequences, with no
separate per-side count. Both trees may reference the same stable slot fields.
Only3750ede..3750eec tests either returned value. Any zero gives absence,
writing only output+8=0. Both-call order is a static/source-review invariant;
ordinary result bytes alone cannot prove evaluation of a discarded second
value. New cycle-policy outcomes do not extend native equivalence to cycles.

## 4. Both unsigned64-to-binary64 SIMD constructions

All arithmetic here is round-to-nearest ties-to-even binary64. Exceptions are
masked and DAZ=FTZ=0; no measured runtime setting is claimed. Let u=L+2^32H,
0<=L,H<2^32. Constant203e80 interleaves exponent dwords43300000/45300000.
The scalar-lane form (oracle3750d57..3750d76; gap impacts3750f2f..3750f84)
forms exact binary64 numbers `2^52+L` and `2^84+2^32H`. Subtracting the
two202ea0 biases yields exact L and2^32H. Their precision is at most32 bits,
so each result is representable; the close biased subtraction is exact. The
single final ADDSD is therefore precisely RN(u), including u>=2^63 and ties
above2^53. It is not a signed64 conversion.

The packed form at3750fe2..375101b puts each u into one lane, masks its low
32 bits, ORs bits4330000000000000, shifts its high32 and ORs bits
4530000000000000. Its high lane value subtracts exact constant
`2^84+2^52` (bits4530000000100000 at204c30), giving
`2^32H-2^52` exactly. This subtraction is between close positive numbers;
the result has at most32 significant bits after factoring2^32, including
negative H<2^20. Adding exact `2^52+L` cancels the bias algebraically and
rounds only the final u. Thus it also gives RN(u), not RN(high)+RN(low)
with an unaccounted extra error. Constants/routing/operation bytes are pinned;
neither construction relies merely on a mnemonic or high-level cast.

## 5. Exact operation order and universal finite domain

Write RN for one binary64 nearest-even rounding. Let
o=RN(RN(oracle)/D), a=RN(RN(first_impact)/D),
b=RN(RN(second_impact)/D). On the active path all are positive finite.
Mode nonzero (3750f88..3750fb6) computes:

```
t = RN(b-o); t = sign_bit_xor(t)
x = SSE_MAX(RN(a-o), +0)       # source operand +0 wins equality
y = SSE_MAX(t, +0)
v = RN(RN(x-y)/o)
```

The order of the b-o subtraction and sign XOR is retained. A zero subtraction
is+0 under nearest-even; XOR may create-0, then MAX with source+0 discards
that sign. x and y are nonnegative, and their exact cancellation rounds+0.
No algebraic reassociation replaces the individual rounded steps.

Mode zero (3751036..375108c) compares both scaled magnitudes with
bits7fdfffffffffffff before choosing addition order. On this domain both
are<=2^64, so the first arm always applies:

```
m = RN(RN(a+b)*0.5)
v = RN(RN(m/o) + (-1))
```

The half-each-then-add arm at375106a is retained structurally but is not a
public input case. If selected membership is true,37510fa performs one further RN(v/100), before the finite test and clamp.
3751123..375113b computes `MIN(+0.5, MAX(-0.5,v))`; both legacy SSE
instructions select their second operand on finite equality. No NaN policy
is needed for these admitted value inputs.

Here is a bound for every u64 input, not just the corpus. RN(u)<=2^64.
For positive u, RN(u)>=1. Since D<=10^6, every positive scaled value is
strictly greater than2^-20: even1/10^6 is separated from2^-20 by much more
than a rounding half-ulp: `(2^20-1000000)*2^53>1000000` proves
`1/1000000 > 2^-20+2^-73`, the midpoint above2^-20. The upper bound is2^64. Their nonzero binary64
values are multiples of2^-72. A nonzero rounded subtraction of such values
has magnitude at least2^-72; neither operand is subnormal. Gap selections
are bounded by2^64. Dividing their nonzero difference by o leaves magnitude
at least2^-137 and at most2^85 using conservative rounding bounds. Optional
division by100 leaves a nonzero result above2^-145. These are normal.

For the midpoint, sum<=2^65 and its half<=2^64. Dividing by o is finite,
positive, between2^-85 and2^85 with conservative margins. Subtraction of1
is either exact+0 or has magnitude at least2^-53 near1, and larger away
from1; division by100 remains normal. The scale conversions, additions,
subtractions, divisions and half multiplication therefore cannot produce
NaN, infinity, overflow or a nonzero subnormal. Every final zero is+0; a
negative nonzero result cannot underflow to-0. The finite guard always passes.
The active result is finite and lies in[-0.5,+0.5]. No generic float input
or alternate overflow-avoiding midpoint domain is claimed.

Primary ISA premises are Intel SDM Vol1, revision253665-080US June2023,
sections4.8 and10, [official volume](https://cdrdv2-public.intel.com/782149/253665-sdm-vol-1.pdf),
and Vol2B revision253667-084US June2024, legacy MAXSD/MAXPD and MINSD
operation/equality rules, [official volume](https://cdrdv2-public.intel.com/825757/253667-sdm-vol-2b.pdf).
These identify generic ISA semantics; they are not target CPU/MXCSR evidence,
latest-version claims or independent corroboration of recovered native logic.

## 6. Active output and one producer record

On success375113b writes premium bits at output+0, first impact at+8, second
impact at+10 hex. On absence3751148 with RBX=8 and RAX=0 writes only+8;
other words stay inactive. The producer's57745a8 relocation is exactly
RELATIVE type8, symbol index0, addend3750ce0. At251c58c XOR EBX makes the
entire tag word0. SETE from output+8=0 stores a byte for absence. Success
copies raw output bits to stack+28; absence251c5b0 copies original raw oracle
RBP, not its floating conversion. After optional preserved growth, MOV BL at
251c46a leaves upper tag bits zero;251c470/474/47f write asset, tag and raw
payload at offsets0/8/10 in the24-byte record. These are ordinary selected
record values under the allocation/copy frame contract in section1. No whole
producer traversal/order/completeness or final storage theorem is added here.

## 7. Proof and qualification limits

The portable checker authenticates bytes, literal/relocation roles, full native
partitions, FDE/CFG/LSDA metadata, original distribution and negative controls.
It does not evaluate captured instructions or mechanically prove these
semantics. Mathematical corpus expectations come from independent exact
prefix/filter arithmetic and Fraction/adjacent-representable rounding, before
production source exists. Cases and false-model witnesses are finite evidence,
not a universal proof. Source's eventual integer arithmetic needs its own
proof and review. Later compilation needs a separate gate. The scope excludes
source ownership/type recovery, economic units, live admission, all-asset
completion, cryptographic/transaction actions and active draft1460 ownership.
