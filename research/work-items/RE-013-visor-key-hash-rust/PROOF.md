# Conditional full-value proof

Only the authenticated Visor ELF with SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31` is the native subject. Addresses below are linked ELF VAs and ends are exclusive. The complete value graph is outer `0x626760..0x6268c0` (352 bytes / 90 rows) and feed `0x628d00..0x628ed7` (471 bytes / 141 rows). The outer's only calls, `0x6267b0` and `0x6267c7`, both target that feed. The feed has no call, indirect transfer or external dependency. Lookup `0x5d3220..0x5d3361` and caller `0x5b9070..0x5b92a6` are retained as full context for the selected uses, not new whole-body membership/parser theorems.

## Domain and frames

At outer entry let RDI=K, RSI=P, RDX=N and RSP=S. Require 0 <= N <= 2^63-1, an immutable readable 16-byte interval at K, and an immutable readable nonwrapping N-byte interval at P. A zero-length input causes no input read. The two immutable intervals may overlap each other. The actual little-endian qwords at K and K+8 are k0 and k1. Do not presume zero keys, a seed generator or a source-library type.

Require ordinary nonvolatile, race-free memory, immutable code/literal bytes and valid hardware call/return behavior. S mod16=8. After PUSH RBX and SUB RSP,0x60, the outer local base is B=S-104 and is 16-byte aligned. Its state H=B+16 occupies [B+16,B+88); the appended FF is the separate byte B+15. A feed call writes its return slot [B-8,B), and the feed PUSH RBX writes [B-16,B-8). Thus the combined writable/return interval is [S-120,S+8), with the original return word at [S,S+8). Inputs and image constants are disjoint from this interval. The state intentionally belongs to the outer frame, while its nested feed stack lies below B; no false requirement separates the state from its own outer frame.

Under these premises all shown arithmetic is ordinary 64-bit wrapping integer arithmetic, all shown loads/stores are valid, and the bounded loops below terminate. No allocator, libc or opaque callback is needed inside this value graph. The feed saves/restores RBX; the outer uses that preserved register to retain H. Other SysV callee-saved registers are untouched, and both RSP adjustments unwind exactly before RET. Scratch registers, flags, exact host memory-access trace and abnormal fault/interrupt behavior are outside the safe value API.

## Logical permutation

All words below are in Z/(2^64), and rot(x,r) is a 64-bit left rotation. For a logical tuple v=(v0,v1,v2,v3), define one permutation R by:

```
a = v0 + v1
b = rot(v1,13) XOR a
c = v2 + v3
d = rot(v3,16) XOR c
f = rot(a,32) + d
e = c + b
R(v) = (f, rot(b,17) XOR e, rot(e,32), rot(d,21) XOR f)
```

Define C(v,w) by first replacing v3 with v3 XOR w, applying R once, then replacing the resulting v0 with v0 XOR w. These are mathematical value definitions, not an instruction evaluator or inferred source implementation.

Actual native state memory order is `(v0,v2,v1,v3)` at H+0,+8,+16,+24. The feed's full-word blocks `0x628da1..0x628df5` and `0x628e20..0x628e63` bind the pre-XOR, add/rotate/XOR flow and post-XOR to C in this order. In the first block RCX/R11/R9/RAX carry v0/v1/v2/v3 after the shown loads; in the bulk loop RAX/R10/RCX/R11 carry that tuple. The stores restore the same memory order. The distinct register allocation does not change the defined permutation.

## Initialization and exact two-call input

The outer loads all 16 seed bytes at `0x626765`. PSHUFD0x44 duplicates k0 and PSHUFD0xee duplicates k1. The two actual 16-byte literal records are:

| Literal VA | Little-endian qwords |
| --- | --- |
| 0x6d380 | 0x736f6d6570736575, 0x6c7967656e657261 |
| 0x6cfd0 | 0x646f72616e646f6d, 0x7465646279746573 |

Consequently the initial logical tuple is
`(k0 XOR 0x736f6d6570736575, k1 XOR 0x646f72616e646f6d, k0 XOR 0x6c7967656e657261, k1 XOR 0x7465646279746573)`.
The original seed pair is also copied to H+32/+40; these words are not consumed by either feed or finalization and remain unchanged. The outer zeroes total length H+48, tail H+56 and buffered count H+64 at `0x626795..0x6267a8`.

At `0x6267b0` the feed receives the original RSI/RDX and H. After that return the outer writes exactly FF to B+15, sets RSI=B+15, EDX=1 and RDI=H, then calls at `0x6267c7`. This is always one additional byte, including when the original input already ends in FF; there is no NUL termination, UTF-8 test, trimming, counter suffix or name-specific branch.

## Feed invariant and bounded reads

A valid feed entry state consists of a logical tuple, an arbitrary wrapping total T, a buffered count q in0..7 and a tail whose only possibly nonzero bits are the low8*q bits. The selected outer first enters with T=q=tail=0. The invariant after each successful feed is: T increases by the supplied length modulo2^64; each newly completed little-endian eight-byte word is compressed once using C in order; q and tail represent exactly the remaining suffix; H+32/+40 are preserved. This lemma supports the outer's two calls, not a new public streaming interface.

`0x628d01` adds the incoming length to T. If q=0, `0x628d3d` initializes the consumed prefix cursor to0 and enters the complete-word phase. If q>0, `0x628d0e..0x628d21` computes gap=8-q and take=min(gap,n). Thus gap is1..7 and take is0..7. Prefix packing at `0x628d21..0x628d80` uses a four-byte load iff take>=4, then a two-byte load iff `(cursor OR1)<take`, and a last byte iff cursor<take. Cursor starts0 or4, becomes2 or6 after the optional two-byte load, and every load stays wholly inside the take-byte prefix. All byte shifts are at most48 before positioning the prefix at8*q; the final represented bytes fit within one64-bit word.

At `0x628d80..0x628d93`, OR with the old bounded tail forms precisely the concatenation of those bytes. If n<gap, the return at `0x628da0` leaves the tuple unchanged and writes q+n<=7 plus the new partial tail. This also covers n=0: no input read occurs. If n>=gap, the formed full word goes through C at `0x628da1..0x628df5`.

For the latter route let n-gap=8k+r with0<=r<=7. The bulk loop cursor begins at gap, while the comparison bound is8k (`0x628df5..0x628e06`). Although these coordinates differ, they give exactly k iterations: for1<=gap<=7, `gap+8j<8k` holds exactly for j=0..k-1. At exit cursor=gap+8k. For the fresh q=0 route, gap=0 and the same statement is immediate. Each load at `0x628e20` therefore reads one complete word wholly inside the original input, in order, and `0x628e5a` advances by8 without wrapping under the admitted span bound. The loop's tuple stores at `0x628e63..0x628e72` preserve C's result.

The final tail code `0x628e72..0x628ecd` uses the same four/two/one-byte decomposition for r. Its starting cursor is exactly the consumed prefix plus all complete words. It reads exactly r bytes, packs them little-endian with all higher bits zero, and stores tail and count at H+56/+64 before the RET at `0x628ed6`. Even after the earlier full-word prefix path, these stores replace its temporary full tail with the final suffix. No unvisited byte beyond the supplied span is needed.

The first outer call consequently represents the original input. On the second call, q=0 stores FF as a one-byte tail; q=1..6 takes the partial return with FF appended; q=7 forms and compresses a complete word, then stores tail=0,q=0. These cases establish exactly the byte sequence M=input||FF. They exclude the tempting simplification of merely OR-ing FF into a tail without compressing at q=7.

## Final block and full RAX

Let L=N+1, m=floor(L/8), r=L mod8, and let w0..w(m-1) be the consecutive complete little-endian qwords of M. Starting at the initialized tuple, apply C once to each wi. Let t be the little-endian r-byte suffix, with zero higher bits. The shifts/OR at `0x6267cc..0x6267da` form
`b = t OR ((L mod256)<<56)`.
Since r<=7, t has no bits in the high byte; this is exact concatenation rather than an overlapping arbitrary OR. Native total addition wraps modulo2^64; the final shift observes only its low byte. Under the selected N<=2^63-1 domain N+1 itself is representable, while all tuple additions still wrap.

`0x6267da..0x626824` applies C to b, then XORs the logical v2 with FF. The blocks `0x62682b..0x62685b` and `0x62685b..0x62688b` are two complete R rounds. The final block `0x62688b..0x6268ba` is an algebraically shortened third round followed by the four-word XOR.

For that third-round entry define a,b,c,d,e,f as in R above. XOR of the complete result is
`f XOR (rot(b,17) XOR e) XOR rot(e,32) XOR (rot(d,21) XOR f)`
`= rot(b,17) XOR e XOR rot(e,32) XOR rot(d,21)`.
The two f terms cancel. Therefore the omitted `rot(a,32)+d` computation does not remove a logical round. The native final RAX at `0x6268b7` is exactly this expression; it is a complete64-bit definition, not just a low-byte or low32 bound. The remaining epilogue only restores RSP/RBX and returns.

Thus the proposed API result is the XOR of the four words after three R rounds applied to the compressed final-block state with v2 XOR FF. All constants, seed order, little-endian block order, mandatory byte suffix, length-byte projection, wrapping additions and final cancellation are necessary parts of the relation.

## Actual uses and deliberate table boundary

The full lookup context loads its optional cached candidate at object+0x48 and can return true before consulting the main table count. Only after that route fails and object+0x30 is nonzero does `0x5d3269..0x5d3278` pass seed=object+0x38, the preserved query pointer and its length to the outer. The returned RAX is copied/shrunk by57 bits for the seven-bit fingerprint and masked by the table mask for the initial offset. With ordinary preserved caller storage, this binds the reconstructed hash value into the exact live dependency of #1009. It does not convert #1009's0/1 return bound into membership.

The separate selected caller supplies the literal13-byte `skip-download` to that lookup at `0x5b90f6..0x5b910a`. For the direct child-name search, `0x5b911b..0x5b9134` supplies the same seed-field position, literal10-byte `child-args`, and the outer call. The high-seven-bit/masked-value consumption is again explicit. Earlier parser/table creation, all search outcome predicates and downstream flag effects remain outside this arithmetic function.

A valid membership theorem additionally needs actual table construction, consistency of a cached candidate with the represented set, occupancy/count consistency, readable72-byte reverse records, correctly mirrored16-byte control groups, and an empty-marker/probe-reachability invariant. Capacities below16 cannot silently inherit a simple periodic mirror model. The producer `0x478c40..0x4796c9` delegates table formation and has73call sites; this packet does not qualify that closure. No synthetic validated-table API substitutes for it. The reconstructed hash remains useful independently: its exact returned value is a now-closed input to those unresolved algorithms.
