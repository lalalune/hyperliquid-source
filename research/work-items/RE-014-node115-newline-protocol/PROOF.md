# Conditional node #115 newline request protocol

Target node #115: 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The selected complete extent is `[0x1686bd0,0x1686e46)`, 630 bytes /173 native
rows. All addresses are ELF VAs. This qualifies a logical request/state
projection under explicit premises; it does not identify an original source
type/compiler/ABI or establish whole-machine cross-release equivalence.

## Relation and memory conditions

At the actual post-prologue loads, let the three QWORD values from incoming
RDI=A be D=load64(A), V=load64(A+8), B=load64(A+16). They are role names.
Incoming RSI=p and RDX=n describe a finite, immutable readable byte interval.
All actually used pointers, frame/return storage and current V+0x18 method
entries must be valid. Relevant address, length, alignment and cursor arithmetic
must not wrap; in particular p+8 and any used p+n or a+7 are representable.

The private frame, saved-register slots and return/control state are protected
from B-directed and callback writes. Input bytes and later-needed pointer/
descriptor memory remain valid and separated from incompatible writes. A's
values mean those loaded after the prologue, not presumed earlier values.
Normal callbacks preserve the observed callee-saved registers, stack and saved
arguments/control slots. Unwinding, faults, nonreturn and concurrent mutation
are outside this normal-return relation. These are conditions, not an inferred
original calling convention or a claim about every possible callback.

For nonempty input, B's byte is separated from the input and all adapter
prologue/private/saved/return/CALL-stack writes. The input is also separated
from incompatible own-stack writes. No B mapping is required for an empty
input because B is not dereferenced; physical preservation of an aliased byte
would still need the stated separation. Each owned CALL writes its return
address at RBP-0x68, below the allocated frame, and called code may use further
stack storage subject to the callback premises.

Split the input into nonempty pieces ending at the first LF byte inclusive,
followed by at most one nonempty tail. For each such piece, in order:

1. Read the current byte through cached B. If nonzero, request the actual
   four-space slice through the method currently read at cached V+0x18,
   with cached D. Nonzero returned AL stops with AL=1 before this piece's
   owned flag store or payload request.
2. Store whether the piece ends in LF through cached B, then request exactly
   that piece through a freshly read V+0x18 method with cached D.
3. Nonzero payload AL stops with AL=1 after that owned store. Otherwise continue.
   When all pieces succeed, return EAX=0.

Callbacks may change B's byte and the current method entry within these
premises. An indent-success callback's B edit is overwritten by the owned
predicate store. A payload callback's B edit can affect the next indentation
decision. Stable writer identity needs an extra unchanged-method-entry
condition; a final physical flag value needs callbacks to preserve it.
Empty input, or the empty tail after a terminal LF, makes no B-directed
access or callback. Physical preservation of B still requires separation
from the prologue/private-frame/call-stack writes.

The theorem concerns requests and owned stores. It does not establish physical
rendering, actual external callback behavior, application reachability, a
reconstructed Rust library or a full formatter/node policy.

## Entry state and changed lifetimes

The prologue at `0x1686bd0..0x1686bdd` pushes RBP and five callee-saved
registers, then subtracts 0x38. Relative to established RBP, private/saved storage
extends to RBP-0x60; the saved return address is at RBP+8. The six cached
entry stores are B at -0x50, D at -0x48, V at -0x40, p at -0x30,
p+8 at -0x58 and n at -0x60. Continuation state later uses DWORD -0x34.
The only explicit non-frame store in this body is the byte store at
`0x1686c42` through cached B. PUSH/CALL stack writes are separate effects;
memory-looking NOP operands are not protocol memory reads or writes.

At header `0x1686c74`, for continuation low bit d=0, use emitted cursor
e=R15 and search cursor s=R14, with e=s and 0<=s<=n.
RBX carries HI=0x8080808080808080 and R12 carries LFWORD=
0x0a0a0a0a0a0a0a0a. Entry initializes e=s=d=0. The header tests d before
reusing cursor state; the d=1 final-tail return intentionally needs no e=s
invariant.

This differs materially from the previously qualified #94 body
`[0x157d000,0x157d26e)`:

| Role / phase | Node #94 | Node #115 |
|---|---|---|
| Frame subtraction | 0x48 | 0x38 |
| Saved n | RBP-0x68 | RBP-0x60 |
| Emitted e at live header | R8, temporarily R12/spill | R15 |
| Search s | R15 | R14 |
| HI at live header | R13 | RBX |
| LFWORD at live header | R14 | R12 |
| C word | RBX, entry materialization | R13, materialized at 0x1686cfb |
| LF end calculation / callback selected end | R12 / R13 | R13 / RBX |
| Indentation preserves old e | explicit R8 spill/reload | callee-saved R15 |
| After payload | R8 from R12 | R15 from R13 |

R13 can become C during a long scan because the next piece end is not live
until a match/tail selection. On a found LF, `0x1686dcd` saves HI into R12
before RBX becomes the selected end. After the payload, `0x1686c5e`
restores HI to RBX and `0x1686c61` restores LFWORD to R12.
These are phase-dependent roles, not a global register-renaming mask.

## First-LF scan

At `0x1686cac..0x1686cb2`, m=n-s is RCX and a=p+s is RAX.
The unsigned bounds gate ensures s<=n. For m<=15, zero length goes directly
to tail selection. Otherwise `0x1686cd0..0x1686ce0` compares byte(a+i)
with 0x0a before incrementing i, starting i=0 and continuing only while i<m.
It therefore finds the first LF or establishes that the entire interval has
no LF.

For m>15, `0x1686cf0..0x1686cf8` computes
delta=((a+7)&~7)-a in [0,7]. A nonzero prefix is scanned in increasing order
at `0x1686d70..0x1686d7c`; m>=16 makes the prefix in bounds.
The wide path is entered only with t<=m-16, initially t=0 or delta.
If the aligned prefix leaves fewer than 16 bytes, the branch at
`0x1686d85` falls through to exact scalar tail handling.

The saved p+8 pointer and the -8/0 load displacements at
`0x1686d20` and `0x1686d34` give exactly two adjacent words:
[a+t,a+t+8) and[a+t+8,a+t+16). The interval gate makes both in bounds.
The constants are read from the actual #115 operands:
C=0x0101010101010100 at `0x1686cfb`,
HI at `0x1686be1`, and LFWORD at `0x1686beb/0x1686c61`.

For two little-endian words w0,w1, let xj=wj XOR LFWORD and let all word
arithmetic wrap modulo 2^64. The actual operations at
`0x1686d25..0x1686d4a` form

```text
T0 = ((C - x0) OR w0) AND HI
T1 = (C - x1) OR x1
skip iff (T0 AND T1) == HI
```

Only safe skipping is required. If a word contains LF, the corresponding
byte of x is zero. In lane0, C's byte 0 and incoming borrow 0 produce subtraction
byte 0. In each higher lane, C's byte 1 minus incoming borrow 0 or 1 produces
byte 1 or0. Thus that lane's high bit is zero, regardless of all other bytes.
OR with original LF 0x0a in T0 or xor-zero in T1 leaves it zero; the combined
predicate cannot equal HI. There are15 relevant lane/borrow cases, checked
against extracted constants. This mathematical byte-borrow lemma does not
evaluate captured instructions.

False candidates are allowed. On a candidate, scalar fallback starts at t.
On a certified skip, t+=16; this remains <=m, and another wide iteration
requires t<=m-16. The final suffix is scanned bytewise in increasing order.
Previously skipped/prefix bytes have no LF. Consequently the returned match
is the first LF of the entire remaining interval. The zero-tail equality
gate at `0x1686d9a` avoids an extra read when t=m.

A match gives j=s+i<n. At `0x1686db0..0x1686dc7`, R13 becomes j+1 and the
native code rechecks both j<n and byte(p+j)==LF. Both pass under the admitted
bound and immutable-input premises. The retry branches to `0x1686ca0`
remain in the raw graph but are unreachable in this theorem; behavior under
concurrent mutation is not silently transferred.

## Piece selection, callback order and returns

A matched piece sets end=j+1 with e<end<=n. At
`0x1686dcd..0x1686dd8`, R14=R13=RBX=end, R12=old HI, d=0,
while R15 remains old e.

If no LF remains, `0x1686de0..0x1686df4` sets end=n, R14=n, RBX=n and d's
low bit1. It copies old e from R15 into R13. If e=n it returns EAX=0 before
reading B or calling anything; this covers empty input and terminal-LF tails.
Otherwise the nonempty final tail proceeds with R13 deliberately retaining
old e. Higher bits of the saved continuation word are irrelevant: only its
low bit is later tested.

The common selection point at `0x1686df6` saves d at RBP-0x34, then loads
the cached B pointer and samples its current byte. Nonzero selects indentation:
EDX=4 at `0x1686e02`, cached D at `0x1686e07`, pointer 0x45a128 at
`0x1686e0b`, cached V at `0x1686e12`, current method[V+0x18] at
`0x1686e16`. The actual data bytes are 20202020. Nonzero returned AL takes
`0x1686e1f -> 0x1686e35`, before this piece's flag store/payload.

At `0x1686e21`, selected end differs from old e for every admitted nonempty
piece. Therefore `0x1686e24` reaches `0x1686c30`, where the last byte is
compared with LF and SETE defines the predicate. The equal-end arm
`0x1686e2a..0x1686e2c` would set that predicate to0 and request an empty
payload in other machine states. It is retained but unreachable under the
nonempty-piece invariant; final empty tails exited earlier.

At `0x1686c38..0x1686c52`, RBX becomes end-e, R15 temporarily becomes p+e,
the predicate is stored through cached B at `0x1686c42`, cached D is
restored, and RSI/RDX become p+e/end-e. Cached V is loaded afresh, then its
current +0x18 method is called. The ordered flag store precedes that request.

After the callback, `0x1686c55` restores R15 from R13. TEST AL at
`0x1686c58` supplies ZF; the intervening MOV/MOVABS reloads of n, HI,
LFWORD and saved EAX do not change flags. Thus `0x1686c6e` tests the
payload's returned AL even though EAX was overwritten from the continuation
slot. Nonzero stops with AL=1. On success, d=0 restores e=s=end; d=1 reaches
the header's success return before the restored old e can be reused.
This is why final-tail success does not require e=s.

Each successful LF piece advances e strictly; the only remaining piece is a
nonempty final tail. With normal callbacks, the finite input therefore gives
at most LF-count plus one owned payload request, at most one owned indent
request per payload, and an optional empty-tail exit. These counts concern
this invocation's two call sites, not arbitrary callback-internal effects.
Error exits occur earlier.
Success at `0x1686e31` clears EAX; failure at `0x1686e35` writes AL=1
only. The common epilogue restores the protected frame and callee-saved
registers and returns at `0x1686e45`. Upper failure RAX bits are unqualified.

## Complete control inventory

Every explicit branch is listed below; both indirect calls and the only RET
are addressed above. Falling through to the next decoded row remains an edge.
This is a local complete body inventory, not a proof of global incoming xrefs.

| Branch VA | Destination | Admitted role |
|---|---|---|
| 0x1686c24 | 0x1686c74 | initialized header |
| 0x1686c6e | 0x1686e35 | payload AL error |
| 0x1686c76 | 0x1686e31 | completed tail |
| 0x1686c7f | 0x1686c90 | s<=n, always at live header |
| 0x1686c88 | 0x1686de3 | bounds-failure arm, unreachable |
| 0x1686c94 | 0x1686cac | search setup |
| 0x1686ca6 | 0x1686de3 | retry bounds-failure arm, unreachable |
| 0x1686cba | 0x1686cf0 | remaining length>15 |
| 0x1686cbf | 0x1686de0 | empty remainder |
| 0x1686cd4 | 0x1686db0 | scalar first LF |
| 0x1686ce0 | 0x1686cd0 | next short-scan byte |
| 0x1686ce2 | 0x1686de0 | short interval exhausted |
| 0x1686d05 | 0x1686d60 | nonzero alignment prefix |
| 0x1686d4d | 0x1686d90 | candidate block |
| 0x1686d56 | 0x1686d20 | next complete 16-byte block |
| 0x1686d58 | 0x1686d90 | final suffix |
| 0x1686d74 | 0x1686db0 | prefix first LF |
| 0x1686d7c | 0x1686d70 | next prefix byte |
| 0x1686d85 | 0x1686d0e | complete block after prefix |
| 0x1686d9a | 0x1686de0 | empty suffix |
| 0x1686da4 | 0x1686db0 | suffix first LF |
| 0x1686dac | 0x1686da0 | next suffix byte |
| 0x1686dae | 0x1686de0 | suffix exhausted |
| 0x1686dbd | 0x1686ca0 | failed match-bound recheck, unreachable |
| 0x1686dc7 | 0x1686ca0 | failed immutable-byte recheck, unreachable |
| 0x1686dd8 | 0x1686df6 | selected LF piece |
| 0x1686df4 | 0x1686e31 | empty tail, no B access |
| 0x1686e00 | 0x1686e21 | no indentation requested |
| 0x1686e1f | 0x1686e35 | indentation AL error |
| 0x1686e24 | 0x1686c30 | admitted nonempty piece |
| 0x1686e2c | 0x1686c38 | empty-payload arm, unreachable |
| 0x1686e33 | 0x1686e37 | success epilogue |

## Fixed edges and scope of transfer

The parent at `[0x167d950,0x167dad6)` loads table 0x64078f8 at 0x167da69.
Its fixed calls at 0x167da74 and0x167da92 use slot 0x64e00a0.
Both that slot and table+24 (0x6407910) have symbol-free RELATIVE addends
0x1686bd0. These static bindings establish the selected helper edge; they
are not observed runtime pointers. The other table entries at+32 and+40
lead to 0x1686b70 and0x168aa10, whose behavior remains opaque here.
The table header words remain raw metadata, not a recovered type layout.

The generic adapter's cached V is its incoming underlying writer table,
not necessarily the parent's fixed adapter table. No confusion of these
two roles is used to close an external callback.

The earlier #94 protocol is credited as the prior theorem. The #115 theorem
above independently reaches the same logical projection under corresponding
premises despite changed frame/register lifetimes. No bytes are normalized,
no #94 implementation is declared ABI-compatible with #115, and arbitrary
frame aliases need not behave alike. All helper bytes were already observed;
this contribution receives no additional recovered-byte credit.

Native FDE/CIE records provide exact unwind provenance and independent
GNU/LLVM exports validate byte partitions. They do not establish complete
function ownership or whole-program behavior. Finite algebra/interval
certificates and native mutation controls support specific proof obligations;
they do not execute captured instructions or callbacks.
