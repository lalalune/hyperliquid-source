# Conditional node94 method association

This is a static relation between one registration, an entry representation,
and the lookup success path. It does not establish that a network request
reaches that path, that the built map survives all intervening operations, or
that every probe terminates. All coordinates are ELF virtual addresses of
node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.

## Domain

All reached memory accesses are valid, arithmetic does not wrap in the
expressions used below, and relevant code/data/relocation bindings are the
ones retained in `observed/records.json`. The stack, saved arguments and
callee-saved registers survive normally returning callees. Concurrent
mutation, faults, unwinding, allocator failure, reference-count abort and
arbitrary aliases into protected frames are excluded from this normal path.
Opaque callees preserve live key bytes, descriptor values and metadata used
later unless an actual store in the retained path is described.

The dynamic slot naming `bcmp` must actually be bound to a normally returning
comparator whose EAX is zero exactly when the supplied two n-byte intervals
are equal; it must preserve the caller's saved state. Static symbol and
relocation provenance establishes the intended external identity, not an
observed runtime binding or a proof of libc's implementation.

For the one-method association, the registration must reach the new-entry
store path described below. The resulting entry, value descriptor and
callback table must be preserved, with the same record representation,
until a lookup reaches that candidate. These are explicit table-transport
and preservation conditions. They are not claims that the constructor,
growth, map sharing or request state machine already establishes them.

## Registration arguments and descriptor

The previously observed 26-name body is retained as context, without claiming
its full semantics anew. At `0x27ab667`, the RIP-relative LEA produces
`0x3f05a2`, the exact 15 bytes `eth_blockNumber`. `0x27ab671` places 15 in
ECX, and `0x27ab679` calls the complete 221-byte FDE
`[0x1f6d8a0,0x1f6d97d)`. RDI points to the caller's temporary result and
RSI to its local context at RSP+0x20. Other names/registrations are outside
this method-specific relation.

Let C be incoming RSI to the 221-byte body and O its incoming RDI.
`0x1f6d8ad` loads Q=load64(C), then increments the qword at Q and aborts
if the signed result is nonpositive. The normal allocation branch requests
24 bytes at `0x1f6d8de..0x1f6d8e3`. Call its nonnull result P.
The stores at `0x1f6d8f2..0x1f6d900` put qwords 1,1,Q at P+0,P+8,P+16.
The reference-count/allocator semantics and allocation safety are not inferred
from those values; only those actual normal-path stores are used.

The temporary at RSP+8 is then three qwords `(0,P,T)` with
T=`0x5691990`: `0x1f6d908` materializes T, `0x1f6d90f` stores it at
RSP+0x18, and `0x1f6d914` stores the zero tag at RSP+8.
`0x1f6d91d..0x1f6d92e` calls slot `0x5770950` with
`(RDI=O, RSI=C+8, RDX=original key pointer, RCX=original length,
R8=address of this three-qword descriptor)`. The selected RELATIVE record
has symbol zero and addend `0x2a484d0`, the start of a complete 592-byte FDE.
These are native argument/register facts; no nominal Rust type is assigned.

## New-entry storage representation

At entry to `[0x2a484d0,0x2a48720)`, R14 saves the descriptor pointer,
R12 the original method pointer, R15 its length and RBX the output pointer.
The call through `0x57735a0` is deliberately opaque; call its result M.
The next call, at `0x2a484fe`, invokes the complete FDE
`[0x2a48ad0,0x2a48c6a)` with `(out=RSP, map=M, key=R12, len=R15)`.
This extra body is included to bind the returned key, rather than assuming
that an opaque helper returned the supplied string.

That helper saves the original key at RSP+8 and original length in R14
(`0x2a48ade..0x2a48af1`). Its hash, candidate comparison and possible growth
are not proved as a complete map algorithm. On its observed no-existing-key
return path `0x2a48c24..0x2a48c38`, it writes the original saved key pointer,
length, M and a hash value into four output qwords. The growth arm at
`0x2a48c4a..0x2a48c68` returns to that same output block. The existing-key
return instead puts zero in the first word at `0x2a48c14` and is not this
new-entry branch. No general successful insertion or absence theorem is
inferred merely from these return layouts.

Back in the 592-byte caller, a nonzero first word chooses `0x2a48510`.
The output key pointer and length become RCX and RDX. The descriptor's three
qwords are saved from actual post-helper memory, so preserving the earlier
`(0,P,T)` is a stated premise. Let D=load64(M), mask=load64(M+8), and i be
the actual selected bucket index after the observed mask operations. The
selected index is negated and multiplied by five at `0x2a4857e..0x2a48581`.
The actual stores are:

| Address | Stored word |
| --- | --- |
| A=D-40*i-40 | original method pointer |
| A+8 | original method length |
| A+16 | descriptor tag 0 |
| A+24 | descriptor data P |
| A+32 | descriptor table T |

The first two stores are `0x2a48589/0x2a4858e`; the descriptor's first
16 bytes are stored at `0x2a4859f`, its last qword at `0x2a485a9`.
The nearby control-byte stores and occupancy counters are retained in the
full native record but do not close the hash/probe/growth algorithm.

## Reached lookup candidate and comparator

The containing request-associated FDE is `[0x2027610,0x2028519)`. Its full
body digest and selected native corridors are retained; only the stated local path is qualified here. Let S be
its cached incoming RSI (RBX). In the initial-state route, `0x202764b`
loads a pointer from S+0xe8, whose dereference at `0x2027c38` supplies a
map allocation pointer B. The lookup uses D=load64(B+0x10) and
mask=load64(B+0x18). Identifying these with the inserted table requires the
transport premise above; the 16-byte representation displacement is observed,
not silently elided.

When the nonempty path is reached, `0x2027c46/0x2027c4a` load request
pointer u and byte length n from S+0x70/S+0x78. The actual hash call is
`0x2027c62 -> 0x2a461c0`; its full algorithm and agreement with insertion
hashing are unqualified. The returned hash's high seven bits supply the
16-lane candidate-byte comparison; masking and TZCNT select a candidate
index i. We do not name a source hash-table implementation.

The live base RDI=D-40, and `0x2027d0d..0x2027d10` gives R15=-5*i.
Consequently `0x2027d14` compares n with the candidate word at
`(D-40)+(-5*i)*8+8=A+8`. Different lengths take `0x2027d58` before the
comparator call. For equal lengths, the candidate key pointer is read from A
at `0x2027d1f` and preserved in R13.

`0x2027c93` loads R12 from slot `0x576e378`. Its actual relocation is
`R_X86_64_GLOB_DAT`, dynamic symbol index 11, addend zero. Symbol 11 is the
undefined name `bcmp`. The call at `0x2027d3d` supplies
`(RDI=u, RSI=load64(A), RDX=n)`. This register-indirect call is a key
comparison, not a method invocation. Under the comparator premise, EAX zero
means the two equal-length keys match. TEST EAX at `0x2027d50` and JE at
`0x2027d52` select `0x2027fed` on that result. Saved base and length reloads
between the call and TEST do not supply a second result condition.

The candidate mask, empty marker and triangular probe are retained, but their
global termination, miss behavior and full table invariant remain outside
this local candidate-success argument. Equality of the stored key to
`eth_blockNumber` therefore makes the matched entry's method association
conditional on reaching that preserved candidate, without assuming that every
matching request reaches it.

## Value and concrete callback

At success, `0x2027fed` restores D and `0x2027ff5` computes E=D-40*i.
The tag is read from E-24=A+16 at `0x202801a`. Tag one takes another arm;
nonzero tags take another arm. The registered zero tag falls through to
`0x202803a`, loading P from E-16=A+24 and T from E-8=A+32.

T's unrelocated six qwords are `(0,8,8,0,0,0)`. The symbol-free RELATIVE
record at T+0x28 (`0x56919b8`) has addend `0x1f702c0`, exactly the start
of `[0x1f702c0,0x1f704a8)`. T+0x20 has the same addend; T+0x18 has a
different one (`0x1f997c0`). Static addends are not observed runtime pointers.
Ordinary PIE relocation and preserved table memory are required to transfer
the stored descriptor to the actual target.

The expression at `0x2028042..0x2028051` makes RSI
`P+((load64(T+16)-1)&~15)+16`. With the retained table word 8 this is P+16.
At `0x20280d0`, the call through T+0x28 receives:

| Register | Observed argument |
| --- | --- |
| RDI | output address, current RSP+0x1a0 |
| RSI | P+16, pointing at captured qword Q |
| RDX | current RSP+0x38, three copied words |
| RCX | current RSP+0x20, three copied words |
| R8 | 0x100000 |
| R9 | current load64(S+0xe0) |

These argument roles are not recovered source parameter types. The callback
body preserves the output in R15, loads RSI=load64(RSI), adds 16, and at
`0x1f702f9` directly calls `0x27b8410` with that pointer in RSI and a local
output buffer in RDI. The destination has a validated complete FDE
`[0x27b8410,0x27b86e8)`, 728 bytes. Its full body digest and entry corridor are retained;
its locking/timing/logging helpers and full return semantics are not closed.
This is a concrete method-associated callback and direct callee address,
not a proof of the public endpoint's complete behavior.

## Evidence and proof limits

The packet binds seven complete FDE identities and their raw CIE/FDE/index
records, eleven selected native-corridor byte partitions and local operands. The
selected address relation and normal-path argument above are manual. Frozen
instruction witnesses, fresh native mutant decodes, relocation/data/unwind
controls and finite affine-address cases check specific evidence seams.
They neither execute the target nor prove changed-program behavior. No
instruction evaluator, live RPC, actual runtime callback, original Rust
ABI/layout, source build, whole-router equivalence or component gate is claimed.
