# Digest-vote insertion to the expected-digest selector

Partial RE-017 work toward checkpoint/replay validation (#3910). Target: Linux
x86-64 node #115, size 105896032, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The new result is a bounded producer contract for the height entry's selector
and following 32-byte digest. On the selected insertion route, an unset entry
becomes selected only across a false-to-true transition of the same candidate's
support predicate. It stores the incoming digest bytes; it does not calculate
an execution root here. A previously selected entry skips this transition.
This does not make the selected digest an independently trusted root.

## Prior work and exact gap

#3271 (`RE-017-hash-signature-record-115`) owns `0x2760bc0` and stops at opaque
insertion `0x28b2f10`. #5244 (`abci-tracker-lookup-watermark-115`) owns prior
lookup `0x2baff80` and watermark `0x27604d0`, and asks what insertion does with
the wrapper's 54-byte record. `RE-010-node115-digest-vote-handler-tracker`
binds that wrapper to the signed ABCI action. These contracts are reused.

`RE-017-node115-digest-reference-handoff` already follows the selected digest
from `0x5377df0` through registry, queue and replay comparison, but excludes
its mutation/provenance. This packet examines the previously opaque insertion
and its support-gate composition. It does not repeat those downstream claims.
`RE-008-digest-quorum-votes-115` is prior work on `0x36c7f70`; its complete
semantics are not newly claimed here.

## Identities and the selected route

Use T for the tracker argument of `0x28b2f10`, H for its incoming u64 height,
D for its incoming 32-byte digest, B for the returned height entry, and C for
the returned candidate entry. T/H/D are preserved at stack+0x28/+0x108/+0x168
at `0x28b2f39/31/29`. The packet retains the wrapper's digest copies at
`0x2760e82..0x2760f5d`: the caller passes the same two 16-byte halves in RCX.

The incoming record offers a 32-byte key and a 20-byte key in separate tagged
fields. The function processes these through distinct paths. Earlier membership,
already-selected-digest and aggregate admission checks can skip an input; this
packet does not claim every submitted vote reaches the route below.

At `0x28b3f55..77`, the normal helper chain is
`entry(T+0x18,H) -> 0x2db1860 -> 0x2421c00 -> B`. At `0x28b4062..40a1`, the
function copies D, passes B and that copy to `0x2db3c90`, and obtains C through
`0x2423760`. The entry helpers are retained with their enclosing FDEs; helper
normal returns and valid adaptive-map layouts are premises. The height entry
helper initializes a new selector to 1 at `0x2421c2d`; it returns the value
address for both tree and flat layouts. Its value contains the candidate map,
selector at +0x20, and digest at +0x21. Candidate values contain two distinct
map descriptors, at C and C+0x20, initialized separately by `0x2423760`.

RBX retains B and R14 retains C across the selected calls. The caller's D is
copied to stack+0x130/+0x140 at `0x28b3113..312c`, before either typed update.
The eventual selected-digest stores use these exact copies.

## Selection is an edge, not merely a successful predicate

| Condition at B+0x20 | Before update | After update | Selected-field stores |
|---|---|---|---|
| Zero: already selected | Predicate skipped; local flag set to 1 | Predicate skipped | None on this route |
| Nonzero | Predicate true | Predicate skipped | None |
| Nonzero | Predicate false | Predicate false | None |
| Nonzero | Predicate false | Predicate true | Selector becomes 0; D copied |

The native order is:

1. `0x28b40a4..40ca`: if B+0x20 is nonzero, call `0x28a9db0` on C and save
   its boolean. Otherwise `0x28b4115` sets the saved flag to 1.
2. Insert the selected typed input. Raw kind 1 passes C+0x20, a 20-byte key,
   and the preserved payload pointer to `0x2dc0820` at `0x28b410e`. The other
   selected kind passes C, its 32-byte key, and that same payload pointer to
   `0x2dc0df0` at `0x28b415d`. These are distinct containers, not one shared
   signer map. Their full replacement, allocation and error semantics remain
   separate dependencies.
3. `0x28b4162..65`: a true saved flag returns to the input loop without a
   second predicate or selected-field store.
4. `0x28b416b..418d`: call the same predicate with the same C and contexts;
   false also returns to the input loop.
5. `0x28b4193` stores selector 0. `0x28b4197..41ae` load the saved halves of D
   and write B+0x21 and B+0x31. The next code collects the candidate's two
   vote containers for the selected return result.

The input loop can continue after a transition. This proves the selected
route's latch behavior, not a global immutability rule across other tracker
operations, resets, rollback, alias mutation or concurrent calls. A selected
height with a different digest is also skipped by the earlier comparison;
that is not a proof of an authenticated equivocation policy.

## The predicate has two independently supplied contexts

`0x28a9db0(C,A,K,L)` preserves A/K/L in R12/R14/RBX. It builds a collection
from C's first map (104-byte flat rows) using `0x22bbe80`, then calls
`0x36c7f70(A,A+0x58,collection)` at `0x28a9e9a`. A false result branches to
`0x28a9ee7` and returns false after the selected temporary cleanup.

Only a true first result continues to C+0x20 (96-byte flat rows), constructs
its collection through `0x22bb880`, and calls `0x2738c80(K,L,collection)` at
`0x28a9f99`. Its result is preserved through cleanup and returned. The gate is
therefore a short-circuit conjunction of two concrete helper results. It is
not evidence that one numeric threshold or one signer set can substitute for
both. This packet binds the actual helper inputs and control flow; it does not
invent threshold, key authorization, signature verification or snapshot
semantics inside an unresolved dependency.

## Connection to the existing expected-digest consumer

The already documented `0x5377df0` reads the height map at T+0x18, finds H,
requires the value's selector +0x20 to equal zero, and takes the following
32 bytes as the key for its candidate lookup. The retained consumer window
ends at `0x5377ef9`, where it forms B+0x21. Thus the newly found stores populate
the exact fields selected by that contract, provided producer and consumer
operate on the same tracker and height. This is an object/field contract,
not a new assertion that arbitrary live calls share T, that H is the first
replayed height, or that selected D equals an independently computed state
root. The existing handoff packet remains the source for the later queue and
comparison path.

## Evidence, validation and remaining boundaries

`records.json` retains eight windows, 2247 decoded instructions and 114 selected
witnesses. `verify.py` checks the complete target digest/size, enclosing FDEs,
window hashes, exact instruction bytes/boundaries and selected witnesses.
Nine negative controls reject a changed target, re-enabled selected latch,
omitted before-gate branch, inverted after-gate branch, changed candidate
identity, altered digest half, conflated typed containers, omitted first gate,
and inverted consumer selector. They validate the static witness record;
they are not execution-based behavioral or cryptographic tests.

```
python3 research/work-items/RE-017-node115-digest-selection-transition/verify.py --target artifacts/node/115/hl-node
```

Dependencies: Capstone 5.0.7 and pyelftools 0.32. No captured executable was
run or emulated. No source implementation substitutes callbacks for the
unresolved helpers. No full-scope component gate changes.

Remaining work includes the complete insertion admission/duplicate policy,
full adaptive-map mutation and helper failure behavior, acquisition/revision
of both support contexts, signature/key authentication, all cleanup/unwind
paths, runtime producer-to-consumer identity, and an independent checkpoint/
replay/root fixture. The finding identifies where D becomes selected and
which concrete dependencies authorize that transition; it does not establish
those prerequisites merely because the selector was written.
