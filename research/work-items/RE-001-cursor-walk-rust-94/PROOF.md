# Fixed-record cursor walk: relation and admitted domain

The complete node #94 linked-VA body `[0x3c1d690,0x3c1d6e1)` is 81 bytes /
28 instructions, SHA-256 `ae2cf37c1a3a17292c3c809245e4836f4a7efeebeff46b2fdd689567dd75e9f3`.
Full artifact, FDE, caller and relocation bindings are retained in `static/`.
This is an independently chosen safe slice projection, not the original ABI.

## Native relation and failure state

Entry loads the cursor from [RDI] and the limit from [RDI+8]. Equal values
return RAX=0 without modifying the cursor or dereferencing a node. Otherwise
the first iteration computes cursor+0x38 modulo 2^64 and stores it to [RDI]
**before** reading the old cursor's tag byte +9. EAX is cleared. Tag 3 and
all other tags except 2 return zero; the explicit tag-3 check is redundant.
Tag 2 then requires the old node's byte +0 to equal zero. A failure returns
zero with the cursor slot already advanced past the failed node.

After a passing node, the new cursor is compared to the saved limit. SETE
sets AL, and equality returns. EAX's high bits remain zero, so this success
returns full RAX=1. If unequal, AL is zero and another iteration stores the
next +0x38 cursor before checking the node it just left. The MOV from RSI to
RDX does not change flags, so the final JE uses the byte +0 comparison.
Every node at stride 0x38 is checked; the first advanced node is not skipped.
The limit itself is never dereferenced. No store is made to the limit field.
There are no calls, and all leaf branch targets are inside the complete body.

Under stable disjoint cursor-state/node memory, this is the relation:

1. Equal entry cursor/limit: return zero, unchanged cursor.
2. Otherwise visit nodes consecutively in 0x38 steps.
3. Before each node check, store its successor in the cursor slot.
4. Stop on the first node with tag !=2 or byte0 !=0, returning zero.
5. If the passing node's successor equals the limit, return one.

The original function has no general bound or step budget. Off-lattice limits
can fail to terminate when all visited nodes pass, and raw arithmetic wraps.
Aliasing the cursor slot with node fields can alter subsequent checks because
the store precedes reads. Neither behavior is flattened into a snapshot claim.

## Slice projection and admission

The Rust API takes immutable `[u8;56]` records, a mutable cursor **index**, and
an exclusive limit index. These are independent value types, with no native
pointer/layout ABI claim. The immutable records and mutable cursor are disjoint
for safe Rust callers. Every byte pattern is allowed; only bytes 0 and 9 matter.

Equal cursor/limit returns false before any index bounds check, including equal
indices outside the slice. This models the native equality branch's absence of
node access. For unequal indices, the API requires `cursor < limit <= len`.
Other inputs return `InvalidRange` without changing the cursor. The target has
no such refusal branch; this is explicit safe-API policy.

For correspondence on nonempty admitted ranges, choose a base B such that
record i occupies `[B+56*i,B+56*(i+1))`, and all used address additions are nonwrapping. The cursor/limit pair and
accessed node bytes must be mapped; the limit address is only compared and
need not be readable. Map cursor/limit indices to B+56*index, with a stable
separate cursor/limit pair. B has no additional alignment requirement;
aligned stride means that cursor and limit share this 56-byte lattice. The full records/slice
borrow strengthens availability beyond the native two-byte reads. The API
excludes aliases, backward/off-lattice limits, raw wrapped pointer paths,
unmapped nodes, concurrency/MMIO, timing and native fault/partial-store behavior.
For equal indices, the relation is simply equality and no node access; no
hypothesis about a readable node is needed.

An admitted nonempty range has `limit-cursor` records. Each successful iteration
increments the index by exactly one, preserving `index <= limit`; therefore
increment cannot overflow, indexing is valid, and termination is finite. An
induction maps each visited index to the native pointer. Both algorithms store
the successor before the same predicates. Thus they agree at the first failure
and on its already advanced cursor. If every selected record passes, both end
at the limit and return true/one. Empty ranges return false/zero, so ordinary
vacuous `all([])==true` is not this function's rule. No extra step limit or
silent truncation is added to the admitted range.

## Caller binding

The complete direct caller is `[0x3362f30,0x3362fc2)`, 146 bytes / 41
instructions. Its call at 0x3362fb8 targets the walk. The selected block at
0x3362f9d multiplies the qword at object+0x40 by 56 modulo 2^64, loads the
base pointer at +0x38, adds them, stores base and result at RSP+8/RSP+0x10,
and passes RDI=RSP+8. This grounds a base/count construction for the helper.
It does not prove that arbitrary caller counts are valid or nonwrapping.
The rest of the caller includes table dispatch and a separate indirect tail
path; its source meaning, those branches' contracts and targets are not
reconstructed here. Full bytes/FDE and the direct call/setup are bound without
claiming full caller semantics. No existing historical emulation was rerun or
used as the comparison oracle.

## Independent expectations

Before Rust existed, oracle.py froze 7,009 inputs and expected return/final-index
pairs. The oracle computes the set of failing indices in the immutable selected
interval and takes its minimum. With no failures it returns the limit and true;
with a failure it returns first_failure+1 and false. It classifies entry equality
and safe refusals separately. It does not emulate the native loop, use the
historical Python walk model, or read Rust outputs. This closed-form first-failure
relation is independently justified by the induction above.

The input-only client receives full raw records and indices, never expectations.
It returns the public result and final cursor index. No result bits or cursor
bits are masked. Input records cannot be modified through the safe immutable
API; no output-buffer surrogate or expected-value callback is used. Finite host
runs corroborate the target-grounded proof but do not execute captured code.
