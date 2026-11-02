# External normal-return frame required by the value theorem

The9 subject/helper FDEs are proved in PROOF. Three caller FDEs are complete
context exports only; their unrelated calls do not inherit this theorem.
records.json retains every call and selected RIP relocation, including cold
and unwinding tails. The following are explicit external premises. They are
not names used to assume a map or reason insertion algorithm: those two complete
algorithms are proved separately from their bytes.

| Interface | Actual selected binding | Required normal-return effect |
|---|---|---|
|allocation|slot576dfd8 RELATIVE/symbol0 →54c06b0; size in RDI|fresh aligned writable span of requested0x18/0x78/0x3d8/0x438 bytes, no alias to live protected storage; zero/failure excluded|
|disjoint copy|slot576dfe0 → imported memcpy|exact n bytes, unchanged source and all storage outside destination|
|overlap copy|slot576e0e0 → imported memmove|exact n bytes as through a temporary; unchanged storage outside destination|
|key comparison|slot576e488 → imported memcmp|unsigned-byte first difference sign, exact equality, no mutation|
|slow lock acquire|slot576ef30 RELATIVE/symbol0 →4e0f640|returns with displayed byte lock granted; preserves protected values and paired object identity|
|slow release|slot576ef38 RELATIVE/symbol0 →4e0f2c0|releases that lock normally, preserves protected values|
|registration log|49587e2 →4707f10|may mutate its log object, preserves key/time/map/tree/stack/output and ownership|
|emission log|44b82f5 →470cbc0|may observe the row (including reason set) and mutate its log object; preserves row and all later-used protected values|
|statistics|4958820/44b832f →4a112a0 with selector4/5 and increment1|may mutate statistic object, preserves all semantic state in CONTRACT|

Protected spans include the complete state map descriptors and every live node,
the selected row and all of its reason nodes, key/hash/event-time arguments,
active output and temporary/caller-stack values, plus allocations whose pointers
escaped earlier. Merely returning or respecting callee-saved registers does not
imply this memory frame. In-node memmove destinations and the explicit algorithm's
new-node/header writes are the stated exceptions. All effective address additions,
counts, capacities and requested spans are nonwrapping and valid. No other thread,
signal handler, callback or foreign code changes these spans during the call.

Both registration log/stat scopes finish before timestamp initialization; both
emission scopes finish before returning an active request. The native sent store
is between emission log and stat5. Thus abstract state correspondence does not
claim the operation is atomic with respect to logging exceptions, lock contention,
allocation failure or observers. It applies to finite ordinary successful traces
with exclusive semantic state. A future safe Rust value API omits logging/locking
effects, rather than claiming to reproduce their implementation or schedules.

Bounds and panic helper calls, allocation failure routes, reason drop49b4c00,
and _Unwind_Resume are retained but outside ordinary success. The proof shows
which index/height guards are unreachable from the admitted tree invariants;
it does not assume those functions never return when constructing CFG facts.
Deadline range rejection is a separately labeled safe policy and does not use
the native panic path as an observation oracle.
