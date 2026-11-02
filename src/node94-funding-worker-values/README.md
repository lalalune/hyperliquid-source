# Node94 funding worker values

This dependency-free research library implements the successful supplied-state
value relation qualified by `research/work-items/RE-007-funding-worker-values-94`.
It computes one user's eligibility, ordered position updates, active funding
rows, saturation requests and first-maximum checked-product summary.

Inputs are immutable Rust values. Returned refusals identify new safe API domain
limits; they do not model native panic results, prior failure-state mutations,
allocation recovery or rollback. The native relation requires valid stable
trees/spans, disjoint mutation frames, successful exact-prefix allocation,
normal opaque diagnostic returns and the explicit SSE control assumptions in
the proof. The library records conceptual diagnostic requests without sending
them. Economic units, whole settlement, native Btree/ABI/layout, concurrency,
scheduling and captured execution are not reconstructed.

The binary64 conversion and multiplication used by the qualified amount rule
are computed with integer significands and exact round-to-nearest/even. They
do not inspect or alter host floating-point control state. Original raw rate
bits are preserved in rows, including NaN payloads. The mathematical oracle
was frozen independently before this source and uses rational distances
between adjacent representable values.

Use `funding_worker(&Inputs, &UserState)`; standard collections represent unique
ordered keys. Only the selected native fields appear in `Position`; the proof
frames other native bytes out of the value interface. Standard collection
allocation must succeed. The complete build/validation status and immutable
chronological evidence are recorded in the associated packet.

This is a real isolated component, not a full node workspace or cryptographic,
trading or risk recommendation. New source is independently authored MIT code.
