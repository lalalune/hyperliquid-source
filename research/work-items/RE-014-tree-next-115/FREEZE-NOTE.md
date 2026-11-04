# Native freeze before source

Base8fd8db680ec4bfef40996e5616bce3d5156d0b86 has only the two-span weighted
fast-fold reconstruction. Its retained weighted-comparison packet explicitly
leaves the generic next helper unclosed. This work selects that helper,
37c4430..37c4644, not a new version of the already implemented fast path.

Initial native freeze3075recipes passed43.149s. A second pre-Rust freeze adds
balanced six-child shapes and ready-cursor high-tag cases,3507recipes,59.011s.
Both original streams/logs are preserved. Equivalent height0 fanout and
empty-root seed recipe aliases were then removed only after exact initial
memory/register/known-mask/nodecount and observed-transcript equality checks.
canonicalization.json records326removed frames and3181retained recipes;
answers were selected from actual native output, never computed by Rust or
an inorder reference model. The default native generator emits this same
canonical subset; normal replay rechecks all hashes and visited addresses.

The raw fixtures include balanced trees and sparse tower shapes through17
levels to cover the eight-step unrolling without enormous allocations. These
are explicit machine-memory fixtures; original stdBTree occupancy/order/type
validity and runtime reachability are NOT asserted. Root/leaf and error-state
cases are also included. No original Rust source or unlicensed inferred code
is copied. No new Rust component exists at this freeze commit.
