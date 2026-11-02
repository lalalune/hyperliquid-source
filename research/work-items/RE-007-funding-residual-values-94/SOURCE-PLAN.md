# Prospective safe value implementation

No production source/client/build harness is present or authorized by this
pre-code packet. A later source phase needs an independent parent gate.

Create the real standalone MIT dependency-free package
`src/node94-funding-residual-values`, with Cargo.toml, Cargo.lock, README.md,
src/lib.rs and tests/residual_vectors.rs. Baseline main is
56c0ec672bd8fdcfaa80f2db700a61e6240b3663. Do not edit another crate's API, manifests
or shared tools. Pending funding-worker/rate/storage packages and the prior
captured evaluator are not dependencies. Standard BTreeMap/BTreeSet are safe
representations; no native node layout, allocator, capacity or lock equivalence
is claimed.

Planned types are opaque fixed20 Address, fixed72 Record, supplied Summary
with signed total and optional asset/magnitude, Position with explicit raw mode,
leverage/margin/size, User with count/cross balance/position map, and State with
users/ARU/auxiliary/users-with-positions collections. No monetary interpretation
or guessed constructors are needed. Arbitrary other fields are outside the
safe representation; the native frame says those bytes are preserved.

One public `apply_supplied_summaries` operation owns the input summaries and
mutably borrows State. It validates duplicate keys and checked native-derived
count bounds, sorts/consumes summaries, folds signed saturating sums, selects
the first unsigned maximum, and flattens each prefix. Zero/no-winner bypasses
selected state lookup. Active paths pre-admit existing user/position and
size!=MIN, then insert ARU, debit mode1 margin or other-mode cross balance,
and obtain/default/update the auxiliary map in the native arithmetic order.
The implementation should perform the two saturating auxiliary steps; the
independent oracle uses the algebraically closed relation. Preserve all other
fields and map entries, including user count and users-with-positions.

Public checked-count admission accepts summary and total input-row u64 counts
and is called by the actual operation after checked length accumulation. It
returns typed bounds/overflow failure, never allocates fictitious huge vectors,
and documents its conservative all-input policy. Duplicate rejection precedes
active user/position/size rejection; state stays unchanged on typed errors.
Allocation failure and arbitrary panic/drop behavior have no atomicity theorem.
A successful result exposes flattened records, total and optional winner.

After the pre-code gate, independently author integration tests covering every
contract branch, exact few frozen vectors, ordered saturation/ties, raw mode,
record suffix behavior, negative aux counterexample and lazy state access.
The stdin-only client must implement PROTOCOL.md without reading expected data.
Audit the real complete Cargo graph, ancestor config, hooks and environment;
freeze actual source/client/harness/toolchain payloads before compilation and
wait for the separate source/build gate. Pin the same approved Rust toolchain
and run offline/locked debug+release, complete-output comparison, clean repeat,
actual compiling behavioral mutants and malformed/comparator controls. Preserve
first failures and compiled bytes privately before deleting build trees; do not
publish raw binaries that may embed private paths. Public raw stdout/stderr and
logical path metadata must retain honest availability/identity limits.

Planned discriminating mutants include unsorted/input-order summation, final-only
clamp, signed maximum, last-on-tie, absent zero-magnitude winner, wrong sentinel
width/offset, stopping all outer rows at one sentinel, treating all modes as
isolated, opposite debit sign, wrapping debit, missing ARU insertion, treating
equal-size auxiliary update as identity, skipping absent-key insertion at size0,
reversing auxiliary arithmetic, mutating count/leverage, eager unused-state
validation, duplicate acceptance and checked-count off-by-one. A mutant must
compile and return a differing complete valid frame; build failure is not a
semantic detection. Exact mutation coordinates belong to the later source freeze.
