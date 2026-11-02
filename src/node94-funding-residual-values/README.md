# Supplied-summary funding residual values

A standalone MIT, dependency-free reconstruction of one bounded node94 value
operation. `apply_supplied_summaries` consumes supplied post-worker summaries,
orders them by opaque address, folds signed saturating totals, selects the first
unsigned maximum, flattens each inner record prefix, and applies the residual
to an existing selected position. The auxiliary update deliberately performs
saturating subtract then add: old `i64::MIN` with size1 becomes `MIN+1`.

This is not the funding worker or whole-host state transition. Native conditional
correspondence requires the supplied tag/address/provenance, stable post-worker
state, initialized represented fields, existing selected user/position,
size!=MIN, valid memory/trees and ordinary helper/copy/allocation frames in the
[pre-code contract](../../research/work-items/RE-007-funding-residual-values-94/CONTRACT.md).
The [proof](../../research/work-items/RE-007-funding-residual-values-94/PROOF.md)
credits merged PR899's prior outline without treating its stubs as an oracle.
Raw mode1 selects margin; every other raw mode selects cross balance. This is a
byte-level branch contract, not an enum-validity or economic assertion.

`checked_counts` enforces native-derived 104/80-byte summary and 72-byte record
bounds and is called by the operation after checked accumulation of **all input**
record lengths. It does not promise Rust layout/capacity or allocate huge test
vectors. Bounding discarded suffixes is an additional conservative safe policy.
Duplicate summaries and count failures are rejected before any state write.
Only active residuals validate user, then position, then size magnitude; typed
refusals preserve state. Native partial failures and panic/allocation/drop
atomicity are not modeled. Unrelated represented state is preserved.

This real package has no external dependencies, build script, proc macros,
network access or captured-code evaluator. Build only this component with the
pinned Rust1.94.1 toolchain, offline and locked. The additive packet
`rust-validation` documents the source/client gate and subsequent qualification;
the immutable pre-code corpus predates this source. No successful source build
or target execution is implied by the presence of these files.
