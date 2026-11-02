# Source plan — no Rust or client exists in this freeze

The planned target is the real dependency-free `node94-consensus-admission`
crate at main56c0ec672bd8fdcfaa80f2db700a61e6240b3663. baseline.json records the13
files from the prior verified clean-baseline receipt. They must be re-admitted
in a dedicated clean integration checkout at the source gate; the shared scout
checkout can contain pending unrelated source. Existing consensus authentication,
types and admission APIs remain unchanged.

Planned writes only after a separate root gate:

- new `src/node94-consensus-admission/src/request_throttle.rs`;
- new `src/node94-consensus-admission/tests/request_throttle.rs`;
- one module/export insertion in the actual crate lib.rs and one README section;
- task-local input-only driver, authored build/validation harness and source proof.

Cargo.toml/lock stay dependency-free and unchanged. No runtime dependency on
pending batch/join/preimage work or open PR1473; no copied source from that PR.
The planned public state is an ordered key map with retained row stamp, reason
set and sent flag. Timestamp admission and deadline computation use the declared
canonical subset and explicit errors. DeadlineRange preserves prior registration
and reason insertion; InvalidTime preserves the entire map. Public constructors
and snapshots should expose the intended values without claiming raw native
layout, allocator capacities, lock/log implementation or network behavior.

Use safe Rust integer/byte operations and ordinary BTreeMap/BTreeSet. A small
private date bridge may use a closed Gregorian serial-day expression plus a
bounded year search; it is part of this composed operation, not a new public
generic packed-date-add library. Explicit-delay conversion must agree with the
all-class proof, including finite-product overflow mapping to zero. Any choice
of host float versus integer arithmetic needs a source-level portability proof
at its gate. The frozen oracle uses a different400-year partition and exact
integer RN-even calculation.

Meaningful tests cover native state histories and the new safe policies. Planned
compiled controls change stamp refresh, key round/hash participation, reason
placement after suppression, sent reset, default/custom choice, equality guard,
nonfinite/overflow mapping, truncation/rounding, calendar rollover and refusal
ordering. Every changed variant must compile and produce a complete comparison
stream; compiler failure is not a semantic kill. Expected mismatch counts must
be measured, never predicted as completed tests.

Before any compilation: inspect the actual entire Cargo graph, ancestor and
canonical-path configs, hooks, symlinks, environment and pinned toolchain payload;
freeze source/tests/client/harness; wait for the root source/build gate. Run only
authored Rust offline/locked in both pinned profiles, use input-only fixtures,
retain first failures and all raw streams, preserve compiled artifacts privately
before clean repeats, and measure same-path and cross-directory identities
separately. Do not execute captured bytes or duplicate broad repository tests.
