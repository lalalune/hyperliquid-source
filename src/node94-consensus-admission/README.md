# Node #94 consensus block admission

This safe Rust crate reconstructs the bounded block-admission contract retained
in `research/work-items/RE-008-block-admission-94/` for node #94. It is an
in-memory component, not a networked consensus node. The captured executable is
never run.

## Target and evidence

- Target: `artifacts/node/94/hl-node`
- SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Primary entry: `0x44b8410..0x44b95a0`
- Certificate helpers: QC `0x4758d70`, TC `0x47594f0`, timeout vote
  `0x454aa10`, strict quorum `0x4ad90d0`, stake lookup `0x42c9930`
- Retained qualification: 15 bounded functions, 22 block rows, 29 QC/TC rows,
  and 456 target-row-versus-spec cases

The integration tests bind the Rust error tags, native boundaries, gate text,
and case families to that immutable packet. They also mutate strictness, tie,
and ordering claims and require the altered contracts to fail.

## Implemented contract

`StakeHistory::snapshot_for` applies the saturating base-plus-2000 threshold,
the 200-round lag, and the last-key-at-or-before lookup. Quorum deduplicates
sorted addresses, ignores unknown weight, checks both `u64` sums, then compares
the full products with `3 * signed > 2 * total` in `u128`.

`verify_qc` preserves signer membership, signature, quorum, hardfork-pair,
start-round, and empty-genesis precedence. The target's stake-overflow and
newer-hardfork panic classifications are surfaced as `VerificationFailure::Fatal`
instead of crashing the embedding process.

`verify_tc` checks snapshot availability, nonempty votes, vote rounds, the
last highest-QC vote, that QC, every timeout signature, and strict voter
quorum. The target dispatches the final signature checks through a parallel
helper. The evidence establishes single-error results but not precedence among
several simultaneous invalid votes; this crate uses stable input order for that
unresolved case.

`verify_block` keeps stake selection, proposer selection, proposer identity,
QC, QC-round, optional TC, proposer membership, and proposer signature in the
recovered order. A `VerifiedBlock` cannot be constructed directly.

`admit_verified_block` applies committed-round, duplicate-hash, and
duplicate-round gates and returns a separate `AdmittedBlock`. Registration then
removes the tag-zero request row, writes unknown-transaction placeholders,
attempts optional forwarding, handles a closed channel without losing the
block, and inserts the block map row. `admit_and_register` does not mutate
`ConsensusState` on any verification or admission failure. Registration
revalidates state gates so a stale admitted token cannot overwrite intervening
state.

## Authentication boundary

The following native behavior remains unresolved in the retained evidence:

- proposer scheduling at `0x4b31e70`;
- block/QC/timeout digest construction at `0x454c050`;
- signature recovery at `0x14c6f50`.

`AdmissionAuthenticator` isolates those operations. It receives typed signing
fields and opaque signatures and returns recovered validator identities, which
this crate compares with the claimed addresses and selected stake set. No API
accepts a caller's `is_valid` boolean. This boundary is not a claim of
end-to-end cryptographic verification. An embedding implementation must
authenticate the supplied block identity consistently with its recovered
digest implementation.

The crate also does not implement networking, proposal construction, commit
walking, transaction execution, persistence, timers, or the already-existing
timeout-transition component.

## Qualified QC-row byte field

The separate `qc_recovery_byte` module implements the one-byte field transition
at node94 `0x4c7e4f3`, conditional on successful preceding row groups. Its chosen
safe API uses charge state and a borrowed input slice; it does not recover the
native ABI, error layout, machine store order, preceding groups or a full QC
decoder. It is independent of the admission and authentication paths above.
All 256 byte values are uninterpreted here; cryptographic validity is unproved.

The existing manifest/lockfile builds this module without new dependencies.
The `qc_recovery_byte_input_only` example receives inputs on stdin and contains
no expected answers. The compiled comparison, frozen native-derived boundaries,
source controls and exact tool identity are documented in
`research/work-items/RE-008-qc-recovery-byte-rust-94/`. Its qualified field
comparison advances no whole consensus gate.

## Qualified QC group projection

`qc_fd_group::read_mode1_fd_group` separately reconstructs the final value,
input suffix and charge of the mode-1 four-success FD-word path at
`0x466bf60..0x466c13f`. It consumes 36 encoded bytes, charges 32 and writes the
observed 40-byte helper result view. See
`research/work-items/RE-008-qc-fd-group-success-94/` for native evidence and
frozen vectors. Its outside-domain rejection is a chosen safe API. No complete
QC decoder, native ABI, failure behavior or cryptographic validity is claimed.

`read_mode1_fd_group_outcome` additionally reconstructs the first short FD/EOF
at each of the four positions, retaining charge and unread partial payload.
It exposes only active incomplete-result fields, with row forwarding rendered
by its input-only research driver. The original bool API is byte-identical.
See `research/work-items/RE-008-qc-fd-group-short-94/`; other markers, nonadmitted
states, inactive error bytes and full QC-row reachability remain unqualified.

`qc_mode0_group::read_mode0_group` separately covers the complete eight-byte
mode word being zero. It composes four accepted 0..FA/FB/FC/FD scalar reads,
including nonminimal little-endian encodings and the first short/empty input.
Charge and limit are unused under that premise. Its independent 96-vector
compiled comparison and native/negative-control evidence are in
`research/work-items/RE-008-qc-mode0-group-94/`. The existing manifest and lockfile
build it with standard-library conversions and no new dependencies. Its chosen
safe outcome type, atomic outside-domain rejection and driver-only row error
projection do not recover native ABI, inactive error storage or full QC decoding.

## Reproduce

From the repository root:

```sh
shasum -a 256 artifacts/node/94/hl-node
python3 -m unittest tests.test_block_admission_path -v
cargo +1.94.1 fmt --manifest-path src/node94-consensus-admission/Cargo.toml --check
cargo +1.94.1 build --manifest-path src/node94-consensus-admission/Cargo.toml --locked
cargo +1.94.1 test --manifest-path src/node94-consensus-admission/Cargo.toml --locked
cargo +1.94.1 test --manifest-path src/node94-consensus-admission/Cargo.toml --release --locked
cargo +1.94.1 clippy --manifest-path src/node94-consensus-admission/Cargo.toml \
  --locked --all-targets -- -D warnings
```
