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

## Joined client batches and retained buffer state

`verify_client_batch` and `ClientBlockBuffer` implement the separate bounded
contract in `research/work-items/RE-008-client-batch-state-94`. A batch checks
proof placement, QC round/hash links, real baseline block admission, every
transaction byte digest, ordered transaction hashes, copied raw time, and the
last child/QC proof. It preserves the extra last-block and mismatch-only child
digest calls. Transaction Keccak comes from the existing MIT
`node94-action-signable` path dependency; full consensus block preimages remain
an explicit authenticator boundary. No pending preimage or bincode PR is needed.

`TimedSignedBlock` retains three raw u32 time words omitted from the baseline
`SignedBlock`. `ClientBatchAuthenticator` requires complete timed signer recovery
and block digests, with no default that discards time. The inherited certificate
rules execute normally; the existing TC competing-error ambiguity is not newly
resolved. Fixture authentication in the comparison client is input-derived test
arithmetic, not a production cryptographic implementation or target oracle.

The buffer advances received round and appends before verification. Recoverable
errors retain that state, including the 101st record without a proof. This permits
the documented empty-stake two-call counterexample: missing validator set first,
then unexpected earlier proof. Success advances confirmed and empties pending
before ordered sends. A closed sink returns its current item, drops that item
and the unattempted remainder, and preserves the accepted prefix and advanced
state. `ClientBufferView` is an immutable safe callback observation, not a native
channel ABI or linearizability claim.

All supplied nested native spans are admitted before semantic work. Span or
fallible-reserve refusal leaves buffer state unchanged and is a new safe API
policy, outside native ordinary-return correspondence. Existing dependency
allocations and callback panics are not recovered. No caller poll reset, channel
reader, packet decode, network ordering, native failure rollback or full node
behavior is implemented. Focused source qualification uses the actual library
unit tests and `--test client_batch`; the old `evidence_contract` integration
target is preserved but is not part of that focused run. See the new packet's
source/build receipts for actual performed validation and chronological limits.
