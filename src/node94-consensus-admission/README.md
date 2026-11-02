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

## Client transaction join

`client_transaction_join::join_transactions` reconstructs the conditional owned
value operation at `0x4548050..0x454859e`. It preserves an opaque `Arc<B>` block
and proof payload, all12 raw time bytes and any supplied outer rows Arc. Supplied
rows invoke neither checked-view provider; absent empty hashes do not invoke the
map provider. Otherwise actual `BTreeMap` lookup preserves request order,
duplicates and shared transaction identity. The first missing hash consumes the
block and releases the temporary prefix.

The [join packet](../../research/work-items/RE-008-client-transaction-join-94/README.md)
freezes the complete native proof and independent input/expected corpus before
this source. Stable valid memory/map views, bounded positive native refcounts,
successful allocation and helper frames remain premises. The source does not
check transaction-body hashes, supplied-row agreement or block/proof validity.
Generic view errors, checked row-span and fallible reservation refusals are new
safe host policies; only `MissingTransaction` corresponds to native tag0x1c.
`checked_row_bytes` is used by actual admission and describes native40-byte span
arithmetic, not Rust layout or allocator capacity. Native atomic thresholds,
arbitrary Drop effects, exceptional paths and whole-client equivalence are not
claimed. Source/build qualification is retained separately in the packet.

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
