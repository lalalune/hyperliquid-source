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

## Block preimage helper

`block_preimage::{block_preimage_len, block_preimage, block_digest}` reconstructs
selector0 from a `SignedBlock` plus explicit `PackedBlockTime`. The separate
time value supplies the three raw words omitted by the baseline block type;
it does not reinterpret `EventTime` or add a calendar-validity check. The
encoder preserves transaction/QC/TC order, encodes signed seconds with zigzag
and emits each nested timeout signature before its body. It ignores the outer
block signature and inactive signature padding.

The conditional native proof and independent pre-Rust expectations are in
[`RE-008-block-preimage-94`](../../research/work-items/RE-008-block-preimage-94/README.md).
Length and native source-span bounds are checked separately before reserving
the preimage buffer. Errors are safe API refusals, not captured ABI statuses.
Digest correspondence retains the credited Keccak identity assumption and
the proof's memory/callee premises. This offline helper performs no signing,
recovery, network operation or admission-state mutation.

## Authentication boundary

`qc_vote_preimage(&qc, signer)` reconstructs variant 1 of `0x454c050`: the
29-byte prefix `Hyperliquid Consensus Payload`, byte `01`, signer20, the
little-endian variable-width hardfork version/start round/vote round, and
block hash32. The result is 85..109 bytes. `qc_vote_digest` applies the existing
independent Keccak-256 component. Votes and signatures are not serialized;
the explicit signer is part of the preimage. The source uses the real local
`hl-bincode-varint` and `node94-action-signable` crates, with Rust 1.94.1.

The [variant-1 packet](../../research/work-items/RE-008-qc-vote-preimage-94/README.md)
retains the full writer/sizer/caller chain, frozen expected bytes and limits.
Native digest correspondence credits the previously identified shared hash
core, without claiming a new formal permutation proof. This addition does not
change `AdmissionAuthenticator` or implement signature verification.

`message_preimages` separately implements the bounded selector-2 timeout,
selector-3 heartbeat and selector-4 acknowledgement preimages established by
[`RE-008-consensus-other-preimages-94`](../../research/work-items/RE-008-consensus-other-preimages-94/README.md).
Timeout encoding includes the explicit outer signer and ordered nested QC votes;
each nested signature contributes eight little-endian varint limbs and byte64,
while bytes65..71 are inactive. Heartbeat options retain absent versus present-empty
distinctions, and ordered row slices preserve the native tree's in-order projection.
The API neither sorts nor constructs native trees. Acknowledgements serialize
signer, random, round in that order. Checked lengths/allocation failures are safe
API errors. Digest helpers reuse the existing MIT action-signable Keccak code;
native permutation identity remains conditional on its credited structural proof.

These offline helpers do not change `AdmissionAuthenticator`, validate signatures
or infer a claimed signer. In particular, its existing timeout recovery method
does not carry that explicit signer, so this addition does not silently wire a
complete native authenticator into admission. The packet retains full native
writer/sizer/caller evidence and the finite tree, memory and imported-call premises.

The following native behavior remains unresolved in the retained evidence:

- proposer scheduling at `0x4b31e70`;
- end-to-end authenticator integration at `0x454c050`;
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

`qc_mode1_group::read_mode1_group` adds the full-word-one reservation domain:
overflow leaves C unchanged, an exceeded limit retains C+32, and both denials
precede marker qualification. Admitted accepted-marker reads reuse the mode0
value/cursor kernel while retaining the independently proved final C+32. Its
BudgetDenied outcome has no need value. The raw view method covers complete
success or initial denial over supplied40-byte memory; other error memory is
unqualified. See `research/work-items/RE-008-qc-mode1-group-94/` for the128-case
pre-source freeze. The original mode0 and FD APIs and Cargo dependencies are
unchanged; no full QC, original ABI or store-trace equivalence is implied.

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
