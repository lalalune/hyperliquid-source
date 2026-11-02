# RE-008: client batch verification and retained buffer state

This packet closes the value/state contract needed to add joined client batches
to the existing `node94-consensus-admission` component. On verification failure,
the buffer retains both its appended records and advanced received round. A
second direct call can therefore return `ClientBlockUnexpectedCommitProof`
(tag1a), correcting the earlier packet's unreachable inference. The concrete
empty-stake two-call witness needs no signature, QC-validity or digest oracle.
Successful verification advances confirmed, empties pending, then sends in
order; channel closure retains that state and any already accepted prefix.

**Pre-code stage:** native proof and221 independent input/expectation cases are
bound by PRE-RUST-FREEZE.json for parent review. No new Rust, driver, build, source implementation result or
captured-target execution is claimed by this stage. Parent review gates the
subsequent actual-crate implementation. Read [PROOF.md](PROOF.md) first, then
[PROTOCOL.md](PROTOCOL.md); bulk exports are supporting evidence.

Target: node94, SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Baseline: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Sixteen full FDEs,
10,566 bytes / 2,320 native rows. GNU and LLVM independently decode the same
artifact; this is one project's provenance, not two independent observations of
an executed node. No captured binary, evaluator or emulator is run.

The proof gives exact active errors and fail-fast order, tx-byte hashing through
complete initialized absorption/finalization wrappers, 12 raw time-byte checks,
proof links and saturating child round, retained-error histories and partial
flush. Keccak permutation identity is conditional and credited to baseline
`RE-005-action-signable-94`. Full block digest/signature algorithms, caller poll
reset, wire decode, distributed behavior and queue linearizability stay outside.
The real baseline admission API supplies membership/quorum/certificate rules;
its ambiguous competing-TC-error domain is explicitly excluded from new native
correspondence. Fixture authentication is input-derived and test-only.

Planned source: new `client_batch.rs` and integration tests in the actual baseline
admission crate, minimal module/dependency/docs changes, and the existing baseline
`node94-action-signable` Keccak provider. No unmerged block/QC/bincode source is a
runtime dependency. Exact source pins and owned paths are in
[BASELINE-SOURCE-PLAN.json](BASELINE-SOURCE-PLAN.json). Existing APIs remain intact;
the new timed wrapper/required signer method prevents silently dropping signed
time absent from baseline `SignedBlock`.

Prior work is preserved and credited: `RE-008-client-block-batch-94` / PR999 first
recovered the batch and buffer gates and explicitly left Rust unimplemented; its
README line70 and error-tags row1a missed failed-batch retention when claiming
unreachability. Its evaluator/stub fixtures are historical evidence, not this
packet's oracle. `RE-008-block-admission-94` and the existing admission source supply
verified certificate rules. Pending source PR1509 adds a separate QC-row reader;
shared lib/docs conflict is possible, semantic scope differs. Own pending block
preimage PR1515 is not required. The tag3 outbox-to-remote-client bridge remains
unresolved and is not inferred from matching layouts.

[VALIDATION.md](VALIDATION.md) records actual ordinary/-O static passes:76
negative controls and two deterministic trees per run. Reproduction commands
and raw validation receipts are retained; later source builds remain pending. Native output text is provider/version
sensitive; collector/verifier accept explicit GNU and LLVM paths. Gzip outputs are
ordinary Git blobs via packet `.gitattributes`, not LFS placeholders.
