# Independently authored source bridge

The real `src/node94-consensus-admission` package gains the public
`block_preimage` module. Existing block/QC/TC/signature types and
`AdmissionAuthenticator` are unchanged. The caller supplies the native time
words explicitly as `PackedBlockTime`; the baseline `EventTime` is not silently
reinterpreted. Source work began only after the independent pre-code gate.

| Conditional native relation | Source operation |
| --- | --- |
| Paired45c4a40/45c4b50 calendar conversion | `PackedBlockTime::timestamp_seconds` uses a signed-floor closed equation; the frozen oracle uses an independent 400-year prefix partition. |
| Block4776d40/4776ab0 measured fields | `block_preimage_len` and `block_preimage` preserve proposer, round, hash order, time, QC and optional TC. |
| QC vote96-byte rows and signature projection | Private helpers preserve each supplied signer, eight little-endian u64 varints and byte64; padding is ignored. |
| Optional TC and184-byte timeout rows | Private helpers distinguish absent/present-empty and emit each outer timeout signature before signer, round and QC. |
| Prefix and hash update/finalizer | The full29-byte domain prefix and tag zero precede the body; `block_digest` calls the credited baseline Keccak implementation on all bytes. Native permutation identity remains conditional. |

The two path dependencies are the existing MIT `hl-bincode-varint` scalar
encoder and `node94-action-signable` Keccak provider. No pending QC/timeout PR is
read or linked. Private block helpers keep this main-based change independent;
later consolidation with other variants requires its own reviewed source
change. The safe API reports `LengthOverflow` or `AllocationFailure`, without
assigning native ABI meanings to those errors. Native source-stride checks are
separate from final encoded length. A narrower host additionally respects its
isize allocation limit. No OOM behavior or giant slice is manufactured in tests.

The input-only client receives `C000000`-style inert IDs and fixed-width input
frames. It constructs existing typed values, rejects malformed/trailing input,
then calls length/preimage/digest APIs. Expected values and semantic names never
enter the client. The parent comparator alone reads the remaining columns of
the immutable pre-Rust vectors. A renamed-ID control verifies that IDs do not
change computed bytes or digest.

`rust-validation/SOURCE-FREEZE.json` binds all32 real package files and the
client/build harness before Rust compilation. `build.py` validates both freezes,
the exact three-package manifests/lock, absent hooks/configuration, lexical and
canonical temporary ancestors, a clean explicit environment and pinned1.94.1
tool identities. It copies the genuine packages with their existing paths;
there is no invented Cargo workspace or package. Native artifacts are never
copied into the build tree, linked, evaluated or executed.

The build procedure runs library tests and the new integration test in both
profiles, frozen input comparisons, malformed-frame/ID controls, two clean
same-path builds, and clippy for the selected library/test targets. It does not
run the broad repository suite or the old evidence-contract integration test.
Seventeen source mutants run in both profiles: wrong tag, negative-second
clamp, truncating negative-year division, wrong epoch, raw seconds, millisecond
nanoseconds, reversed hashes/votes, omitted votes, collapsed empty TC,
signature-after-body, raw65 signature bytes, big-endian limbs, padding as final
byte, zero proposer, one-block hashing and exact-rate truncation. These are
compiled behavioral controls over own Rust, distinct from static byte controls.

Actual build outcomes and retained raw command/output identities belong in
`rust-validation/VALIDATION.md` after completion. Finite source comparisons
supplement the conditional native proof; they are not dynamic target execution,
a proof of cryptographic validity or completion of the authenticator boundary.
