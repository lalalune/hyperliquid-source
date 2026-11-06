# Retained validation evidence

`validation.jsonl.gz` is a deterministic gzip-compressed JSONL archive with
1,622 records: one header, 1,073 file records and 548 blobs. The original files
total 42,539,157 bytes; repeated original bytes share a blob. Each blob contains
base64-encoded stored bytes and their SHA-256. A file's `blob_id` is its original
SHA-256 and resolves to the corresponding blob. `INDEX.json` repeats the file
inventory without base64 payloads. `CONTROLS.json` indexes actual transport
fixtures, literal expectations, output/error observations and statuses.

Two fresh data-only assemblies produced four byte-identical files. An independent
read-only audit decoded every blob, verified each stored size/hash and index,
reconstructed every private original using the declared byte offsets, and
matched the pinned allowlist and retained originals. It also checked 98 actual
build/comparison/mutation/public command receipts against 196 retained raw
streams. No test, driver, capture or archive helper was executed by that audit.

738 files are exact raw originals. The other 335 replace only 3,140 explicitly
listed private path prefixes; their original and stored hashes, byte offsets,
prefix lengths/hashes and aliases are declared. Every non-prefix byte remains
unchanged. All 565 entries classified as behavioral streams/fixtures that
forbid projection remain byte-exact. Public bytes alone cannot reconstruct the
withheld prefixes. These are scoped command/results records, not conversations,
usage logs, credentials or raw agent traces. Binaries and build directories are
excluded. A bounded pattern scan found no remaining personal path or credential
candidate; this is not a universal secret-absence guarantee.

The original transport suite remains 119 passes out of 121, with both failed
wrong-access-mode descriptor premises retained. The two subsequent controls are
a separate 2/2 suite. A pipe with no readers has uncaptured stdout: its reference
is null, never a fabricated zero-byte observation. Predicted EISDIR/EPIPE names
do not claim syscall tracing. The archive retains the earlier LFS-pointer admission and pc/va-schema
failure receipts; VALIDATION.md describes their corrections.

Original paths in command receipts may refer to an archived file, the separately
packaged corpus or an excluded executable/build product. Such a historical path
is not a claim that every private workspace artifact is published. The nine
separately packaged input/definition references appear in INDEX's
`external_input_references`. Later repository checks are recorded separately.

Archive SHA-256:
`daee309128d81f9fb1f0c3b57fa78bfe292c2db6a2dc788474c1e5ccea8ea78d`.
