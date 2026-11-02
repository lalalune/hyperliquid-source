# Node94 client transaction join

This RE-008 packet recovers the conditional value/ownership operation at
`4548050..454859e`: preserve supplied rows unchanged; otherwise look up every
requested hash in order, retain duplicates/shared value identity, or return the
exact first missing hash and release the built prefix. The original block/proof
payload and12 raw time bytes remain opaque and unchanged. Supplied rows bypass
both hash and map access; absent empty hashes bypass map access.

Target SHA256 is `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
node94,91,774,280 bytes. Baseline is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
This is a pre-code evidence/corpus freeze; no new Rust implementation or Rust
build is claimed here. [SOURCE-PLAN.md](SOURCE-PLAN.md) describes the subsequent
gated addition to the actual dependency-free consensus-admission package.

Read [PROOF.md](PROOF.md) for the complete ordinary-return argument and premises,
[PROTOCOL.md](PROTOCOL.md) for independent input/expected-value framing, and
[VALIDATION.md](VALIDATION.md) for actual static commands/results. The compact
[records.json](records.json) and full native text archives follow those claims.

The evidence closes the full hash/map/append/missing-cleanup branches, selected
temporary-error drop table, exact row-size limit and no-growth induction. It
binds9 complete core/helper FDEs (2,580 bytes/634 grouped instructions) plus3 full
caller-context FDEs (51,145 bytes/8,727 instructions). The contexts admit local
call sites; their complete poll semantics are not recovered. GNU/LLVM agree on
every exported byte boundary. The39-entry signed error-drop table is retained;
the selected tag1c arm goes directly to POP/RET. All622 non-padding core/helper
instructions are pinned, along with all118 referenced relocation slots. The
complete80,300-entry `.rela.dyn`/`.rela.plt` census does not overlap these bodies.

The independent Python corpus has361 cases, derived before new Rust:322 native
ordinary projections,19 deferred unused-view projections,11 explicit safe view
refusals and9 count-admission boundaries. Its lookup oracle is a flat finite
relation with least-missing-index selection and mathematical owner multiplicity;
it does not simulate a native B-tree or instructions. It includes equal bytes in
distinct objects, shared objects under different keys, repeats, every hash/time
byte, exact first-miss prefixes, supplied-empty versus newly created-empty, and
malformed unused views. The eventual driver receives only opaque-ID input frames.

[Merged PR999](https://github.com/lalalune/hyperliquid-source/pull/999) and
[`RE-008-client-block-batch-94`](../RE-008-client-block-batch-94/README.md) already
observed the join rules and explicitly lacked Rust. This packet credits that
work; it does not claim to discover those rules or fix a native defect. Old
native-evaluator fixtures were read as historical evidence and not executed.
The new full conditional proof, deferred safe API and actual owned-value source
qualification are one coherent contribution. Recent exact/name PR searches
found only999, and newer inspected pathsets through1575 were disjoint; this is
a time-bounded public overlap check, not a private ownership guarantee. Pending
admission-crate lib/README integration overlaps remain explicit in the source plan.

The native contract assumes valid stable ordered-map/hash views, disjoint frames,
successful allocator semantics, ordinary memcmp sign/frame semantics, bounded
positive reference counts even under repeated aliases, and normal block/proof
destruction with no foreign mutation. It excludes raw ABI/layout equivalence,
std/native B-tree shape or refcount thresholds, allocator identity, allocation
failures, arbitrary Drop side effects, concurrent changes, LSDA/unwind, network,
signatures and whole client or node equivalence. One target/project lineage plus
two decoders/reviewers is not independent captured execution evidence. Component
acceptance gates remain false.

New code/proof is independently authored under the repository MIT license. Generic
static export/parsing methods reuse the author's MIT prior packet code with no
runtime dependency on pending work; only two hash-pinned baseline static parsers
are imported. No unlicensed inferred source was copied or evaluated. `.gitattributes`
keeps gzip evidence as ordinary Git blobs, not LFS pointers.
