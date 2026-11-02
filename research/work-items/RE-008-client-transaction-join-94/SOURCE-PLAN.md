# Source gate plan, not an implemented API

The actual baseline package is `src/node94-consensus-admission` at
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Its manifest/lock are dependency-free;
`BASELINE-SOURCE-PLAN.json` pins the actual 13 package files and root MIT license
read in the parent's clean integration checkout. No pending block, QC, batch,
bincode or action-signable implementation is a dependency. Other pending PRs
touch lib.rs/README.md; that shared integration overlap must be disclosed and
resolved explicitly by the parent. No Cargo files need changing.

After a separate parent pre-code gate, add only:

- `src/node94-consensus-admission/src/client_transaction_join.rs`;
- `src/node94-consensus-admission/tests/client_transaction_join.rs`;
- one public module declaration in existing lib.rs and a bounded README section;
- packet-local input-only driver, real-Cargo qualification harness and receipts.

Proposed public values are `JoinedTransaction { hash: TransactionHash,
bytes: Arc<Vec<u8>> }`, `ClientJoinInput<B> { block: Arc<B>,
rows: Option<Arc<Vec<JoinedTransaction>>>, time: [u8;12] }`, and
`JoinedClientBlock<B>` with the same fields except required rows. Generic B
preserves the complete opaque block/proof payload, not only selected fields.
No existing authentication, block or error type changes are needed.

`join_transactions` consumes the input and receives two FnOnce checked-view
providers: hash slice and `BTreeMap<TransactionHash, Arc<Vec<u8>>>`. Providers
return borrowed views with an appropriate caller lifetime or generic E errors.
If rows are provided, neither provider is invoked, and the same outer rows Arc
is returned. Otherwise invoke the hash provider once, perform checked count/span
admission and reserve temporary row storage. If hashes are empty, do not invoke
the map provider. For nonempty hashes invoke it once and use actual ordered-map
lookup in request order, cloning actual Arcs. The first missing hash aborts and
discards the prefix, consuming the block input; no later lookup occurs.

`JoinError<E>` distinguishes `MissingTransaction(TransactionHash)` from new safe
policies `HashView(E)`, `MapView(E)`, `RowCountLimit`, and `Reservation`. Only the
first has the recovered ordinary native tag1c. A checked `checked_row_bytes(u64)
-> Option<usize>` helper must be called by actual join admission, not only tests.
It checks native `40*n <= 2^63-1` plus host usize/isize representability. Its
successful integer is native span arithmetic, not a claim about Rust row layout
or allocator capacity. `Vec::try_reserve_exact` additionally checks actual Rust
layout/capacity and can refuse. It need not reserve exactly n elements. The
ordinary projection assumes reservation and subsequent outer Arc allocation
succeed; stable Rust `Arc::new` allocation failure is not a recovered Result.

The providers are an explicit safe adapter for deferred input access, not native
callbacks. Their result must agree with the corresponding live native views
when used. The source must preserve unused providers, though dropping captured
closure environments may have arbitrary effects outside the projection. Generic
payload Drop and source/native allocator/refcount internals are not equivalent.
Neither map tree shape nor exact comparison/clone/drop callback traces are public
claims. Borrowed views, immutable shared values, ordinary source Arc identity and
post-return ownership are the intended abstraction.

The input-only driver will use actual BTreeMap/Arc values and opaque IDs solely
to observe Arc identity. It will construct view Result values from raw byte
blobs; closures count accesses to these Results. Invalid unused blobs are not
invalid Rust references. It receives only the fixed-width framing documented in
PROTOCOL.md, no expected outputs, semantic labels, validity flags, branch traces
or Python oracle code. Full expected streams remain in the parent comparator.
Distinct pool objects with equal bytes must remain distinct, and aliased values
must remain shared. Preserve the original block/time, provided outer-row identity,
map contents and reference multiplicities after success/failure and result drop.

Before compiling, freeze the full actual source/test/driver/harness graph and
inspect all lexical/canonical ancestor Cargo configurations, symlinks, manifests,
lockfiles, build hooks and environment. No fake workspace or substitute package.
Use the pinned Rust1.94.1 offline/locked toolchain and retain executable/payload
identities, full command status and raw output. Run library tests plus the new
integration target in both profiles, compare all frozen input-only values, and
clean same-path repeats; another output-directory root replay is independent.
Do not claim cross-directory binary identity without measuring it.

Compiled behavioral mutants should test eager providers, empty-map eagerness,
sorting/deduplication, reverse rows, last-missing selection, byte-based object
substitution, copying provided rows, consumed-block leakage, and skipped prefix
release, alongside every copied time/hash byte and checked-count boundary. Only
compiled, actually distinguished controls count. No captured evaluator is needed;
old PR999 tools/tests and broad make test remain outside this authorization.
No source implementation/build claim exists at this pre-code checkpoint.
