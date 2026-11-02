# RE-001: Rust for the three node94 snapshot-admission prefixes

Target node94 SHA256:
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Base e5c9b6436876b2a4a39daef813171f9879317699.
Component: abci/storage admission. This is a selected control-flow projection,
not a complete checkpoint API, filesystem operation or original Rust ABI.

## Existing evidence and gap

Credit merged #1082 and RE-001-snapshot-admission-94. It already binds all three
owners and their prefixes, labels and controls but contains no Rust implementation.
This adds the one shared raw-word predicate, keeping all three copies in one PR.
Original records, FDE/CIE identities, full exports and earlier failures remain
untouched. No unlicensed inferred code was copied.

Full owners in original ELF VAs:
0x220bed0..0x220c477, 0x42e73d0..0x42e797d,
0x42e7980..0x42e7f2d. native-records.json retains their complete hashes and exact
prefix outcomes. Original complete exports are in the credited packet.

Raw u32 tag1 enters a u64 freeze-target comparison. Past freeze reaches the
assertion branch before the periodic test. Equal target reaches freeze even at
a periodic height. Other selected states reach periodic iff height is divisible
by10000, including zero, otherwise skip. The source returns those branch
classifications; it does not run a captured assertion or pretend to perform
snapshot writes. Arbitrary raw states do not establish live-node reachability.

## Expectations and real builds

FREEZE.json and fourteen smoke rows were committed at915ccd5e before production
Rust existed. Actual selected prefix instructions plus separate order/divisibility
equations generate240480 comparisons across three lanes, representing80160
distinct raw tag/height/freeze triples. Lane identifiers are metadata; the shared
Rust predicate has three raw-word inputs. Repeated inputs across different native
owners are not counted as three distinct input spaces.

Both actual rustc1.94.1 opt0/opt3 libraries, separately linked with input-only
clients and overflow checks enabled, match all240480 rows. Compiled target smoke
passes. Actual period/past-freeze/tag mutants mismatch216/51/162rows and each
fails its compiled smoke assertion with exit101. Identical opt3 recipes yield
raw-identical own host arm64 rlibs; no original target-byte equivalence claim.

The build work completed and printed its final report, then the external
resource supervisor hit a child-exit EPERM race. That wrapper's exit1 is retained,
not relabelled success. Saved profile outputs and source SHA were rechecked.
The supervisor outside this PR was corrected only to ignore that race after
positively reaping its exact child, and bounded busy/quick-exit probes passed.
Subsequent focused/style/catalogue commands exited0 under the repaired limiter.

All11 focused tests pass in225.000wall seconds with10%active-time duty cycling,
including existing actual instruction/owner/signed-immediate mutations for all
three lanes. Pinned rustfmt, Clippy library/test and catalogue-check pass.
The OS denied setpriority; nice19 is not claimed. The source is no_std and adds
no dependency, placeholder workspace, captured executable or network call.

## Reproduce

From repository root with authenticated inputs and actual pinned1.94.1 tools:

    python3 tools/snapshot_admission_rust.py --rustc "$RUSTC" --output /new/output
    python3 -m unittest tests.test_snapshot_admission_rust tests.test_snapshot_admission -v
    "$RUSTFMT" --check --edition 2021 src/node94-snapshot-admission/lib.rs src/node94-snapshot-admission/input_only_driver.rs
    "$CLIPPY" --edition=2021 --crate-type lib src/node94-snapshot-admission/lib.rs --emit=metadata -o /new/library.rmeta -D warnings
    "$CLIPPY" --edition=2021 --test src/node94-snapshot-admission/lib.rs --emit=metadata -o /new/tests.rmeta -D warnings
    make doctor verify test catalogue-check reproduce

For rustfmt use separate arguments --edition 2021. Output directories must be
new; the runner checks frozen input/output hashes before invoking any compiler.
build-result.json retains exact compiler, recipes and source/output identities;
$REPO/$OUTPUT/$RUSTC replace path spellings only. Full generated corpora and raw
build products stay outside Git; the committed fixture is14smoke rows.

Shared input/import/reproduction checks reuse the completed#1831 results only
after checking that their explicit dependency paths remain byte-identical to
the same base. shared-input-validation.json records that narrow scope.
New Rust/native-focused and catalogue checks are fresh; a reused input check
is not verification of new code. Full make test awaits upstream CI and is not
claimed passed. Signatures, canonical inventories and original pins are retained.

## Remaining work

No snapshot content schema, helper effects, file writes, housekeeping, original
typed lane ABI, source-byte match, whole CFG or node compatibility claim.
Existing decoder tests retain immediate sign-extension and wrong-field controls.
All full component/catalogue gates remain unchanged. Next recover the snapshot
helper and app-hash handoff before joining this scalar projection into a complete
checkpoint path.
