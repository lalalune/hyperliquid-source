# RE-005: varint size-counter state in node94

Component: private serialization fork, u32/u64 measured SizeWriter family.
Target node94 SHA256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f,
91774280 bytes. Base e5c9b6436876b2a4a39daef813171f9879317699.
Freeze0798eaac predates the new counter APIs. Existing implementation and
static evidence from merged #10/#48 and subsequent Reader work are credited;
original packets, source pins, failures and licensing remain unchanged.

## Gap and established contract

The existing crate supplies encoded_len_u32/u64 but cannot apply the captured
accumulating size-writer state transition. A real baseline crate builds, while
a client calling count_u64 fails E0425. baseline-absence.stderr retains that
result. This adds count_u32/count_u64 to the existing actual dependency-free
crate, reusing the established length functions rather than another copy.

Original ELF VA/FDEs, fully bound and raw-decoded in owners.json:

| Owner | Full range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| u32 | 0x27ab280..0x27ab2f5 |117|36|
| u64 | 0x27ab5b0..0x27ab64b |155|48|
| u64 copy | 0x4aaa230..0x4aaa2cb |155|48|

These427bytes/132instructions are an export denominator, not original byte
equality or complete panic-path recovery. The evaluator visits129instructions
and stops before each indirect panic call. Original complete capture identity,
FDE extents, anchors, source Locations and call/idiom census are regenerated
through the existing varint producer. Capstone5.0.6 independently partitions
all three complete bodies. The original source Locations name
bincode-fork/src/enc/write.rs:78:9; slot0x576e118 and each actual LEA target
are retained. Exact dependency version/fork differences remain unresolved;
no reconstructed first-party byte credit or public-library source identity is
requested.

For encoded length L in {1,3,5,9} and incoming counter C:

1. C==u64::MAX reaches the overflow-call boundary without changing C.
2. Otherwise a multibyte arm commits C+1 **before** checking the payload.
3. If C+L fits, final counter is C+L and the output prefix is raw qword8.
4. If payload addition overflows, final counter remains C+1 and the caller's
   output prefix has not been written before the call.

A one-byte arm has no payload check and commits C+1 on success. Example:
value251, C=MAX-1 reaches overflow with counterMAX, not MAX-1. A subsequent
one-byte request at MAX reaches the first guard and preserves MAX.
The original result prefix is observed, but this Rust API does not reproduce
its object layout: SizeOverflow is this component's own representation of the
**pre-call boundary**, returned normally. Native panic behavior, unwind,
callbacks and caller policy are not replaced or claimed equivalent.

The native function takes a raw mode byte, whose TEST flags are overwritten
by the following CMP; this selected counter relation is order-independent.
No byte-order argument is added to the new APIs.

## Freeze and actual comparisons

FREEZE.json, native-controls.json, owners.json and25 smoke rows precede Rust.
137250 line-distinct rows =42750u32 +47250per u64 copy. The population uses
285u32 values,315u64 values,30counter words and5raw mode bytes. Repeated mode
bytes and duplicate u64 owners do not create extra logical implementation
states: there are18000 distinct (width,value,counter) states. Values cover
all0..259, neighborhoods of65536/2^32, signed boundary and maxima; counters
include0..11, sixteen words at MAX and the signed boundary. Full inputs/answers
regenerate outside Git and their SHA256s are frozen before compilation.

The evaluator reads the actual instruction stream, allows writes only to
qualified8-byte counter/output regions and synthetic stack, and rejects every
call. No target process, CPU-native captured execution, Unicorn, live IO,
wallet, chain or network is used. This offline Python instruction evaluation
was explicitly authorized. Native outcomes agree with an independent
piecewise integer state equation. Four actual instruction-byte changes alter
threshold/commit/overflow outcomes; whole-body binding distinguishes each.

The initial overflow-control attempt used an already-failing input and did
not change outcomes, so it failed (134.182wall seconds). It is preserved as
FAIL. Correcting that probe to the exact successful MAX-total boundary gives
a completed native freeze exit0 in158.358wall seconds; no failed attempt is
relabeled PASS. Baseline API-absence check completed exit0 in10.306wall seconds.

Real Rust opt0/opt3 libraries each match137250rows; all16integration tests
pass per profile. Three compiled mutants mismatch113085/19590/136440rows
and fail counter smoke(exit101). The first, named atomic-counter, actually
omits the marker store (including the one-byte commit); it is not a separate
whole-function atomicity proof. Own opt3 rlibs rebuild raw-identically. Build
completed exit0 in245.227wall seconds. Twelve focused tests PASS18.251wall
seconds; rustfmt, Clippy library/new-test and fresh catalogue-check PASS in
a combined exit0 run62.302wall seconds. Nonfatal make/xcrun cache warnings
are retained. Exact commands and identities are in build-result.json and
validation-results.json. To repeat the missing-API baseline, first restore the
base revision source with git show (hash in FREEZE), then run the two commands
in baseline-result.json against that source; current source now has the API.
Only private path spellings in command records are substituted; no machine
operand, input or comparison output is normalized. Own-host archive equality
is not original Linux x86-64 binary identity. No target-wide coverage is claimed.

## Reproduce

From repository root, Python3.12.14, Capstone5.0.6 and actual pinned Rust1.94.1:

    python3 tools/bincode_size_state.py --rustc "$RUSTC" --output /new/output
    python3 -m unittest tests.test_bincode_size_state tests.test_bincode_varint.PanicLocationBounds tests.test_bincode_varint.RelativeRelocBounds -v
    "$RUSTFMT" --check --edition 2024 src/bincode-varint/src/lib.rs src/bincode-varint/tests/size_counter.rs research/work-items/RE-005-bincode-size-state-rust-94/driver.rs
    cargo test --locked --manifest-path src/bincode-varint/Cargo.toml
    make doctor verify test catalogue-check reproduce

The build command authenticates the capture and original static records,
regenerates frozen input/output SHA256s and checks retained owner/control
records before invoking a compiler. Output must be new. Direct rustc build
uses the existing crate's edition2024 and real locked1.94.1 compiler, no new
manifest, dependency, lockfile or fake workspace. Compiled tests include all
existing crate integration files, the new frozen counter states and a
sequential partial-update scenario.

The Reader runner only compares reader/cursor equations and cannot evaluate
counter stores or panic boundaries. The component-specific evaluator/driver
is the minimum bridge for this missing implementation; no shared framework
refactor or standalone tooling PR is included.

Shared signed-input/import/inventory checks reuse completed#1831 results only
for explicitly unchanged paths, as recorded separately. New-code validation
is fresh. The operator requested serial low-CPU execution:10%active wall-time
duty, one process group at a time, bounded commands. This is not an exact
aggregate CPU guarantee; setpriority was unavailable. Full make test remains
incomplete and awaits upstream CI; queued is not PASS.

All full component gates and byte-credit/catalogue inputs stay unchanged.
No complete bincode integration, original panic/unwind/effect or result ABI,
whole-node behavior or exact public dependency version is recovered. Next
close the real size-writer caller and overflow handler before integrating
this state relation into an original-compatible encoder.
