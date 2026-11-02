# Source bridge and qualification boundary

This is the source-phase companion to the immutable pre-Rust proof and corpus.
The source is the actual dependency-free MIT `node94-consensus-admission` package
at baseline `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, with one new module and
integration target, one module declaration and one README section. Cargo.toml,
Cargo.lock, the existing public types, authentication and state code are unchanged.
No pending QC, block, batch, bincode or action-signable implementation is used.

The pre-Rust freeze is `dc729f9dd4d9a794daad2dd5f7d538080c3c0266fc37be512d90ec46a71a3f5c`.
Its 49 original inputs remain unchanged. The parent pre-code gate and independent
peer reviewed that conditional native proof, input protocol and corpus before
this Rust existed. The source freeze records a later phase, and is not itself a
compilation verdict. All reviews derive from one captured target/project lineage.

## Value and ownership relation

`TransactionHash` is the existing public tuple type over `[u8;32]`, with derived
unsigned lexicographic `Ord`. `BTreeMap` is used as the finite unique-key relation;
its shape and comparison trace need not match the native tree. `B` is unconstrained:
`Arc<B>` carries the complete opaque block/proof object without selecting fields.
No source hashing, authentication or supplied-row agreement check is inserted.

Destructuring the owned input moves its block, optional rows and 12-byte time.
The first branch returns provided rows unchanged. It neither invokes nor inspects
either view provider. `Some(empty)` therefore preserves the supplied outer Arc;
it differs from an absent empty hash list, which creates a new empty rows Arc.
Dropping uncalled closure environments can have effects outside this projection;
"unused" promises no provider invocation, not arbitrary destructor neutrality.

On the absent path the hash provider is called once. Its length is converted to
u64, passed to the actually used `checked_row_bytes`, then reserved with
`try_reserve_exact` using the real Rust row layout. The arithmetic helper computes
`40*n` with checked multiplication and checks both signed native span and host
usize/isize representation. Its returned number is not a Rust allocation-size
claim. The frozen scalar cases assume the pinned 64-bit host; narrower hosts can
refuse more. Fallible reservation is a new safe policy. A later `Arc::new` failure
is not converted into a recovered native Result.

Only a nonempty request calls the map provider, once. Before loop iteration i,
rows have exactly the first i requested hashes and a clone of their actual map
value Arcs, including every duplicate. A successful lookup appends that hash and
one `Arc::clone`; no sort, deduplication or equality-by-bytes substitution occurs.
The loop visits hashes in their original order. The first absent key drops the
prefix explicitly, then the owned block, and returns exactly that full 32-byte
hash. No later lookup occurs and no prefix escapes. All other safe errors also
consume the owned input. Successful output moves the original block and time
and wraps the completed rows in a new Arc.

For each value object, the result's extra owners equal its successful row
multiplicity. Supplied outer Arc clones do not clone its inner owners. On a
missing hash, every temporary prefix owner is released; after successful result
drop all temporary owners are released. The borrowed map remains unchanged.
These are ordinary source ownership claims. Native correspondence still requires
the complete PROOF.md premises: live disjoint stable views and ordered tree,
ordinary helper/copy/comparison frames, successful allocations, and every
successive native Arc increment staying positive signed, including repeated
aliases. Native allocator/layout/abort thresholds, atomic instruction traces,
arbitrary payload Drop effects, unwinding and whole-client behavior are excluded.

## Independent inputs and measured observations

`driver.rs` accepts only the frozen opaque-ID/fixed-width input framing on stdin.
It has no file access, expected-output parameter, validity flag, branch trace or
oracle dependency. It builds distinct pool Arcs even for equal bytes and aliases
them only by the explicit input object IDs. Valid map views are admitted only in
strictly increasing unique-key order; invalid lengths, order and IDs become
checked Result values, with no sorting/repair. Preparing those Results before the
call is distinct from the API's measured invocation of their providers.

The driver measures output payloads, actual Arc pointer identity, provider calls,
map contents, strong ownership counts and block Weak liveness. There is no strong
block keeper; `Weak::upgrade` observations are immediately dropped. A supplied
rows keeper holds only the prescribed additional outer owner. The result is
dropped before after-counts are observed. An unexpected new value Arc is encoded
with pool ID `u32::MAX`, which cannot name a valid fixture object. This makes a
copy-by-bytes mutant emit a complete unequal observation instead of preventing
comparison; it changes neither the frozen expected frames nor production API.

The parent comparator alone reads `expected.tsv.gz`. It requires all 361 IDs in
order and byte-exact outputs, rejects malformed/duplicate/missing/extra output,
and retains each actual stream. The independent pre-Rust finite-relation oracle
uses equality and identity multiplicities, not BTreeMap/native node walking.
The corpus covers 322 ordinary projections, 19 invalid unused-view projections,
11 new safe view refusals and 9 scalar count boundaries. Reservation failure is
not fabricated. A successful finite fixture assumes allocation success.

Ten integration tests separately exercise opaque block/proof transfer, supplied
empty versus absent empty, both view errors, request order and alias multiplicity,
equal-byte distinct objects, first-missing cleanup, all 32 key bytes, a 256-entry
map and native span boundaries. These are authored-source tests, not independent
native executions or additional target-source lineages.

## Frozen build procedure

`build.py` first admits the original proof freeze, every actual source file,
every harness input, the unchanged one-package manifest/lock and all 97 pinned
Rust 1.94.1 bin/lib payloads. PREBUILD-CHECKS.json records the actual source and
lexical/canonical ancestor configuration audit. FORMAT.json is a retained
format-only repeat; no compilation occurred at that checkpoint.

After a separate source/build gate, the harness copies the full real package and
license into a fresh direct `/tmp` child. It invents no Cargo workspace or package.
It rejects symlinks, build scripts, dependencies and unexpected ancestor Cargo or
rustfmt configurations, uses a fresh CARGO_HOME and a scrubbed offline environment,
and checks actual Cargo metadata against one package and its real targets.
Both lexical `/tmp` and canonical `/private/tmp` build prefixes and the toolchain
prefix are remapped. HOME is preserved for host tools but never recorded as a
public value; an unexpected home path in raw output fails admission for publication.
Commands, exact raw stdout/stderr, timeouts and launch failures are retained before
verdicts. An output-root private map remains outside the public packet.

The planned commands build the real library and link the input-only client in
debug/release, run library plus the new integration tests, and run clippy on the
actual targets. The baseline evidence_contract target is compiled by clippy but
not executed by the selected tests; no broad repository or captured-evaluator
test is called. All 361 values run in both profiles and a second clean build at
the identical physical path. Raw rlib/client equality is measured for that
same-path repeat only. Another root-directory run does not imply raw identity.

MUTANTS.json freezes 17 exact original-source edit coordinates: eager views,
empty-map eagerness, sorted/deduplicated/reversed requests, last missing first,
copied value/provided objects, leaked block/prefix, altered missing hash/time,
wrong row width, rejected final valid count, wrapped size and supplied-empty
fallthrough. Each must actually compile and emit all 361 outputs with a nonzero
mismatch in both profiles; a planned mutant is not a passing control. Eight
comparator corruptions and ten parser/argument/empty-input checks also run.
No expected value is changed to accommodate a build or surviving mutant.

Generic receipt/copy/remap machinery was adapted from this campaign's own MIT
client-batch build.py, SHA-256
`c1ddbaa114c504ce6ce7a74ebf7d336be1a5fdf9d8adcc7886518161238d7088`.
It is retained locally here and has no runtime dependency on that pending source
or packet. The current driver, API and mutation semantics are join-specific.
Toolchain executables, selected linker/SDK files and raw streams are pinned;
the host OS/dyld and whole SDK are not hermetic. No target binary or emulator is
executed. Source freeze precedes all actual build qualification; results and any
first failure must be added later without rewriting the original freeze.
