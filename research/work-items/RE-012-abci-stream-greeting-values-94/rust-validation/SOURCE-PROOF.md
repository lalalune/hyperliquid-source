# Source bridge to the immutable pre-code relation

This is additive source-phase documentation. The original165 packet files,
PRE-RUST-FREEZE0ac42f74f8e2820807845f356a1eda0a2eb89760b887411665c8cd909011e7e3,
proof, oracle and18,290 expected frames remain unchanged. Source authoring is
authorized by the coordinator gate on current main966865f1637a29ce75b019e1bf11d5529cc6f519.
No source build or client execution is claimed here. The source/harness freeze
and a separate gate must precede any compilation or mutant run.

## Actual package and scalar provider

The actual package is `src/node94-abci-greeting-values`, with one dependency:
the existing MIT `hl-bincode-varint` at `../bincode-varint`. Its six source,
manifest/lock, documentation and test files are unchanged. Root LICENSE and
rust-toolchain.toml complete the proposed context pins. No new root workspace,
registry package, build script, proc macro, unlicensed reference code or pending
wrapper source is used. Eight preparation commands obtained the actual lock and
two-package metadata offline, queried four tool versions and formatted/checked
the authored Rust. They did not compile or run source. PREPARATION.json binds
the original private raw streams; SOURCE-AUDIT.json records the admitted graph.
The old provider's reader_vectors/evidence_vectors integration tests are pinned
context and are not rerun by this qualification. Cargo builds its actual library
as the new package's dependency; only the new package's16 focused tests run.

The baseline provider's `read_u32` and `read_u64` consume an available marker
before errors, retain short payload bytes, accept nonminimal encodings and
decode Little payloads with raw expected categories2/3. The existing
`decode_u64_slice_fast` requires at least9 remaining bytes, consumes only a
supported complete value and distinguishes rejected markers. These exact
source properties match the already merged Reader/fast-path contracts.

Reader::u32 first charges4. If remaining>4 and marker>=253 it constructs the
proved expected2/found3/4/12 error without calling the consuming provider.
For all other inputs it calls read_u32 and commits its resulting suffix length
on success or error. A supported fast marker's payload always fits in>4 bytes,
so using the Reader for that success has the same value/consumption. For a slow
input, the public Reader already has precisely the required error state.

Reader::u64 first charges8. Remaining>8 uses decode_u64_slice_fast; success
advances by its consumed length, while rejection advances nothing and maps
254/255 to found4/12 and expected2 (or5 for the usize-kind leaf). The provider's
FastPathUnavailable arm is unreachable under that exact guarded source call.
At remaining<=8 it calls read_u64, commits the suffix even on error, and keeps
expected3 or substitutes the independently proved usize expected5. No success
value is cast to host usize. This preserves the fast/slow u64 counterexample;
calling read_u64 at every length would fail the frozen corpus.

## Reader invariant and charge composition

Reader fields are private. Its constructor admits a safe immutable slice of
length<=i64::MAX and cursor<=length. `None`/`Some(limit)` represent exactly the
full canonical native u64 tags0/1; invalid upper flag bits are unrepresentable.
The constructor intentionally does not require charged<=limit. All successful
mutations keep cursor within the same input; remaining is derived as length-
cursor, avoiding separate incoherent fields. Remaining bytes are a borrowed
suffix and no method mutates the input, limit or an escaped external object.

charge(amount) uses checked_add before storing. Overflow returns NativeError::
LimitExceeded and preserves the old word. A finite sum is stored before its
limit comparison, and an excess returns the same native kind with that stored
sum. `None` skips all arithmetic and preserves arbitrary charged. These cases
cover the complete u64 domain and do not depend on test sampling.

fixed<N> charges first, reports needed=N-remaining without fixed-byte
consumption on shortage, otherwise copies exactly N from the available suffix
and advances N. N is only1/20/32/2048 at call sites. Valid slice bounds prove
cursor+N cannot overflow. The source's infallible bounded array copy has no
opaque callback; its value/state relation matches the native ordinary-return
copy under the pre-code imported-copy premise, not its instruction timing.

vector reads its length, charges it, then compares that u64 length against
actual remaining. The constructor's span bound makes remaining's u64 conversion
lossless. If too large it returns native BulkUnexpectedEnd before allocation
or payload consumption. Otherwise the comparison proves host usize conversion,
and the source reserves/copies exactly those bytes then advances. A refused
try_reserve_exact returns separate HostAllocation with no native-kind claim.
Native count0 still calls memcpy with sentinel1; Rust's empty vector need not
make that call. Only the active ordinary-return relation is compared, under
the original explicitly stated count0 native-call premise.

group reserves32 and refunds8 before each of four u64 reads. After every
successful scalar, charge equals its accepted reservation. Before each refund
it is at least8; checked_sub's expectation cannot fail in the admitted source
path. A failing scalar leaves the full reservation charged. signature executes
two groups in order, then fixed<1>; it preserves all eight limbs and all256
final-byte values. No verification or canonicality policy is added.

map reads count, then only in enabled mode checked-multiplies96 and charges the
product. Product overflow precedes any reservation store; finite charge follows
the shared limit-after-store rule. Each iteration refunds96, reads key20 and
the signature, then inserts. After k successful rows the charge is
C+96*(N-k)+85*k, with C after the count scalar. Before any pending row it is
at least96; a full row consumes85, so every subsequent refund is representable
and the accepted reservation bounds intermediate charges. No count-sized vector
or capacity request is made. With disabled limit, even u64::MAX count reaches
a first read error after finitely many successful rows in a finite byte slice.

## Values, order and ownership

BTreeMap's array keys compare unsigned bytes lexicographically. Inserting the
same key replaces its entire Signature and does not add a distinct key. This
standard container relation is the relation proved for the complete native
tree closure. Native split shape, capacity, parent links, allocator calls and
pointer identity are deliberately not claims about the Rust container.
Signature has no user destructor or nested heap ownership. Source map iteration
in the transport exposes the sorted relation, just as frozen PROTOCOL.md defines.

Each record reads two usize-kind scalars in wire order then fixed<2048>. The
source labels first/second and owns those bytes; it does not imitate the native
stored bytes-before-scalars layout. All three records parse before Box::new
constructs their owned aggregate. The output owns its data rather than exposing
the captured pointer. Standard box/map allocations can abort on exhaustion;
the API does not claim to intercept every host allocation failure. Successful
resource behavior is part of correspondence, as in the pre-code theorem.

decode reads the outer u32 once. Tags2..5 return the matching empty variants.
Tag1 reads three u64 values in wire order. Tag0 reads vector, scalar, nested
tag, then the complete selected nested arm. Nested0 reads H32 and one map;
nested1 reads H32, first map, second map; nested2 reads all three records.
Question-mark propagation stops at the first failing operation without restoring
Reader fields. The Rust locals own any partial/previous vectors or maps, and
ordinary Rust drop releases them on error return. There are no custom user
callbacks. This is safe ownership and active-value correspondence, not exact
native deallocation order/count or an unwinding theorem.

Invalid outer/nested tag errors retain only the exact name, bounds and found
value from the frozen contract. NativeError's other variants retain only needed
or expected/found as applicable. Native padding, inactive union words and
allocation pointers are absent. Error::InvalidState and Error::HostAllocation
are separately documented policies, not native errors1/2 or failure atomicity.

decode_with_limit constructs cursor0, Some(limit), charged0, invokes decode,
and adds consumed only on success. Its Result error has no consumed field, which
represents the caller's inactive word without inventing zero. It allows trailing
input. The core Reader separately provides its post-read state on both outcomes;
that access is not mislabeled as the native caller result ABI.

## Input-only client and focused checks

input_client.rs reads only stdin and command-line argument count. It has no
filesystem/fixture/hash/oracle lookup. Opaque C000000-style IDs are echoed after
syntax/uniqueness validation and never select behavior. It parses exact G94R fixed frames,
validates booleans/op/cursor/counts/trailing bytes, and invokes the actual public
library. It serializes all active values and full core cursor/remaining/charge,
or the selected caller's success-only consumed option. The parent comparison
receives frozen expected bytes separately; no expectation reaches the client.

The transport qualifies frames whose complete input/output counts fit u32 and
whose host allocations succeed. It is not a claim that arbitrary mathematically
large syntactically valid frames always produce an output. All18,290 frozen
cases fit this envelope. Malformed transport or a separate source-policy refusal
terminates with exit2 and a fixed message before publishing its buffered output.
This batch-level publication policy is new client behavior, not a native parser
atomicity claim. Such client policy results are not
native outcomes. Completed native-domain streams must be compared byte-for-byte,
including ordering, ID, suffix state and output count; a partial output or process
failure is not a semantic mutant kill.

The16 focused integration tests currently authored cover empty tags, both scalar
threshold/cursor counterexamples, short payloads, overflow versus finite over-limit
store, bulk-kind1, group reserve, unprocessed map reserve, last duplicate/unsigned
order, second-map error, disabled huge count, three complete records, usize
categories, nonminimal/trailing caller behavior, invalid variants and explicit
safe cursor policy. Inputs are hand-assembled grammar bytes and expected state
is derived from the frozen proof, not from a production encoder. The full frozen
corpus and later compiled mutants supply separate complete-output qualification.
Authored/planned checks are not reported as executed; actual results will be
retained only after the independent source/build gate.

## Qualification harness boundary

build.py admits all five authored package files, six unchanged provider files,
two repository context files, every harness input and all165 old packet files.
It also requires the exact read-only capture before launching any command.
The old static verifier runs from an isolated exact165-file copy with the same
two pinned parser dependencies; its complete validation bytes must match the
historical result. It does not see the new source qualification as old evidence.

Each clean/mutated build copies the actual two-package graph, never a synthetic
workspace or replacement provider. A fresh Cargo home, offline/locked Cargo,
explicit pinned Rust1.94.1 tools, no registry dependencies/build scripts/proc
macros, checked lexical/canonical ancestors and explicit overflow checks define
the host execution scope. The pinned97 bin/lib payload files are rehashed before
and after. The host linker, two SDK inputs and static decoders are recorded and
rechecked; the whole OS/dyld/SDK and target compiler are not reconstructed.

The parent opens expected.tsv separately and gives only vectors.tsv to the
client. qualification.py parses every returned field, checks exact ordered IDs,
sorted unique output-map keys, full frame length and the caller's active option.
It rejects partial/reordered/malformed output and distinguishes a changed active
charge field. Twenty-four source mutants target specific independent native
obligations: charge/store/overflow order, both length dispatches and categories,
marker consumption, reservation/refund, duplicate replacement, signature/record/
triple/map ordering, EOF fields, variant bounds and consumed count. Each must
compile, exit0 and emit all18,290 complete frames before a mismatch counts. A
compile error, crash, timeout, partial frame or surviving mutation stops the run;
it is not a semantic kill. All cases retain their native-conditional label.

The planned run has205 commands,54 complete value streams,16 new integration
tests in each profile,24 mutants in both profiles,12 comparator controls and23
malformed-input cases plus argument/empty-input checks. These are planned counts
until actual receipts exist. Three clean builds comprise initial, same-physical-
path clean repeat and a different directory. Both rlibs and client bytes are
archived privately before the same-path target is removed. Same-path identities
must match; other-directory differences are recorded without masks or an assumed
cause. Raw command streams are retained before status checks, including partial
timeout output and launch diagnostics. Private paths in any raw stream stop the
run and remain private; binaries are never redacted or blindly published.
