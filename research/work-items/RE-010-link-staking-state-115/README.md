# RE-010: Node115 link-staking logical state transition

- Component: action-dispatch / RE-010.
- Sole target: Linux x86-64 node #115, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Source/reference base: 05bc2de303c05525b71e7e257426e741bc66a390.
- Primary prior research: merged PR2126 and
  research/work-items/RE-010-link-staking-path-115. Its static mapping is
  credited, not presented as newly discovered function coverage.
- New result: independently authored Rust for the whole logical normal
  request/finalize transition, complete resulting maps and ordered writes;
  further native helper/data qualification and frozen corruption controls.
- No component gate or byte-window change requested.

## Scope and evidence status

The prior packet identifies the selected wrapper and normal state effects but
contains no Rust implementation. This contribution implements that established
logical contract with our own typed inputs and real BTreeMap/BTreeSet storage.
It does not invent a native workspace, substitute supplied helper returns, or
claim the captured container implementation/ABI was recovered.

The profile is a valid stable relationship map with unique20-byte keys and
the three row forms written by this path (tags0/1/2), a set of stake keys, and
successful ordinary allocation. It includes missing rows, overwritten pending
rows, unrelated rows, key aliasing, repeated operations and both modes.
It excludes malformed native memory, unestablished raw row states, original
container representation, allocation failure, panic/unwind and complete parent
admission/signature/nonce/wire behavior. The parent gate-selected key is not
assumed to replace the wrapper's forwarded key. Human account roles and the
labels staking/trading follow diagnostic strings; they are not authority,
ownership or an economic-policy proof.

All expected states are independent mathematical expectations derived from
static native branches. They are not captured runtime outputs. No captured
code was executed or emulated. No native instruction evaluator, chain,
network service, signature, key or live user state is used.

## Reproduce

Observed tools: Python3.12.1, Capstone5.0.7, GNU objdump2.47, Rust/Cargo1.95.0
x86_64-pc-windows-gnullvm, matching rustfmt/Clippy/rust-lld, GNU make4.4.1
and native Git Bash. Cargo.lock is generated offline for the actual isolated
component; it has no registry/path dependencies. Captured dependency versions
and a recovered workspace are not inferred.

From the repository root, with TARGET_INPUT the pinned captured ELF and OUTPUT
a fresh scratch directory:

    python -B research/work-items/RE-010-link-staking-state-115/extract_native.py --target TARGET_INPUT --objdump /absolute/path/to/objdump --output OUTPUT
    python -B research/work-items/RE-010-link-staking-state-115/evidence_tests.py
    cargo test --offline --locked --manifest-path src/node115-link-staking-state/Cargo.toml
    cargo test --release --offline --locked --manifest-path src/node115-link-staking-state/Cargo.toml
    cargo clippy --offline --locked --manifest-path src/node115-link-staking-state/Cargo.toml --all-targets -- -D warnings
    cargo fmt --manifest-path src/node115-link-staking-state/Cargo.toml --all -- --check
    python -B research/work-items/RE-010-link-staking-state-115/rust_counterfactuals.py --cargo /absolute/path/to/cargo --output FRESH_NEGATIVE_OUTPUT
    make doctor
    make verify
    make reproduce
    make catalogue-check

Compare native.json, native-disassembly.txt, native-gnu.txt and
qualified-profile.json in OUTPUT with this packet. GNU CRLF is normalized to
LF and its input filename to TARGET_INPUT. Printable disassembly drops
trailing alignment whitespace. Published command logs replace declared operator
paths and drop terminal empty lines; original/public hashes are both retained.
No instruction bytes or relocation operands are masked.

The Windows operator uses a bounded own Job Object supervisor and explicit D
temp/cache/home/build/output/history paths. Static commands have900s total,
300s phase and180s idle limits; Rust subprocesses have300s limits. Only our
Rust tests execute. These standalone public commands do not themselves promise
Windows Job cleanup. checks.json records actual inputs/commands/results.

## Native observations

Coordinates are ELF virtual addresses with exclusive ends, not ASLR addresses.
native.json carries actual file offsets, full FDE bounds/body hashes, decoded
instruction bytes, RIP-relative data and selected real relocations.
There are21 unique complete FDE extents,33,303bytes /7,170instructions and
46 selected relocation records. GNU and Capstone agree on all instruction-byte
partitions in those extents. This is decoder agreement, not compiled
Rust/native equivalence or a whole-component denominator. Some records are
caller/formatter context; the number is not newly reconstructed byte credit.

The wrapper0x58c07d0..0x58c08b8 tests byte[payload+0x3d].
For zero it builds pair(payload20,caller20) and calls0x5611bd0.
For nonzero it builds pair(caller20,payload20), passes context+0x40a0 and
calls through actual slot0x64e7a80 ->0x469fe90.
The payload key comes from+0x28/+0x38, the other key from the forwarded
pointer. The wrapper maps inner0x1a2 to outer0x0e, other results to0x0f.
Inactive result payload bytes are unclaimed.

The prerequisite0x5611bd0..0x5611d79 searches context+0xfb0 using the
first20-byte pair key, including compact lookup0x4556850.
That helper compares20-byte keys and returns zero for found; the wrapper
continues on zero. It reads no stake amount on this path. The tree path uses
the actual imported memcmp slot0x64dfb50. Missing keys produce the31-byte
"Staking user has no staked HYPE" error before the request core is called
through slot0x64e7f20 ->0x469fa60.

The request core0x469fa60..0x469fe8d compares both20-byte keys, then
checks the trading record before the staking record. Normal behavior:

| Mode/condition, in decision order | Result | Ordered logical writes |
| --- | --- | --- |
| Request, stake key absent | Missing stake key | none |
| Request, both keys equal | Same keys | none |
| Request, trading row has nonzero tag | Trading already linked | none |
| Request, staking row has nonzero tag | Staking already linked | none |
| Request, checks pass | success | trading ->(0,staking) |
| Finalize, trading row absent/nonzero/wrong peer | Missing pending request | none |
| Finalize, matching pending trading row but staking row nonzero | Staking already linked | none |
| Finalize, checks pass | success | trading ->(1,staking), then staking ->(2,trading) |

Finalize0x469fe90..0x46a02ea has no stake prerequisite or extra equal-key
guard. Its pending peer comparison covers all20bytes. Both checks precede the
first upsert. At0x46a0259 it prepares tag1, calls0x3ce1080 at0x46a0288,
then prepares tag2 at0x46a029c and calls the same writer at0x46a02b6.
Thus a valid pending self-row can finalize: the last write leaves tag2.
Rechecking the second guard after the first write would change that behavior.
A repeated request may replace the peer of an existing pending row.

The shared writer0x3ce1080 copies the full21-byte value on replacement and
uses compact insertion0x4546140 or tree insertion0x370caf0/0x34dba60.
The observations include the compact/tree threshold branches at32/64 rows,
ring insertion0x4572f70, conversion0x3892d40/0x3dc74f0 and iterator/drop
0x3909130. The conversion copies20-byte keys and21-byte values and stops on
tag3 at0x3dc7658/5b. Inferring3 is an option/iterator sentinel is explicitly
separate from observing those bytes. Stable arbitrary raw3/255 rows are not
claimed valid original types. The general native tree/allocator/cleanup graph
and exceptional conversions are not reconstructed by our Rust containers.

All five ordinary error strings are bound to actual RIP-relative16-byte data
chunks in their producing branches (16 chunk bindings plus the self-error
final immediate word). These cover the full31/36/43/43/45-byte strings.
qualify_profile.py checks those bindings, the frozen36 branch/data anchors,
actual call targets, key-copy instructions and ordered writer calls.
It performs static decoding/data comparisons, never machine execution.

## Implementation and comparison

src/node115-link-staking-state has independently authored Rust types and apply.
Expectations are never passed to it. The implementation receives actual typed
keys, a stake-key set and a complete map; it returns the ordinary outcome and
ordered writes and mutates the real map. Its storage/types are ours, not an
original memory-ABI declaration. Both alias writes are performed in sequence.

frozen-cases.json SHA-256:
ab67314e108401b5f2632b851435d67bc9337b30b3cb8af4bf4c5f930466a923.
The274 full-state expectations were frozen before this Rust implementation.
They cover all six ordinary outcomes, precedence conflicts, pending-peer
replacement, aliases,20-byte key patterns, untouched rows, replay sequences and
map sizes around native threshold observations. Those sizes are logical input
cases, not a claim that captured container transitions ran.

Debug and release each run one integration test over all274 states. The
comparison checks the full resulting map, ordered writes, error identity and
text, and active result tags. Maps are sorted by key only for canonical fixture
representation; native map iteration/physical bytes are unclaimed.
All11 TSV columns are checked against the frozen JSON. messages.tsv is a
verbatim projection from its already-frozen five errorLiterals, not newly
refrozen expectations. frozen_reference.py preserves the pre-Rust mathematical
model, with no production Rust or captured instruction evaluation.

Nine intentionally wrong own-Rust copies each compiled then failed the actual
comparison with Cargo101: adding a finalize stake gate, adding a self-finalize
gate, reversing prerequisite precedence, reversing actual upserts, ignoring the
pending peer, reversing relationship failure precedence, refusing pending
replacement, swapping forwarded keys, and changing native error text.
Production source stayed unchanged. The portable reproduction creates fresh
copies only. Static comparator controls additionally change actual branch/tag
instruction bytes, re-decode and recompute body hashes; other controls are
explicitly metadata/data/relocation/extent/identity corruption, not target runs.

## Results and remaining limits

Observed component debug/release, Clippy, rustfmt, nine Python evidence tests
and the nine expected-failing Rust controls passed their stated contracts.
This is finite target-grounded logical comparison, not an exhaustive theorem,
native runtime observation, native byte match or integrated node test.

An initial baseline doctor/verify returned0 with a missing configured D
temporary-directory warning and fallback. Those logs are preserved; their
temporary-path compliance is not claimed. All configured per-candidate D
directories were then created, actual tempfile.gettempdir was checked, and both
commands passed again with no make fallback warnings and clean source.
The frozen JSON/TSV did not change during that correction.

The base has known generated README/SVG inventory drift (559 recorded versus
560 actual work items). Reused exact-base evidence and file identities are
recorded; official make catalogue regenerates outputs after staging this source
and packet. No generated table or gate input is hand-edited.

Full make test is not claimed passed or newly completed for this candidate.
The unchanged test_assembled_record_readers_static.py SHA-256
6eb5b06f04a8d5701d71712b32528a1b516d387960f67fd216a3664f92242138
has a preserved exact-base05 no-progress124 result after180s idle within
300s total/phase limits. Its105,896,032-byte capture-copy loop is addressed in
separately submitted PR2918; the fix is not duplicated here. Reusing that base
result is not a candidate aggregate pass or proof all old failures are unrelated.
Actual final-head official checks are reported with the PR and D handoff.

Still unknown: original enum/map/ownership ABI, complete native
allocation/iterator/tree/dependency/panic/unwind behavior and failures between
the two native writes; transient or unestablished row states; full parent
classifier/gates, signature/nonce/HTTP/wire/network effects; compiled native-byte
or whole-node equivalence. No complete RE-010/component gate is requested.
New source is MIT; no unlicensed inferred implementation was copied.

Next question: close native container conversions and exceptional update paths
against their original dependency graph before making any native-ABI or
full-function equivalence claim.
