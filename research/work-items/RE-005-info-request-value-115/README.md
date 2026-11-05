# RE-005: complete Node115 InfoRequest logical value construction

- Task/component: RE-005 serialization, with a bounded RE-012 caller lead.
- Target: Linux x86-64 node #115, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Source/reference base: 05bc2de303c05525b71e7e257426e741bc66a390.
  Generic ELF/FDE parsers are the unchanged tools at that base. No inferred
  can1357 source was read/copied into this MIT implementation.
- Status: native observations plus independently authored typed Rust on a
  bounded valid-input logical-value profile. No acceptance gate requested.
- Scope: all 55 branches of VA 0x273bf30..0x273ebc0 and the nested
  FileSnapshot value constructor, not an HTTP router or byte serializer.

## Question and progress

The base has no named NodeInfoRequest value implementation. Diagnostic names
and nearby request strings alone do not recover its complete value contract.
This packet derives the entire root dispatch/field map, follows scalar,
address, nested-value and map helpers, freezes 190 synthetic whole-value
expectations before Rust exists, and implements that logical value construction.
It preserves native tags even when they differ from inferred source names.
This resolves a concrete serialization unknown, rather than adding an API
feature, inventing a recovered workspace, or claiming a whole-node build.

## Reproduce

Use Python 3.12.1 with Capstone 5.0.7, GNU objdump 2.47, Rust/Cargo 1.95.0
(x86_64-pc-windows-gnullvm in the observed run), rustfmt/Clippy from that
toolchain, native Git Bash, and GNU make 4.4.1. There are no Rust registry
dependencies. Cargo.lock is the actual offline-generated lock of our isolated
component, not a recovered captured dependency graph. See checks.json for
observed commands, source/input hashes, results and declared gaps.

From the repository root, with TARGET_INPUT pointing to the pinned captured
ELF and OUTPUT to a fresh scratch directory:

    python -B research/work-items/RE-005-info-request-value-115/extract_native.py --target TARGET_INPUT --objdump /absolute/path/to/objdump --output OUTPUT
    python -B research/work-items/RE-005-info-request-value-115/evidence_tests.py
    cargo test --offline --locked --manifest-path src/node115-info-request-value/Cargo.toml
    cargo test --release --offline --locked --manifest-path src/node115-info-request-value/Cargo.toml
    cargo clippy --offline --locked --manifest-path src/node115-info-request-value/Cargo.toml --all-targets -- -D warnings
    cargo fmt --manifest-path src/node115-info-request-value/Cargo.toml --all -- --check
    python -B research/work-items/RE-005-info-request-value-115/rust_counterfactuals.py --cargo /absolute/path/to/cargo --output FRESH_NEGATIVE_OUTPUT
    make doctor
    make verify
    make reproduce
    make catalogue-check

Compare native.json, native-disassembly.txt, native-gnu.txt and
qualified-profile.json from OUTPUT byte-for-byte with this packet using the
recorded tool versions. GNU line endings are normalized to LF and its input
filename is replaced with TARGET_INPUT. Printable disassembly drops trailing
alignment whitespace; published command logs drop terminal empty lines and
replace declared operator paths. Original and public log hashes are both saved. Nothing else in the function bytes or
operands is masked. Run the Python checks from the packet directory or by
the explicit path above; they read the committed packet.

The Windows operator ran commands in a minimal secret-free environment under
a bounded Job Object supervisor, with all temporary/cache/build/output/history
paths on D. Static extraction has a 900s total, 300s phase and 180s idle limit;
component command subprocesses have 300s limits. Only independently authored
Rust test executables run. Captured code is neither executed nor emulated.
This packet's standalone commands do not themselves claim Windows Job cleanup.

## Native evidence and coordinates

All addresses are ELF virtual addresses, not runtime ASLR addresses. Every
record in native.json also carries its actual file offset, exact FDE start/end,
body SHA-256, complete instruction bytes and RIP-relative data. Its 23 unique
complete FDEs cover 32,536 bytes / 6,600 decoded instructions. Capstone and GNU
objdump agree on every address/byte partition in those extents. That is decoder
agreement, not compiled-Rust/native byte equivalence. There are 67 selected
actual relocation records; this is not an exhaustive transitive graph.

Root: 0x273bf30..0x273ebc0 (11,408 bytes / 2,238 instructions). The
55-entry signed rel32 table begins at 0x5f45d0; every destination is an actual
instruction start in that FDE. The first-word niche logic uses INTMIN+5,
subtracts four, and masks using the sign bit. Table positions are test-adapter
coordinates, not a stable enum ABI. Index zero includes FileSnapshot's first
String word. Arbitrary malformed memory/unknown native constructors are excluded.

qualified-profile.json re-derives all 55 exact type literals, field names,
construction sequence and helper identities from the static CFG. Both edges
of conditional jumps are traversed; this is conservative reachability, not
machine execution. Optionality/width conclusions additionally depend on the
actual helper/guard instructions below, rather than reachability alone.

- u64-like payloads: 0x26eb010 and 0x26eb1d0 load qword[r15] at
  0x26eb0cf / 0x26eb28f, retaining all 64 bits. The original u64/usize
  source alias is unknown; both are 64 bits on this target.
- u32: 0x26ebcc0 loads eax,dword[r15] at 0x26ebd7f, zero-extending.
- Boolean: 0x26ec100 reads a byte at 0x26ec131 and constructs its Boolean
  tag at 0x26ec1c0. Only valid Rust bool values 00/01 are modeled.
- String: 0x26eb830 clones pointer/length, including zero length, using
  the length at +0x10. Logical Unicode content is preserved without normalization.
- Address: 0x26eba60 and the Some arm of 0x26ebe80 pass length20,
  capacity42 and compact=false through relocation slot 0x64e4d08 to
  0x2eabb50..0x2eabcde (398 bytes). The latter writes 0x7830 ("0x")
  and uses the lowercase alphabet at 0x455d40. All 20 bytes / 40 nibbles
  survive, including leading zeros.
- Optional address: 0x26ebe80 checks byte[r15]==1 at 0x26ebf40.
  The None branch at 0x26ebf8b constructs Null and still inserts the field
  at 0x26ec04f. webData2.user and vaultSummaries.leader are explicit null,
  not omitted or empty String.
- Nested FileSnapshot: 0x273f3b0..0x273f65a. referrerStates has only type.
  l4Snapshots always includes includeUsers/includeTriggerOrders in both states;
  its coin-None guard at 0x273f5ea/5ed skips coin, while includeL4Details
  is omitted when false by 0x273f60b/60e. Some empty coin is retained.
- Fresh ordinary map state: 0x5c558a0 and end-map 0x5c55a00. Insertion
  wrapper 0x2b6cb40 leads to 0x26f3fc0, whose unique-key append path uses
  0x68-byte entries and increments length at 0x26f43c4/7. Request keys are
  unique. Our Vec preserves observed construction sequence, not an unproved
  native hash implementation or general map iteration contract.
- Ordinary Boolean fields are always emitted, including false; only the
  specifically observed nested omission guards remove fields.
  borrowLendUserState, borrowLendReserveState, allBorrowLendReserveStates and
  aqav2InterestHistory are the observed tags; only_use_db keeps its spelling.

The selected set additionally contains Value/request drops, the request clone,
and the full caller 0x2e3ed10..0x2e414d3 (10,179 bytes / 1,723 instructions).
Its direct call at 0x2e3fb58 builds a logical Value after cloning through
slot 0x64e8918 -> 0x2ecf9d0, drops the clone, checks the result and stores
the Value at async-state +0x468. This does not close a network/HTTP endpoint,
later byte serialization, or ownership through the entire async lifecycle.
The diagnostic adapter 0x2773bd0..0x2773be9 references the
NodeInfoRequest::PerpDexStatus name. A diagnostic string alone is not the
field or endpoint proof.

## Implementation and comparison

src/node115-info-request-value contains independently authored typed enums,
an Address alias, a logical RequestValue representation and to_value.
No captured instruction bytes are used by the implementation. It does not
read the fixtures or call the captured ELF. The Rust type layout is our own.

frozen-cases.json (SHA-256
dbeb3498fd3d66c7948832f5a32416162c708284e553c2d4db3da3c72eb7fa9d)
was frozen before the implementation. Its manually transcribed native contract
was checked against the extracted whole-arm field map. Expectations use
independent Python integer/object/bytes.hex operations, not captured runtime
outputs. 190 complete values include default/changed values for all 55 variants,
16 nested flag combinations, 40 u64 boundaries, six u32 boundaries, six Unicode/
control/long-string cases, eight address patterns and four explicit optional
address cases. evidence_tests.py checks all 18 TSV columns against that frozen
input/expectation corpus, not only case IDs or expected outputs.

One Rust integration test per debug/release build exercises all 190 values
through actual public typed constructors. Canonical test-only JSON sorts member
keys; separate assertions check observed top/nested construction sequence.
No string/integer/address value is normalized and there is no relocation mask.

Four counterfactual own-Rust implementations each compiled and failed the
whole-value test with Cargo exit101: dropping false fields, None-to-empty-String,
u64 truncation to u32, and replacing borrowLendUserState with an inferred tag.
Original production source remained unchanged. The portable reproduction script
creates fresh copies only; raw sanitized outputs are preserved in results/.
The Python evidence checks include a same-size actual native-byte width
counterfactual re-decoded by Capstone with a recomputed body hash, a valid
dispatch-slot swap, and explicitly labeled metadata/literal/relocation controls.
These corruption checks are not represented as captured execution.

## Results and limitations

Debug/release value comparisons, Clippy, rustfmt, nine Python evidence tests and
the four expected-failing Rust controls passed their stated contracts.
Before implementation, doctor and verify passed; catalogue-check failed on the
exact clean base with generated inventory drift (559 recorded vs 560 work items).
Both committed README and research-progress SVG were stale, not only line-ending
differences. Original failed diagnostics are retained in the D operator record;
this contribution regenerates outputs through official make catalogue after
staging the new packet and source.

Full make test is not claimed green or freshly completed for this candidate.
The unchanged test_assembled_record_readers_static.py (SHA-256
6eb5b06f04a8d5701d71712b32528a1b516d387960f67fd216a3664f92242138)
has an existing exact-base05 no-progress failure, exit124 after 180s idle,
300s total/phase limit. It copies the entire 105,896,032-byte capture in a
52,495-entry loop. The fix is already in separate open PR2918 and is not
duplicated here. Reusing that exact-base failure does not establish a current
aggregate suite pass or classify all historical failures as unrelated. Actual
final-head commands/results are reported with the PR; any remaining gap stays
explicit.

Still unproved: captured enum/Value ABI and valid native constructors; complete
allocator/TLS/RandomState/hash/panic/unwind/dependency behavior; special
serializer-state errors outside fresh ordinary maps; arbitrary invalid memory;
wire bytes, HTTP/networking, native byte equivalence and integrated node behavior.
No gate, byte-window, component progress or whole-node percentage is changed.
No source output is transplanted or padded to fit native code.

Next question: follow the Value beyond the captured caller and close the actual
later wire writer and request destination, with its errors and side effects.
That is future work, not a completion claim for this packet.
