# RE-002: node115 complete GNU Build ID descriptor scan

Component foundation; task RE-002. Linux x86-64 node #115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes. Main base `05bc2de303c05525b71e7e257426e741bc66a390`.
Coordinates are linked ELF VAs, without rebasing or byte normalization. New
Rust/evidence/scripts are independently authored MIT. Collector/verifier
scaffolding reuses the project's MIT metadata research collector; scope and
instruction obligations are newly derived for this function.

## Gap, outcome and provenance

The existing std census identifies Object::build_id and compares dependency
bodies, but does not provide this complete buildable parser contract, malformed
section/note policy or a target-bound caller/result qualification. This outcome
reconstructs that entire selected leaf as `src/node115-elf-build-id`, without
inventing an ELF Object constructor or original workspace. Build provenance
and the actual runtime's build-id consumption are RE-002 concerns. This is a
reconstruction of captured node code, not standalone tooling polish.

The primary FDE is **0x5c948e0..0x5c94a72:402 bytes/112 instructions**.
It has no calls and no LSDA, so there is no hidden leaf helper or imported
allocation to stub. One real consumer's complete FDE
`0x5c83460..0x5c84111` supplies context:3,249 bytes/660 instructions.
Total retained export denominator is **two FDEs,3,651 bytes/772 instructions**,
49 calls and114 branches. This is an export denominator, not a claim that the
whole caller is reconstructed or that these bytes match new compiled Rust.

The existing std census attributes the helper to public Rust std's gimli ELF
Object::build_id. It already records raw source/target inequality. Recovered
logical semantics do not create private-node or dependency byte credit; all
92 full-scope gates and registered comparison totals remain unchanged. No
public or unlicensed inferred parser source was copied. Live PRs, issue state
and recent merges were checked before selection and again before submission;
no overlapping Build ID outcome was found and no issue was opened/claimed.

## Valid borrowed Object view and section selection

The actual leaf reads file pointer/length at object+0x18/+0x20 and section
record pointer/count at +0x28/+0x30. Each record is64 bytes. The new API accepts
`file:&[u8]` and `section_headers:&[[u8;64]]`, projecting that already-valid
borrowed Object view. Header decoding, ELF magic/class validation, endianness
selection, extended section counts and Object ownership remain outside it.

It scans records in supplied order, selecting type dword+4 exactly7. File
offset is qword+0x18 and size qword+0x20. An offset beyond file length or size
beyond the remaining bytes skips that entire section, rather than aborting
later sections. Empty sections produce no candidate. The logical safe wrapper
may bounds-check an empty span where the native code constructs a dangling
empty pointer; it does not claim that pointer ABI or invalid raw references.

Raw section alignment is qword+0x30. Values **0,1,2,3,4 all select width4**;
exactly8 selects width8; other values are skipped. This is the actual numeric
predicate, not a strict ELF-format validator that refuses 0/1/2/3 or accepts
every power of two. Note alignment is relative to each note's start, not an
absolute file-address rounding operation.

## Complete note traversal and descriptor admission

A remaining note span shorter than12 ends this section. Three little-endian
dwords provide name length n, descriptor length d and type. The name must fit
after its12-byte header; descriptor start is `round_up(12+n,width)`, and the
unrounded descriptor end must fit inside the current section span. Any failure
abandons this section; later section records are still considered.

Name bytes are trimmed of **all terminal zero bytes**. A trimmed name exactly
`GNU` and type exactly3 returns the descriptor pointer and its original dword
length immediately. Thus `GNU`, `GNU\0`, and `GNU\0\0` are accepted names;
`GNUx`, `GNU\0x`, empty/all-zero and prefixed-zero names are not. The first
match in section/note order wins, without comparing descriptor lengths or
requiring a nonempty ID. Some(empty) is distinct from None.

For a nonmatching note, next offset is
`round_up(round_up(12+n,width)+d,width)`. If it reaches or exceeds the remaining
section length, traversal advances to the next section. Otherwise traversal
continues at that offset, provided at least12 bytes remain. A matching
descriptor may therefore be accepted even when **final descriptor padding is
missing**, as long as its actual bytes fit. Prevalidating the padded extent
before matching would reject inputs this native function accepts.

All n/d values are u32, so their header/alignment arithmetic fits the selected
64-bit domain. File offset/size values remain u64 and are checked against real
borrowed slice bounds. The safe Rust code uses immutable slices and produces
an actual borrowed descriptor; no fake pointer, allocator or reader is used.
Invalid raw pointers, concurrent mutation, non-64-bit behavior and native
struct/Option niche layout are excluded.

## Real consumer and exact static evidence

At **0x5c83ea2**, the retained caller passes its actual parsed local object to
this leaf via E8 at **0x5c83ea9**. At0x5c83eae it tests returned RAX for zero;
subsequent instructions use returned RDX in its length relation and compare
bytes through actual dynamic slot **0x64df9f8 -> bcmp**. That importer is
resolved from its dynamic symbol and relocation, not guessed by address.
Object construction and the rest of this consumer's cache/file/debug
resolution are not closed. A bytewise E8 lead scan also found another site
0x5c6c689; both sites were qualified as instructions within actual FDEs, but
this packet does not claim a complete direct/indirect/tail-call census.

`records.json` retains complete body hashes, FDE/CIE bytes, all selected
instructions/control-flow/relocation context and15 actual instruction windows.
GNU2.45/LLVM23.1.4/Capstone5.0.7 instruction partitions agree byte-for-byte;
GNU readelf independently confirms both full FDE extents. No masks are used.
The verifier reproduces every raw native export and record, rejects15 actual
instruction-window corruptions below whole-artifact hashing, rejects the
bcmp imported-writer mutation, and separately rejects wrong/truncated capture
identities. No mutated captured instruction executes. Source helper and ABI
claims are kept separate from the supporting caller inventory.

## Pre-Rust independent qualification and actual captured-file read

Before production Rust existed, oracle.py/freeze.json fixed **25,486 cases**,
fixture SHA256 `6d9703933ed6e858f74f791c97a43326b8bfbe072a467ecbd9e3c2749936464a`.
Lossless gzip(mtime0) hexadecimal bytes are retained and must reproduce exactly.
The Python oracle derives candidate intervals using division/concatenation;
Rust uses incremental borrowed slices and bit alignment. These are independent
mathematical implementations, not a captured instruction evaluator or runtime
comparison. Deterministically seeded cases use only synthetic offline bytes.

Cases cover type/alignment combinations, invalid offsets and u64 length,
truncated note headers/names/descriptors/padding, both alignment widths, all
relevant GNU name variants, empty descriptors, multiple sections/notes, first
match ordering and actual captured note bytes. Rust opt-level0 and3 each match
all25,486 rows. Eight separately compiled mutants exit normally and differ:
wrong section type, refusing zero alignment, losing width8, trimming one NUL,
wrong note type, requiring final padding, aborting the file on a bad section,
and using width4 for width8 descriptor positions. First witnesses and actual
compiler/stdout/stderr/source identities are retained in qualification.json.

The compiled library was also applied as a **file parser** to the authenticated
artifact's real file bytes and section records. It returns offset812/length20,
ID `ac2880fcda5e49007a8e4fb1ea6aa7dd1b2eae01`, exactly matching an independent
GNU `readelf -n` report. This executes only new host Rust over bytes; it does
not run, load as a process, emulate or invoke a captured code entrypoint.
The probe's ELF-header extraction is harness-only, not a claimed Object parser.

The initial pre-Rust generator incorrectly expected an `alignment` key from
the shared section reader. It failed before freezing any fixture; the original
freeze.log remains in ignored work. It was corrected to read the actual raw
ELF64 section record. Only then were expectations frozen, while Rust was still
absent. The oracle/fixture/scope hashes have not changed after that freeze.

## Reproduce and limitations

From repository root after sourcing the existing local pinned environment:

```sh
source work/environment/new-three-env.sh
python3 -B research/work-items/RE-002-elf-build-id-115/collect.py --out work/build-id-static-fresh
python3 -B research/work-items/RE-002-elf-build-id-115/verify.py --out work/build-id-static-check.json
python3 -B research/work-items/RE-002-elf-build-id-115/qualify.py --out work/build-id-qualified-fresh --rustc "$RUSTUP_HOME/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc"
cargo +1.95.0 build --offline --locked --manifest-path src/node115-elf-build-id/Cargo.toml
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-elf-build-id/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-elf-build-id/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-elf-build-id/Cargo.toml -- -D warnings
```

Host and Linux/amd64 release rlib builds, fmt and Clippy pass. Linux emits an
rlib and does not execute it. Python3.14.5/Rust1.95.0 and native versions are
recorded. Final publication runs doctor/verify/catalogue-check/reproduce and
13 catalogue tests. The unchanged main-base583-file qualification(25 skips)
is explicitly reused, not reported as a fresh full make test. There is no
hosted CI, container, full consumer, original ABI or whole-node equivalence
claim. Whole-ELF identity and original Object construction remain open.
Next bind the actual object-construction/ELF-header validation premises and
consumer byte-comparison/cache ownership before integrating this leaf.
