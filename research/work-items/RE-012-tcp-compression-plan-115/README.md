# RE-012: node115 TCP compression plan in independently authored Rust

Component: transport. Target: Linux x86-64 node #115, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base main `05bc2de303c05525b71e7e257426e741bc66a390`. Coordinates are original
ELF VAs; no rebasing, instruction emulation, byte masking or target execution.

## Gap and scope

The main tree has a TCP framing reader/writer prefix and selected codec
research, but no buildable implementation of the caller's compression choice.
The earlier static-only PR #2768, commit
`9854fc58d8b30e5f78fc74684b2743942aba21d6`, recovered the adapter and explicitly
claimed no Rust. This outcome independently implements those established
semantics as a dependency-free `no_std` library in
`src/node115-tcp-compression-plan`. It does not implement the codecs or claim
additional understood bytes from the reused full-function exports.

The old project's MIT static collector, verifier and original native exports
are retained here with attribution so this main-based PR does not depend on
another unmerged PR. They are unchanged except `verify.py` is named
`verify_static.py`. Their hashes and the full records are freshly reproduced.
No unlicensed inferred source or public codec implementation was copied.
Live open PR titles inspected on 2026-11-04 showed #2768 and the related
static LZ4 #2770/#2771, but no competing implementation of this bounded adapter.
The parent submission workflow must refresh live scope before publication.

## Established relation and instruction obligations

The complete sender FDE is `0x2b7a290..0x2b7b523`. The API covers its selected
initial-arm decision, normal codec-result handoff and existing framing join:

* `0x2b7a2de..0x2b7a2fe`: unsigned n >= 1025, and low16(context dword at
  +0x90) is neither 3998 nor 3999. The real operation is a modular subtraction
  followed by an unsigned **word** comparison. High 16 bits cannot change it.
  The field is not identified as a port, version or message tag.
* `0x2b7a366..0x2b7a3b8`: checked 110*n, q=floor(product/100), requested
  allocation q+24, little-endian **truncated u32** original n, and a sink
  starting after four bytes with capacity q+20. Since product <= u64::MAX,
  both additions are arithmetically safe. Allocator/slice admissibility is
  separate and unclosed.
* `0x2b7a3d8`: n < 65535 chooses 8192-byte scratch and slot `0x64e77a0` ->
  `0x477e950..0x477f036`; otherwise 16384 bytes and slot `0x64e77a8` ->
  `0x477f040..0x477f746`. These are real local observations, not invented
  dependencies. The implementation supplies a plan, not stub compressors.
* `0x2b7a583`: retained codec RAX exactly one enters unwrap failure. Other
  values follow this caller's normal branch. `finish` reports a logical
  CodecFailure for one; it does not claim arbitrary other tags are valid
  native Result encodings or reproduce panic effects.
* `0x2b7a58d..0x2b7a5ab`: reject k > u64::MAX-4 **before** adding four;
  choose L=min(k+4,allocation). The clamp is retained even though valid codec
  success reaching it with excessive k is not established.
* `0x2b7a68a..0x2b7a758`: successful compressed arm keeps marker one, even
  if L >= n. No caller comparison falls back to raw for poor compression.
  Both arms require the selected length to fit u32, encode it big-endian,
  then put the marker at header byte four. Raw bypass uses n and marker zero.

`CompressionPlan` fields are private so the arithmetic invariant cannot be
bypassed by constructing an arbitrary plan. Input lengths are logical u64
values, avoiding allocation and host-usize differences. No native struct,
object ownership, async state layout or ABI is asserted.

The quotient is also tied to the real reciprocal bytes. Let z=floor(x/4),
M=`0x28f5c28f5c28f5c3`, x=110*n after the multiply check. The captured output
is floor(z*M/2^66). Since 25*M=2^66+11 and z<2^62, the extra fraction is
<11/400<1/25 and cannot carry any residue across the next integer. Thus the
output equals floor(x/100), including the largest multiply-admissible n
167697673397359560. This is integer algebra, not target instruction evaluation.

## Evidence and real verification

`collect.py` reauthenticates the complete capture, checks actual FDE extents,
GNU/LLVM/Capstone instruction partitions, relocation writers, source Locations,
call edges and exact operand bytes. `records.json` contains the sender, two
codec and telemetry contexts: 9417 exported bytes / 1958 instructions, not a
reconstructed-byte claim. `verify_static.py` freshly reproduced those records,
rejected 34 actual instruction corruptions without relying on the whole-file
hash check, rejected two identity/truncation controls, checked 1,572,864
eligibility relations and 21,000 reciprocal examples. Original GNU/LLVM/readelf
outputs and options remain retained, without byte normalization.

`oracle.py` is an independently authored branch relation using unbounded
Python integers, the captured modular predicate and division. Its 82,047
unique original rows and oracle source were frozen **before the new Rust
directory existed** (`freeze.json`, fixture SHA
`d047fad965e7ea684609435b7f26ceb30251e6ad761095abbe95ec974b2b1086`).
It is not an emulator, codec, native peer or execution comparator.

The first probe run revealed 96 synthetic k values outside u64, generated by
using allocation arithmetic with an already inadmissible enormous input.
That run failed parsing with a recorded nonzero exit. The original fixture,
freeze, oracle and production source were preserved. The qualifier now filters
only unrepresentable input rows, selecting the **81,951 valid-row subset after
Rust existed**; this chronology is explicit in `qualification.json`.

Both opt-level 0 and 3 compile the actual library as an rlib and link the
probe with `--extern`. Both production binaries exit zero and match every
valid frozen row. Eight actually compiled, normally exiting mutants are caught:
threshold, full-width field comparison, codec split, inner endian, missing
caller clamp, outer endian, success marker, and tag-one unwrap comparison.
Raw compiler output and all actual rows stay under ignored work; durable
qualification records bind source and output hashes. This proves the bounded
relation against a static mathematical oracle, not target runtime equivalence.

Reproduce from repository root after sourcing the pinned local toolchain:

```sh
python3 -B research/work-items/RE-012-tcp-compression-plan-115/verify_static.py --out work/fresh-plan-static.json
python3 -B research/work-items/RE-012-tcp-compression-plan-115/qualify.py --out work/fresh-plan-qualification
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-tcp-compression-plan/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-tcp-compression-plan/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --check --manifest-path src/node115-tcp-compression-plan/Cargo.toml
```

The Linux output is only an rlib; it is not linked into or run as a node.
The host probe executes only independently authored Rust. `validation.json`
records observed component checks; parent publication owns repository inventory
and catalogue checks. No hosted CI, container or byte equality is claimed.

## Open boundaries

The codec body, valid codec Result ABI, output bytes, context-field producer,
allocation/resize behavior, telemetry aliasing, unwinding, scheduling, socket
I/O and interoperability remain unresolved. Slot `0x64e7798` is telemetry,
not a compression oracle. Pure returned errors are explicit logical boundaries
and do not assert the target returns instead of panicking. All 92 acceptance
gates and registered byte-comparison totals remain unchanged. A complete sender
or compressor requires additional independently reconstructed, validated helpers.
