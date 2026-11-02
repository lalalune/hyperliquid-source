# RE-001: reconstruct the node94 tag-selected address pair

This contribution closes the missing independent Rust implementation for the
complete `[0x15d65b0,0x15d65f3)` leaf from
[foundation-tagged-pointer-94](../foundation-tagged-pointer-94/README.md).
It preserves all 64 bits of RAX and RDX for every supplied object/tag/load-bias
triple. The high-tag paths retain distinct literal RDX values. The other paths
return biased slot addresses, never their relocated contents.

Task RE-001, foundation; author 신준. Baseline
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23`, unchanged. Target is Linux x86-64
node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
New source and packet code are independently authored MIT work. The unlicensed
inferred implementation was not read or copied. Imported artifacts retain
their existing rights. Existing evidence, progress gates and pins are unchanged.

## Established behavior and domain

The 67-byte body has 18 instructions, one qword input load and no data stores.
For `H=2^63`, input object `O`, tag snapshot `T` and image bias `B`:

| Input tag | Full RAX | Full RDX |
| --- | --- | --- |
| `T < H` | `O` | `B+0x5676c20` |
| `T = H` | `O+8` | `B+0x5676ba8` |
| `T = H+1` | `0` | `H+1` |
| `T >= H+2` | `0` | `H+2` |

Address additions are modulo `2^64`. The [proof](PROOF.md) derives the complete
unsigned interval partition, NEG's single overflowing input, every return path,
zero-extension from EAX, and relocation/address distinction. It does not infer
an original option, tagged pointer type, library identity or source signature.

[The safe `no_std` component](../../../src/node94-tag-address-pair/README.md)
accepts numeric values and returns a numeric pair. It does not validate or read
memory. Native correspondence additionally requires an ordinary valid qword at
`O` matching `T`, mapped code/control under the common bias, and the stated
normal execution premises. Faults, MMIO, concurrent changes, register/stack ABI,
flags and other registers are not reconstructed. All numeric inputs remain
accepted; their existence as mapped process states is not asserted. Returned
addresses need not be mapped because the target does not dereference them.

## Static evidence and boundary closure

`static_evidence.py` authenticates the complete target and decodes all
121,299 FDEs and three CIEs. The only overlap is the exact 67-byte FDE at
`.eh_frame+0x1d860`; its bytes and shared CIE are locked. GNU and LLVM decode
identical complete partitions. The 13 following `CC` bytes are padding; the
next FDE begins at `0x15d6600` and is bound only as a boundary, not reconstructed.

The body has no calls or branches outside the leaf. The complete 70,370,352-byte
`.text` E8/E9 candidate scan has zero incoming candidates. This is not a census
of indirect callers. One symbol-zero RELATIVE slot, `0x5678ee8`, names the
entry. The actual consumer of that slot remains unknown.

All 80,300 RELA entries are checked for body writers, naming addends and partial
writes into the three relevant qwords. The two LEA targets are `0x5676ba8` and
`0x5676c20`, with unique symbol-zero RELATIVE addends `0x15d3e70` and
`0x15d44e0`. Exact records, raw zero qwords, section mappings and PT_LOAD file
mappings are retained in `static/records.json`. Those slots would hold biased
pointee values after relocation; the LEAs return the biased addresses of the
slots themselves. Neither pointee is read or called by this leaf. Their source
types and the surrounding data-object extent remain unknown.

## Frozen oracle and actual native qualification

The interval-rank oracle uses `bisect_right` and a table of mathematical pairs,
with unbounded integer sums reduced modulo `2^64`. It does not simulate native
instructions or import the Rust code. The 10,680-case corpus, expectations and
oracle hash were frozen at `2026-11-01T22:15:14.090894+00:00`, while the new Rust
directory was absent. No post-Rust supplement was needed.

The corpus contains 3,837 below-half cases, 1,603 equal-half cases, 1,571
half-plus-one cases and 3,669 upper-tail cases. Among those cases, 50 exercise
object-plus-eight wrapping and 1,813 exercise biased slot-address wrapping.
It includes every tag bit and neighbors, dense boundary bands, each object/bias
bit, literal-versus-biased values and deterministic synthetic random inputs.

`native/result.json` and the exact commands retain these observed results:

- All 10,680 cases match at opt0 and opt3, each independently built twice:
  42,720 native comparisons. Rlib and client artifact hashes reproduce within
  each optimization level. The Rust client receives only input triples; the
  Python comparator retains expected values. No output bits are masked.
- All 28 compiled mutants return normally and differ on observable output.
  Controls include signed/truncated gates, overflow misclassification, off-by-one
  classes, saturating address arithmetic, missing/wrong bias, pointee value
  substitution, output truncation and collapsed literal returns. Witnesses and
  mismatch counts are retained. No compiler failure is counted as a kill.
- 38 static corruptions are rejected: full digest, every instruction boundary,
  FDE/CIE/padding/next boundary, extra overlapping FDE, incoming call/jump,
  code relocation, naming relocation, all three raw slots and their relocation
  type/addend, and an extra partial slot writer. Structural controls bypass only
  the full digest so the relevant lower-level rejection is exercised.
- Four comparator corruptions and two lossless-archive corruptions are rejected.
  `native/raw-streams.json.gz` retains all 32 exact stdout streams using a shared
  line dictionary; every reconstructed stream's byte count and SHA-256 is
  checked. It is not a digest-only replacement for raw output.

Only newly authored Rust ran, on macOS arm64 with Rust 1.94.1. This is
qualification against a proven static relation, not a captured-target
execution differential, target instruction emulation, Linux ABI reproduction
or rebuilt-byte identity. `checks/versions.json` preserves native tool versions.

## Reproduce and retained checks

From repository root after materializing the pinned artifacts:

```sh
python3 research/work-items/RE-001-tag-address-pair-rust-94/oracle.py
python3 -O research/work-items/RE-001-tag-address-pair-rust-94/verify.py --out work/tag-address-pair-replay
python3 -O research/work-items/RE-001-tag-address-pair-rust-94/verify.py --check-archive
python3 tools/foundation_tagged_pointer.py --check research/work-items/foundation-tagged-pointer-94/evidence.json
python3 -m unittest tests.test_foundation_tagged_pointer -v
cargo +1.94.1 check --manifest-path src/node94-tag-address-pair/Cargo.toml --locked --offline
```

The validator requires Python's standard library, the repository's existing
static ELF/FDE parsers, GNU and LLVM objdump, and Rust 1.94.1. Override objdump
paths with `GNU_OBJDUMP`/`LLVM_OBJDUMP` or rustc with `--rustc` when needed.
Output directories must be fresh. Rust has no third-party dependency. Builds
remap temporary paths and enable overflow checks, warnings as errors and abort
panics. `native/commands.json` contains every actual compiler argument.

The retained focused checker and all 15 legacy tests passed, as did locked
offline Cargo check and rustfmt. `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` passed; exact command exits and logs
are under `checks/`. The check environment prepended the installed GNU binutils
and rustup directories to PATH and kept Cargo output under ignored
`work/tag-address-pair/cargo-target`.

No new full-suite sweep was run. The shared baseline sweep reported 971 files,
15,462 tests and 69 skips; its original aggregate exit was 2 solely from three
Errno28 disk failures, with all 20 affected tests subsequently passing isolated
retry. That is not an aggregate clean rerun on this head. Hosted CI, skipped
Linux qualifications and whole-node behavior are not claimed.

Initial overlap inspection covered 161 open PRs, zero issues and 50 recent
merges; final inspection covered 165 open PRs, zero issues and 50 recent merges.
The retained inventories and source search found no overlapping range, slot or
semantic-name work. The existing static predecessor is intentionally extended
by this implementation. Parent reservation was confirmed before substantial
edits. Only the new source and packet directories change.

Verify `MANIFEST.sha256` from this packet directory with
`shasum -a 256 -c MANIFEST.sha256`. It includes the source, frozen oracle,
fixtures, raw evidence, validators, logs and reused static parsers. Completion
of foundation or the entire node remains unclaimed; no gate or coverage
registration is advanced. The remaining call-path question is the consumer of
slot `0x5678ee8`, outside this leaf's numeric contract.
