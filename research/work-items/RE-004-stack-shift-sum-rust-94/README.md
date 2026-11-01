# RE-004: node #94 stack shift-sum Rust value reconstruction

The earlier [foundation packet](../foundation-stack-shift-sum-94/README.md)
validated the static leaf but left Rust unimplemented. This contribution adds
an independently authored, safe `no_std` value component for its complete
55-byte FDE, including the full u32 input domain, unsigned ordering, masked
shift counts and wrapping sum. It also proves the exact active-zero condition:
`flag==1`, `first>second`, `first mod64==60`, `second mod64==61`. Consequently
zero is preserved as a raw result rather than assigned a sentinel meaning.

- Task/component: RE-004, bounded foundation arithmetic reconstruction.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, current origin/main
  when branch `research/node94-stack-shift-sum-rust` was created.
- Node #94 SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Addresses are ELF VAs without runtime rebasing.
- Selected function: `[0x55c6c40,0x55c6c77)`, file offset `0x55c5c40`,
  body SHA-256 `870d7451ce9ea720f99ed16dcdb9b410544afaf279db5803df18e0a14d683168`.
- Reference pin remains `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  node upstream pin remains `405cc08b17a727ee51b0f9128918955a84439915`.
  No inferred implementation was copied or used as an oracle.
- Scope: returned u64 value for every u32 triple. Excludes original ABI/faults,
  whole-caller semantics, original library/source identity and rebuilt target bytes.
  Source names are descriptive, not recovered symbols. Disassembler nearest-symbol
  labels are not evidence of ownership.

## Evidence and proof

[PROOF.md](PROOF.md) derives the full-domain rule from the retained instructions
and traces the real caller stack copy. [static.json](static.json) records the
full selected and caller bytes, PT_LOAD/section-backed offsets, complete FDE/CIE
records, boundaries, branch target, internal NOP and external padding. Fresh GNU
and Apple LLVM exports agree without normalization on all 19 leaf and 191 caller
instruction boundaries. Both decode the unique `.text` direct-E8 candidate at
`0x555ba70` inside the complete caller `[0x555b930,0x555bbf8)`.

The caller copies 24 bytes from its entry RSI pointer through R14 into its
pre-call stack. The leaf reads the first three u32 words at its own RSP+8/+12/+16.
No source struct identity is asserted. The leaf has no calls, memory writes,
external data, or LSDA; 80,300 ELF RELA records contain no addend naming the leaf
or conservatively eight-byte overlap with the protected leaf/padding or caller.
Indirect callers and whole-caller data closure remain unclaimed.

The static verifier checks the full digest first, then separately performs
structural checks so 14 in-memory corruption controls reach actual body,
padding, FDE and caller validation. No captured instructions are executed.

## Implementation and oracle independence

[`lib.rs`](../../../src/node94-stack-shift-sum/lib.rs) uses unsigned saturating
subtraction, u64 `wrapping_shl`, and `wrapping_add`. Its Rust by-value API is new;
there is no original stack ABI wrapper. [The source README](../../../src/node94-stack-shift-sum/README.md)
states the domain and conditional-memory-read limits.

The oracle was authored and frozen before the Rust source was created.
[oracle-freeze.json](oracle-freeze.json) binds the original static verifier,
raw disassembly, static record, coverage and compressed fixtures at that point;
this is local chronology, not an independent timestamp attestation. The oracle
uses Python unbounded powers and modulo, not Rust arithmetic, the legacy rule
function, an instruction evaluator or target output. Its expected formula is
proved from target instructions; native testing checks the independent Rust
implementation against those expectations.

The 29,871 triples include all 4,096 residue pairs for each strict unsigned-order
region, small and signed-boundary-crossing representatives, equality, powers of
two, u32 extrema, inactive flag variants and deterministic digest-derived cases.
There are 27,357 active cases, 2,514 inactive cases and two active-zero cases.
[coverage.json](coverage.json) binds 358,452 input bytes and 238,968 expected
bytes to their hashes. The input-only native client accepts only u32 triples on
stdin; it has no fixture paths or expected outputs. It emits u64 little-endian
results and rejects partial triples before emitting any output.

## Reproduce

Use materialized pinned artifacts/submodules and Python 3.14.3. Exact disassembly
and validation commands, versions, logs and exit codes are in
[checks.json](checks.json). GNU objdump 2.47.20260726 uses `--insn-width=16`;
Apple LLVM objdump is 17.0.0. No instruction bytes are normalized or masked.

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 research/work-items/RE-004-stack-shift-sum-rust-94/verify_static.py
python3 research/work-items/RE-004-stack-shift-sum-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/stack-shift-sum-review
shasum -a 256 -c research/work-items/RE-004-stack-shift-sum-rust-94/manifest.sha256
```

The verifier requires a new output directory and the actual rustc executable
SHA-256 `b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`,
release 1.94.1, commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, host
`aarch64-apple-darwin` (LLVM 21.1.8). It records the linker executable hash and
Apple clang version. This pins the observed research build, not the original
node compiler. There are no dependencies, Cargo workspace or fabricated lockfile.

The direct compiler recipe uses edition 2021, explicit aarch64 Darwin target,
`-Dwarnings -Ccodegen-units=1 -Coverflow-checks=on -Copt-level=0/3`, `/usr/bin/cc`,
fixed crate metadata and repository-path remapping. Full argument vectors and
stdin/stdout/stderr hashes are in [native/calls.json](native/calls.json).
[native/results.json](native/results.json) records the source/fixture/compiler
identities, observed environment, comparison counts, mutation witnesses and
four repeated-artifact hashes.

## Results and limits

Both optimization profiles produced all 29,871 expected outputs with zero
mismatches and passed three focused Rust unit tests each. Four repeated artifacts
(two rlibs and two clients) were raw-byte identical, with no normalization.
Eight actually compiled wrong implementations were rejected at each profile:
boolean gate, signed minimum, unclamped difference, either 5-bit count mask,
narrowed ordering, wrong base and saturating addition. The last has two normal
return mismatches, proving the active-zero cases exercise wrapping behavior.
Output corruption and truncation controls also reject; malformed client inputs
of one and thirteen bytes fail with no stdout.

`native/raw-streams.json.gz` is a deterministic lossless JSON archive. It maps
all 140 stream names to hashes and stores each unique raw payload once as base64,
including empty streams. Every decompressed payload was checked against its hash
and every call's recorded stream. Its bytes and the complete packet are covered
by `manifest.sha256`; regular commands/results stay readable outside the archive.

Completed local checks: `make doctor`, `make verify`, `make catalogue-check`,
`make reproduce`, all 10 existing stack-shift-sum tests and exact legacy evidence
reproduction. The first doctor invocation used the default PATH and failed
because Apple objdump was selected and readelf was absent; its log is retained. Doctor logs replace the literal home path with `<home>`;
original and retained hashes are recorded, and no comparison bytes are changed.
Putting the already installed GNU binutils first made the same check pass.
Static regeneration under two hash seeds/timezones, including Python `-O`, was
identical. No full suite or hosted CI success is claimed here.

All results are static proof plus native execution of new Rust. Original Linux
x86-64 compiled-byte/ABI identity is unmeasured. No captured code or emulator was
executed; there were no live-node actions or imported-code changes. No progress
gates or coverage registry entries change. The remaining integration question is
which original type and application invariant supply the observed 24-byte caller
copy; this value reconstruction does not answer it.
