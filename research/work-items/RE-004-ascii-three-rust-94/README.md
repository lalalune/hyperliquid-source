# RE-004: node94 ASCII three-byte equality in Rust

This reconstructs the complete `[0x151a4a0,0x151a52f)` leaf as safe,
dependency-free `no_std` Rust. The preceding
`foundation-case-insensitive-3byte-equality-94` packet established static
behavior but left the Rust implementation open. Its evidence remains intact.
Target node94 is 91,774,280 bytes with SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, reference gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23`.

## Returned value and domain

`equal(length, left, right)` accepts a u64 length and two three-byte
snapshots. It returns true exactly when length is three and each corresponding
byte agrees after folding ASCII uppercase letters to lowercase. Every other
byte, including punctuation and high bytes, is unchanged. The implementation
exits on the first unequal pair and needs no dependencies or unsafe code.

The [proof](PROOF.md) derives the modular byte predicate, every branch and
the complete RAX result. The final SETE only writes AL, but the preceding
MOVZX EAX establishes all higher bits as zero; thus the returned numeric
value really is 0 or 1. Length comparison uses all 64 bits. Snapshot validity
and stable ordinary memory are explicit premises; pointer faults, concurrent
changes, MMIO, timing and original ABI are outside the projection.

## Static evidence

The leaf has 143 bytes and 47 instructions. Its body SHA-256 is
`4076d343e48641e98282e8477e0ecdf12f6d5e17ace7e09fe934a7b6230146ad`.
All 1,443 bytes/408 instructions of caller `[0x151b100,0x151b6a3)` are
retained, SHA-256
`a251bf0ce66f9c6945fc2c68617ab9381408110c9bc0d5fc73e12f980087c2fc`.
GNU objdump, Apple LLVM objdump and Capstone agree on every instruction
boundary and byte; no instruction-prefix or operand normalization is needed.

The complete FDE parse checks unique exact extents and retains raw FDE/CIE
records. Fourteen preceding INT3 bytes and one following INT3 byte are
separate from the function. Whole-text E8 scanning finds exactly two candidates,
`0x151b4f9` and `0x151b527`; complete caller decoding confirms both targets
and boundaries. All 80,300 RELA records are checked for naming/overlap with
protected code. This is not an indirect-reference census or a reconstruction
of caller purpose, referenced literals or string identity.

Ten structural corruptions exercise the length/fold/read/return bytes,
both padding regions, FDE/CIE and both caller edges. They bypass only whole-file
authentication so the downstream guards actually reject them. Raw exports
and the digest-bound `static.json` are retained. No captured instruction
executes, no emulator is used, and no inferred reference implementation was
read or copied. New code/prose use the root MIT license; captured bytes and
disassembly retain the original artifact's rights.

## Frozen oracle and actual native results

Before Rust existed, `oracle.py` froze 26 literal ASCII letter-pair classes
and 204 singleton nonletter classes. Class membership is independent of the
decoded subtract/compare and Rust range/add operations. Its source hash and
exact compressed input/expected streams are bound by `frozen.json`.

The 204,864 distinct cases include every one of 65,536 ordered byte pairs
at each of three positions, full-width length boundaries, mixed byte arrays
and 4,096 deterministic arrays with self-equality counterparts. There are
5,022 true outcomes. This is exhaustive pair coverage per position, not
enumeration of every six-byte combination or every length. The proof covers
that generalization through the separable equality relation.

The input-only client receives 14-byte records and emits a single 0/1 byte.
It never sees expected values. Four actual host builds/runs (opt0 and opt3,
each repeated) match all 819,456 rows. Repeated rlib, client and stdout hashes
agree within each optimization level. Two unit tests run per level, and a
partial input is refused before output.

All ten compiled wrong variants exit normally and yield mismatches:

| Variant | Mismatched rows |
|---|---:|
| Unconditional OR32 | 613 |
| Exclude uppercase A | 617 |
| Exclude uppercase Z | 617 |
| Include @ in folding | 7 |
| Do not fold left | 1,825 |
| Do not fold right | 1,823 |
| Ignore first position | 65,229 |
| Ignore second position | 65,228 |
| Ignore third position | 65,229 |
| Compare only length's low byte | 8 |

Two comparator controls detect an altered expected row and a missing byte.
`native/result.json` contains concrete first witnesses, source/compiler/linker
hashes and artifact/output hashes. `native/commands.json` retains all arguments,
statuses and stream hashes. The deterministic `native/streams.json.gz`
losslessly preserves all 102 stdout/stderr streams; each payload is hash-checked
and compared with its original raw stream before archival acceptance.

## Reproduce and limits

From the repository root after materializing pinned artifacts:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -O -B research/work-items/RE-004-ascii-three-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-ascii-three-rust-94/verify_rust.py \
  --out work/ascii-three-review \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc
python3 -B -m unittest tests.test_foundation_case_insensitive_3byte_equality -v
rustfmt +1.94.1 --check --edition 2024 src/node94-ascii-three/*.rs
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-004-ascii-three-rust-94 && shasum -a 256 -c MANIFEST.sha256)
```

`--out` must be fresh. The qualified native host is macOS ARM64; rustc is
1.94.1 commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8,
with actual binary SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Static decoding used GNU binutils 2.47.20260726, Apple LLVM 17 and Capstone
5.0.7; Python 3.14.3 ran validation under `-O`. Exact recorded compiler/export
pins deliberately require those tools; other-host validation must be separately
labeled. Original x86 ABI and target compiled-byte equivalence are unmeasured.

Seven focused predecessor tests, rustfmt, repository checks and the manifest
pass. `repository-checks.json.gz` retains their raw logs with hashes. The shared
legacy sweep remains pending; no full-suite or hosted CI pass is claimed here.
No imported evidence, pin, catalogue, progress gate or other source directory
changes. This closes one bounded Rust gap without claiming a completed node.
