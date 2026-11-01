# RE-004: full-width mask sentinel, RCX and global store

Component: foundation; one complete arithmetic/store helper. This contribution
reconstructs node94 `[0x5521d10,0x5521d37)` in independently authored safe
`no_std` Rust. Prior `foundation-mask-builder-94` evidence established a mask
formula but had no Rust implementation, retained only part of the caller,
and did not qualify full RCX on each path or the load-biased store image.
The new question closes those values over every u64 input without assigning
a source name, quantity meaning or runtime role to the global.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF VAs. Base:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Reference gitlink remains
`999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed inferred
implementation was not read/copied. New code/evidence were authored with
OpenAI / Codex; the runtime model identifier is not exposed.

## Result and evidence

The full-u64 comparison with -1 selects the sentinel. That path stores and
returns all ones while preserving entry RCX. Every other input uses its low
six bits as a shift count, stores/returns `(1 << count)-1`, and zero-extends
its low32 into RCX. Thus 255 and `0x1ffffffff` differ from the full sentinel,
and input64 returns zero with RCX64. The store always replaces eight bytes
at load bias plus `0x5788110`, with wrapping address arithmetic.

[PROOF.md](PROOF.md) establishes all widths, safe shifts, the exact store,
register preservation and original-memory premises. The new API operates on
an eight-byte slot image and never dereferences its returned address bits.
The observed `.data` initializer is all ones; runtime initial contents are
not assumed or read by the original body.

The 39-byte/10-instruction body, nine padding bytes, actual FDE/CIE and the
full 957-byte caller are locked. The sole qualified direct call is
`0x54b9c3f`; the caller's broader behavior is excluded. All 80,300 RELA records
are checked for entry naming and any overlapping writer to body/padding or
global slot. There are none. E8/E9/EB candidate scans are retained, without
claiming a complete xref census or runtime reachability. Fresh GNU body/caller
listings and selected actual CIE/FDE output accompany Capstone decoding.

The arithmetic oracle was frozen before Rust on
`2026-11-01T21:36:48.728712+00:00`, source SHA-256
`8a2e20044c23d5428861469c0967d760e8976cc483eb465bbc6d30f15365bed9`.
It sums powers of two and uses integer remainders; Rust uses bounded shifts,
subtraction and a byte store. The 30,592 inputs span all 64 shift classes,
1,034 full sentinel cases, high-bit/low32 aliases, RCX preservation and
extension, changing/unchanged initial slots and 10,704 destination wraps.
Finite controls qualify the implementation; the proof supplies the universal
relation. Neither oracle nor validator executes or emulates captured code.

## Observed qualification

All 122,368 observations match across four native builds (30,592 each),
opt0/opt3 with repeats. Within each optimization level the library, client
and stdout hashes repeat exactly. All fifteen compiled wrong variants
produce real output differences; the counts and first counterexamples are
retained in `observed/selected-controls.json`. The smallest control changes
586 observations (low32 mistaken for the full sentinel), while a wrong
store address changes all 30,592. None of these is merely a new refusal
policy: every compared input belongs to the full safe value domain.

Twenty-one structural corruptions reject. The input-only client rejects
malformed framing with exit 2 and no stdout; replacing one expectation
produces exactly one mismatch. The optimized-Python archive audit rebuilds
all 126 exact stdout/stderr streams and rechecks every native mismatch
count. The compact lossless archive is 828,591 bytes. Parent read-only
source/proof review and fresh GNU disassembly review found no blocker.

Eight focused predecessor tests, rustfmt, `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` pass. Exact check output is
retained with path normalization and original/retained hashes in
`observed/repository-checks.json.gz`.

## Reproduction and limits

Use the unchanged materialized pinned artifact and submodules. From the root:

```sh
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
python3 -B -m unittest tests.test_foundation_mask_builder -v
python3 -O research/work-items/RE-004-node94-mask-builder-rust/verify_static.py
python3 -O research/work-items/RE-004-node94-mask-builder-rust/verify_recorded.py
python3 -O research/work-items/RE-004-node94-mask-builder-rust/validate.py \
  --output work/node94-mask-builder/review
```

The native pin is rustc1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM21.1.8, compiler SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The observed host is macOS arm64; Python3.14.3, Capstone5.0.7 and GNU binutils
2.47.20260726 supplied the independent static checks. Exact commands, tool
version output, compiler/library/client hashes and raw native output are
retained in `observed/`. The archive uses lossless base64/XOR-base64 encoding
and verifies every original stream length and SHA-256 on decoding. Readable
GNU listings strip trailing whitespace only; exact raw bytes remain archived.
Frame output is explicitly limited to the actual relevant CIE/FDE records.

This is a source-built numeric/store projection, not target-byte identity,
an original-ABI implementation, whole-caller closure or whole-node behavior.
No original flags, faults, MMIO, concurrency, CET behavior or physical access
trace is claimed. Synthetic biases do not imply all real process mappings
exist. No progress, catalogue, imported evidence or pin is changed.

The separate shared baseline sweep covered 971 files, reported 15,462 tests
and 69 skips, and exited 2 due solely to three disk-space errors. All 20 affected
tests passed isolated retries. That is not a clean original full sweep, a
full-suite run on this head or qualification of skipped Linux tests. Hosted
CI results are not claimed.
