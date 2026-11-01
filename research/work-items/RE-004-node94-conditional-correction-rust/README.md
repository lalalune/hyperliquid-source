# RE-004: complete conditional-correction arithmetic family

This packet adds independently authored no_std Rust for four complete node #94
leaves totaling 512 bytes: Add `[0x565da40,0x565daba)`, Subtract
`[0x565dd00,0x565dd72)`, AddNonzero `[0x565dde0,0x565de6e)`, and
SubtractNonzero `[0x565de80,0x565df06)`. It resolves their arbitrary-input
256-bit correction decisions, ordered memory effects, and seven written
registers as one coherent family. No neighboring helper or progress gate is
included.

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base source: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Component: bounded foundation arithmetic under RE-004. Addresses are original
ELF VAs. Imports, pins, generated catalogues and gates remain unchanged. No
unlicensed inferred implementation was read or copied.

## What is established

`PROOF.md` derives the complete whole-integer relation without assuming a
modulus or reduced operands. Add makes its correction decision using the full
257-bit sum, while the stored result wraps to 256 bits. Its raw RDX preserves
both carry and subtraction borrow; it can be `0`, `2^64-1` or `2^64-2`.
Subtract conditionally adds the correction after its 256-bit subtraction and
discards the final carry. The plain variants' RAX and RSI are saved sum words
or selected correction words, not result pointers. The Nonzero variants change
RAX plus R8/R10 while leaving the four destination words unchanged.

All input loads, including all correction reads, precede all destination
stores. The safe byte-image API therefore handles partial/full input/output
aliases by snapshotting the initial image. The proof specifies the target
premise of stable ordinary memory and excludes overlap with original stack
scratch, saved registers and return-control storage. `None` is a new safe API
range refusal, not inferred original behavior.

`static-lock.json` binds each complete body and its actual FDE/CIE, plus
separate 6/14/18/26-byte alignment context. All four contain no branches or
calls and have no RIP-relative data/table dependencies. Full GNU disassembly
and selected original GNU frame records are retained alongside Capstone
instruction exports. An entire `.text` scan found zero E8/E9/EB candidates to
these entries; all 80,300 RELA records contain no naming addend or overlapping
writer to the bodies/padding. No caller or whole-program reachability/census
claim follows from that bounded absence. The prior `foundation-nonzero-below-94`
packet names `0x565dde0` only as the next excluded FDE; its analyzed body is
`[0x565dd80,0x565ddc5)`, outside this family.

## Independent expectations and observed results

The oracle was frozen before any new Rust source existed. Its SHA-256 is
`c94c439dedd99b8d67f74be02cb256d4ad222ed03d109880dfa895713b433539`.
`frozen/ORACLE-FREEZE.json` records the UTC freeze, full target admission,
static facts and raw fixture hashes. Python evaluates unrestricted whole
256-bit integers and creates one immutable-image overlay. Rust independently
uses u128 limb carry sums, paired overflowing subtractions, and output stores;
their equivalence and all arithmetic bounds are proved in `PROOF.md`.

There are 13,420 cases, 3,355 per family member: 13,372 admitted target
projections and 48 new API range refusals. Cases cover every one of 256 bit
positions and adjacent values, cross-limb carry/borrow, equal/zero/all-ones
operands, sum overflow, high correction words, zero results, 4,428 output/input
overlap cases and 948 input/input overlap cases, plus seeded arbitrary inputs.
Each entire output image and all seven observed registers are compared.

Pinned installed rustc 1.94.1 produced four actual native builds: opt0/opt3,
two builds each, with overflow checks, panic abort and warnings denied. All
13,420 cases matched in every build: 53,488 admitted projections and 192 API
refusal checks across the four builds. Same-option library, client and output
hashes repeated exactly. The host is macOS arm64; these are executions of
newly built Rust, not of the captured Linux node or an instruction emulator.

All 16 compiled wrong variants ran normally and produced actual admitted-case
mismatches. Examples include ignoring the 257th add bit, incorrect carry/borrow,
wrong raw return words, missing OR clobbers, reversed byte order, and a store
before input loads (3,732 alias-related mismatches). The selected counterexamples
and complete mismatch counts are in `observed/selected-controls.json` and
`results.json`. All 37 structural corruption controls were rejected. One
corrupted expected row caused exactly one comparator mismatch; malformed
client input exited 2 without stdout. No mutant result depends solely on
changing the safe API's refusal policy.

`observed/raw-streams.json.gz` retains 136 exact command-labelled stdout/stderr streams
with raw hashes, using base64 or lossless XOR against the first native stdout.
This is storage compression, not comparison normalization. The archive audit
restores all streams, verifies bytes/hashes/exits and independently recounts
mismatches and selected examples. The large GNU frame stdout is explicitly
retained as selected original CIE/FDE records only. Readable disassembly strips
only line-ending whitespace; exact GNU output remains in the archive.

## Reproduce and limits

From repository root, with installed Python 3.14.3, Capstone 5.0.7, GNU
binutils 2.47.20260726 and rustc 1.94.1:

```sh
python3 -O research/work-items/RE-004-node94-conditional-correction-rust/validate.py \
  --output work/node94-conditional-correction/recheck
python3 -O research/work-items/RE-004-node94-conditional-correction-rust/verify_recorded.py
shasum -a 256 -c research/work-items/RE-004-node94-conditional-correction-rust/MANIFEST.sha256
```

The validator authenticates the captured bytes statically, regenerates and
byte-compares the pre-Rust expectations, then builds/runs only new Rust.
Exact arguments, compiler executable hash, platform and outputs are recorded
in `observed/commands.json` and `results.json`. There are no dependencies or
invented Cargo workspace/lockfile. Captured code byte equivalence is unmeasured.

Local `make doctor verify catalogue-check reproduce`, 33 focused tests,
rustfmt and manifest/archive audit passed. Their results are retained in `observed/repository-checks.json.gz`. The shared
baseline attempted 971 files / 15,462 tests / 69 skips; its original make
exit2 was solely three disk-full errors, and all 20 affected tests passed
isolated retries. That is not a fresh full-suite result on this head or a
Linux-native qualification. No hosted CI success is asserted.

Original ABI/stack behavior, racing memory, pointer faults, flags, source
symbol identity, callers and mathematical operand meaning remain excluded.
A further bounded question is how runtime callers select these entries and
constrain the correction operands; this reconstruction does not assume an
answer. No component acceptance gate or whole-node completion claim is made.

Authorship: OpenAI / Codex client. The exact runtime model identifier is not
exposed to this session and is not invented.
