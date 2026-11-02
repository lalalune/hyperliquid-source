# RE-004: five-word masked-top coefficient combination

This contribution reconstructs the full node94 `[0x565e960,0x565ea92)` leaf in
independently authored Rust. It resolves the arbitrary fifth-word correction,
signed-coefficient boundary cases, exact output/register relation and overlapping
input/output behavior. The fifth word is ANDed with the unsigned coefficient
magnitude and subtracted at bit256; replacing this with ordinary full-width
multiplication changes admitted results.

- Target: node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Component/task: bounded foundation reconstruction under RE-004.
- Repository base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Implementation: [library](../../../src/node94-five-word-combine/lib.rs),
  [input-only client](../../../src/node94-five-word-combine/input_only_driver.rs),
  [universal relation and proof](PROOF.md).
- Original addresses are ELF virtual addresses, not host pointers or rebases.
  Imported pins, prior packets, catalogue and progress gates are unchanged.

The scope is one 306-byte, 93-instruction function. Its actual unique FDE and
complete CIE are bound along with 14 separate NOP alignment bytes. The full
2,155-byte caller `[0x565df20,0x565e78b)` supplies 20 instruction-boundary-qualified
direct E8 sites. E9/EB candidate scans find none. All 80,300 RELA records are
checked for naming addends and full-width writes overlapping the body, padding
and caller; no such reference/write exists. No callee, RIP-relative operand,
table or hidden loop lies inside this leaf. The caller remains context, and
indirect references are not a complete census.

The neighboring helpers at `0x565e7a0` and `0x565eaa0` are excluded. Their source
questions include different input widths, intermediate stores, shifts and
returns. This leaf reads all 80 input bytes before its five result stores; it
has arbitrary fifth-word masks and reports all 13 modified GP registers.
Fresh live PR/issue/recent-merge and local-source checks are recorded in
`overlap.json`. No existing source implementation or live claim covers this
entry. No unlicensed inferred implementation was read or copied.

## Independent pre-Rust freeze

`oracle.py` was frozen at `2026-11-01T22:37:15.966120+00:00`, before the Rust
source directory existed. Its SHA-256 is
`5db91b09186a1d887df3e9c58ecdf348c2dd5c944850479428b857675b2cfb9f`.
It treats each input as one whole 320-bit integer, applies whole-integer signed
negation, multiplies the low 256-bit integer, applies the masked-top correction,
and decomposes results by quotient/remainder. Memory output uses immutable
concatenation. Rust independently uses word complement/carry, four u128 products
and five word additions. The oracle imports no Rust and performs no instruction
emulation.

`frozen/ORACLE-FREEZE.json` binds the oracle, target/static closure and complete
raw input/expected hashes. The gzip fixtures are deterministic; their raw hashes
are inputs `b69e17b8139ed875f176e5cd9aff1215664d579ea02af1f627dcb0f5c380584a`
and expected `285b84d14c6e8c24869ad8d6eb481da420c59e39b3ad539607aa6ab5ee5bc3d7`.
There are 13,570 input descriptors: 13,505 admitted and 65 finite-image refusals.
The admitted cases include 589 data aliases and 6,270 arbitrary fifth-word values
outside zero/all-ones. Every operand/coefficient bit rank, adjacent boundaries,
zero/MIN coefficients, both coefficient signs, high carry chains, dense byte
aliases and exact image bounds are covered.

Each input is five little-endian u64 descriptor fields (coefficients A/B, source
offset, destination offset, active image length), followed by 128 synthetic
bytes: 168 bytes total. Each expected output is status plus 13 full registers
in `Registers` field order, followed by all 128 bytes: 240 bytes total. The
inactive suffix is also compared. Refusals encode zero status/registers only
in the new driver format; they are not original target returns.

## Native and structural qualification

Only newly authored Rust was built and run. The installed compiler is rustc
1.94.1, commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Runs used macOS arm64, Python3.14.3, Capstone5.0.7 and GNU binutils2.47.20260726.
The input-only client receives the input path, never expected outputs or the
oracle. Builds use `-Dwarnings`, overflow checks, panic abort, opt0/opt3, then
repeat each profile. All 54,280 observations matched without masks; repeated
library, executable and output hashes were identical within each profile.

All 19 compiled controls were detected. Eighteen alter admitted projections:
signed handling, MIN magnitude, whole-input negation, top mask/correction,
product/sum carries, raw final multiply registers, term selection, byte order,
and early stores that reread aliased second-input bytes. Selected counts include
5,997 mismatches for ordinary full-320-bit multiplication, 3,384 for reporting
the carry-adjusted word in RAX, and 408 for the early-store alias error.
The nineteenth control changes 41 new-API refusal images only; it does not
constitute evidence about original target fault handling.

The actual native comparator also detects exactly one corrupted expectation.
A malformed input record exits2 with no stdout. All 55 structural controls reject
full-body/caller/frame/padding/relocation corruption. Exact counts and native
counterexamples are retained in `observed/results.json`, and all binary streams
are audited by `verify_recorded.py`. There were no failed native qualification
runs or ineffective controls in this packet.

`observed/raw-streams.json.gz` is one lossless archive. The first native stdout
is base64; later fixed-width native streams use XOR-to-first plus base64. Each
stream's raw size/hash, command label and encoding are retained. The audit
reconstructs all 150 streams and checks output rows, command hashes and mutant
source changes. Raw GNU body/caller stdout is retained there; readable copies
remove trailing whitespace only and are verified byte-for-byte after that
documented transformation. The large GNU frame dump is explicitly retained
as selected complete CIE/FDE records, not falsely labelled full stdout.

## Reproduce and limits

From the repository root with the pinned target materialized:

```sh
python3 -O research/work-items/RE-004-node94-five-word-combine-rust/validate.py \
  --output work/node94-five-word-combine/recheck
python3 -O research/work-items/RE-004-node94-five-word-combine-rust/verify_recorded.py
python3 -m unittest tests.test_fde_extents tests.test_elf_index tests.test_readelf_crosscheck -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH \
  make doctor verify catalogue-check reproduce
```

All 24 focused tests passed. Repository gate outcomes and exact streams are
retained separately. The shared baseline sweep covered 971 files / 15,462
reported tests / 69 skips; original `make test` exited2 solely on three disk-full
errors, and isolated retry of their 20 affected tests passed. It was not rerun
as a full suite on this head. Linux-only skipped qualification and hosted CI
are not claimed.

The all-input proof depends on stable ordinary memory and successful original
accesses. `apply_image` adds explicit nonwrapping finite-image premises and
atomic refusal behavior; it does not model original faults, arbitrary pointer
provenance, MMIO, concurrent observations, flags, stack/CET or native ABI.
Input quantity meanings and upstream range invariants remain unknown. This
does not reproduce original compiled bytes, recover the caller, establish a
whole-family census or complete any component progress gate. Only target
static parsing/disassembly and newly authored Rust execution occurred.

Authorship assistance: OpenAI/Codex. The runtime's exact model ID was not
exposed; none is invented here.
