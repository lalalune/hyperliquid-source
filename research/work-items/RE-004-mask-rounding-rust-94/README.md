# RE-004: reconstruct the node94 mask-rounding leaf's complete u64 value rule

- Component: foundation; one bounded arithmetic reconstruction.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: current `origin/main` at
  `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` after a fresh fetch.
- Included: complete 75-byte leaf `[0x555e610, 0x555e65b)`, its FDE/CIE,
  five padding bytes and successor FDE, immediate constants, internal control
  flow, full-u64 value proof and independently authored safe Rust.
- Reference: the project-authored
  [foundation-mask-rounding-94](../foundation-mask-rounding-94/README.md)
  packet. No unlicensed can1357 implementation was read or copied.
- Excluded: original function/library/version identity, caller semantics,
  original ABI/compiler, target execution, compiled-byte equality and any
  full-component gate.

The previous packet explicitly left Rust unimplemented. This contribution
provides a real dependency-free value component and closes the modular upper
bound needed for its zero-branch proof. It also identifies an admitted input
whose result equals the apparent sentinel: `0xff00ff00ff00feba` returns
`0xffffffffffffffb8`. The new API therefore returns raw bits and does not infer
an error type from that word. This is a separate captured body from the
Snappy/LZ4 arithmetic leaves; no common library identity is asserted.

Before work on 2026-11-02 KST, live GitHub inspection found 36 open PRs and zero
open issues. No open PR title/body matched the selected addresses, cutoff or
mask-rounding topic. Current `src/` contained no implementation. The
coordinating agent reserved the scope. No issue/claim was created by this worker.

## Actual target binding

All addresses are linked ELF virtual addresses. The body file offset is
`0x555d610`, with SHA-256
`30eff3374e960cd9973a58b50251b45a09b8e4c9b4976817a932f71e34f7ca53`.
`verify_static.py` requires the complete ELF digest before normal analysis,
then independently resolves file-backed executable bytes, decodes the full
FDE table, checks a unique overlapping extent and retains the complete FDE/CIE
records. Its selected FDE is `.eh_frame+0x2cfd9c`; the successor begins at
`0x555e660` and ends at `0x555e66c`. The leaf has no LSDA.

Fresh GNU and LLVM exports agree on all 18 instruction boundaries and all 75
bytes. The verifier checks complete body identity, both forward branch targets,
the cutoff and both signed -72 immediates, as well as padding and relocation
closure. The two branches stay inside the body; the zero test selects a
conditional move, not an external edge. No calls, external jumps, data loads,
tables or vtables occur. Every arithmetic constant is an immediate operand.
Only `ret` requires a valid return stack. Every ELF RELA record is checked for
an eight-byte write overlapping the body/padding or an addend naming the entry;
none do. This conservative overlap check does not infer relocation widths or
claim an indirect-caller census.

The prior checker's three incoming `e8` candidates and caller FDEs still
reproduce. Their higher-level behavior remains outside this implementation.
Nearest-symbol labels in the disassembly are printer labels, not original
function names.

Exact raw export commands:

```sh
/opt/homebrew/opt/binutils/bin/objdump -d --insn-width=16 --start-address=0x555e610 --stop-address=0x555e65b artifacts/node/94/hl-node
/usr/bin/objdump -d --start-address=0x555e610 --stop-address=0x555e65b artifacts/node/94/hl-node
```

## Value proof and implementation

[`PROOF.md`](PROOF.md) partitions all `2^64` inputs:

| Input | Raw return value |
| --- | --- |
| `n > 0xff00ff00ff00feff` | `0xffffffffffffffb8` |
| `0 <= n < 131072` | `n + floor(n/256) + floor((131072-n)/2048)` |
| `131072 <= n <= 0xff00ff00ff00feff` | `floor(257*n/256)` |

The small path is bounded by `[64, 131582]`. The large admitted path is bounded
by `[131584, 2^64-3]`. These upper bounds exclude modular wrap as well as zero,
so the target's zero-to-sentinel conditional is unreachable for every admitted
input. If the cutoff were absent, the first arithmetic wrap would be at
`0xff00ff00ff00ff01`; that input is actually rejected before arithmetic.

`src/node94-mask-rounding/lib.rs` uses a safe `const fn`, no dependencies,
`no_std` and `forbid(unsafe_code)`. It preserves the unsigned inclusive cutoff
and explicit wrapping additions, while omitting the proven dead conditional.
The raw-u64 API distinguishes no invented source-level error type. The exact
admitted sentinel collision is frozen and tested. This is a value projection
of RDI to RAX under normal return; original register clobbers, flags, CET,
unwind/fault behavior and the complete caller contract are not implemented.

## Independent oracle and finite corpus

Before writing Rust, `verify_static.py --freeze` created immutable-by-default
expectations, input bytes and their hashes. The producer refuses to overwrite
those files. Ordinary checks regenerate them and compare every byte/hash.
The small oracle groups `n = 2048*q + r` and computes
`2055*q + 64 + r + floor(r/256) - [r != 0]`; the large oracle uses the single
unbounded numerator `floor(257*n/256)`. These are mathematical derivations from
the byte-bound proof, not copied Rust code, captured observations or an
instruction evaluator.

There are 134,483 frozen input-only cases:

- Every one of the 131,072 small-path inputs, covering all 2,048 residues and
  every correction boundary.
- 2,633 large admitted inputs, including 32/64-bit boundaries, all local
  256-residue classes around selected anchors, the cutoff and sentinel collision.
- 778 rejected inputs, including the first excluded arithmetic wrap, maximum
  u64 and values spread across the complete rejected interval.

The corpus also incorporates 1,024 deterministic SHA-256-derived input words.
The full-domain claim comes from the proof; only the small subdomain is
exhaustively executed natively. `coverage.json` supplies exact counts and hashes.

The independent Rust client reads only raw 8-byte input records from stdin,
calls the compiled library and writes one raw 8-byte result per input. It does
not embed or open expected answers. The parent comparator receives every output
word in order; changed and missing output controls test that comparison. This
is data-flow separation, not an operating-system sandbox.

## Reproduce and observed checks

From repository root with pinned captures/submodules materialized:

```sh
PATH="/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH" make doctor
make verify catalogue-check reproduce
python3 tools/foundation_mask_rounding.py --check research/work-items/foundation-mask-rounding-94/evidence.json
python3 -m unittest tests.test_foundation_mask_rounding -v
python3 -B research/work-items/RE-004-mask-rounding-rust-94/verify_static.py
RUSTC_BIN=$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)
python3 -B research/work-items/RE-004-mask-rounding-rust-94/verify_rust.py \
  --out work/mask-rounding-review --rustc "$RUSTC_BIN"
shasum -a 256 -c research/work-items/RE-004-mask-rounding-rust-94/MANIFEST.sha256
```

Use a fresh output directory. The recorded research compiler is rustc 1.94.1,
commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8, host and explicit
target `aarch64-apple-darwin`. Its actual executable SHA-256 is
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6` and is enforced.
Other recorded tools: Python 3.14.3, GNU objdump 2.47.20260726, Apple LLVM/clang
17.0.0 (`clang-1700.0.13.5`), macOS 27.0.1. These are research build tools;
the original Linux target compiler is not recovered.

The compiler recipe uses edition 2021, codegen-units=1, optimization levels 0
and 3, overflow checks enabled, warnings denied, explicit `/usr/bin/cc` linker
and path remapping to `/reconstruction`. No Cargo manifest or lockfile is
needed for this direct, dependency-free build. The record includes the linker
executable hash/version but does not pin every shared library or OS SDK.

At each optimization level, all 134,483 native comparisons matched and all
three Rust unit tests passed. Repeated rlibs and linked clients were identical:
four raw-equal own-artifact comparisons, no normalization. The common output
SHA-256 is `3adaf6ffed089055fa300616585a3afdbd393d7b7aabaa3d3a45b6bbe2a1f893`.

Eight wrong implementations were compiled and executed at both optimization
levels. Every run completed normally and was rejected by output differences:

| Mutation | Mismatches per level |
| --- | ---: |
| Reject the inclusive cutoff | 1 |
| Signed cutoff comparison | 132,617 |
| Omit the cutoff | 778 |
| Main shift 9 instead of 8 | 133,449 |
| Correction shift 10 instead of 11 | 130,049 |
| Correction base one too small | 64 |
| Narrow the input addend to 32 bits | 2,118 |
| Return -73 instead of -72 on rejection | 778 |

Eight independent structural corruption controls reject changed body/cutoff/
sentinel/threshold/conditional-move/padding/FDE/CIE bytes below the full-file
digest gate. The legacy checker and 11 focused tests also passed. Hash-seed
7/119 and UTC/Pacific-Kiritimati static regenerations match the frozen evidence.
Completed repository checks are in `checks.txt`; no full repository test-suite
or hosted CI result is inferred from these focused/native checks.

`native/calls.json` records all commands, exit codes, stdin hashes and raw
stream identities, replacing only repository/compiler paths with `<repo>` and
`<rustc>`. `native/results.json` binds sources, fixtures, tools and each mutation
witness. `native/raw-streams.json.gz` is one deterministic, lossless archive:
`streams` maps log names to hashes; `payloads` stores base64 data once per hash.
All archived streams were decoded and compared byte-for-byte to their raw
outputs. Input and expectation archives are separate and hash-bound as well.

## Limits and remaining question

No captured node, instruction emulator, networked node, keys, chain actions,
transplanted instruction bytes or inferred unlicensed implementation were used.
The library is a new Rust value API, not original source/ABI/build provenance or
compiled target-byte equality. Existing packets, pins, byte-window registries
and progress gates are unchanged. The meaning of -72, the source library and
callers' interpretation remain unknown. Which callers distinguish an admitted
result equal to -72 from rejection cannot be answered from this leaf alone.

Execution provenance: OpenAI via Codex; the exact model identifier was unavailable
to this worker and is not guessed.
