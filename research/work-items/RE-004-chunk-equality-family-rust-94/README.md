# RE-004: complete twelve-member chunk-comparison family

Component: foundation. This adds independently authored safe Rust for twelve
complete functions at `0x14b52b0 + 0x30*i`, i=0..11. The predecessor
`foundation-chunk-equality-94` bound only the first member; its eleven
siblings had listed comparands but no complete reconstruction. One coherent
family contribution closes every body, constant and entry relocation.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF VAs. Baseline is
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The can1357 reference gitlink
remains `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred unlicensed
implementation was copied. New code/evidence are independently authored
with OpenAI/Codex; exact runtime model unavailable.

The API exposes all three written GP registers. RDX always contains the
wrapping object+56 value, RCX contains the exact sixteen byte-equality bits,
and RAX contains RDX only on a full match. A full match may return zero
when the address calculation wraps. No output-object memory is read or
written, and no source type or meaning is assigned to the opaque constants.
[PROOF.md](PROOF.md) states the full relation and ordinary-memory premises.

## Complete members

Each row is a complete 33-byte/eight-instruction FDE with fifteen separate
padding bytes. GNU/LLVM/Capstone agree on all 396 bytes/96 instructions.
The table's slot has one exact symbol-zero RELATIVE record naming its
member, with a zero pre-relocation qword in `.data.rel.ro`.

| Pattern | Entry | Comparand | Entry slot |
|---|---|---|---|
| P0 | `0x14b52b0` | `0x208300` | `0x566e618` |
| P1 | `0x14b52e0` | `0x2072e0` | `0x566e408` |
| P2 | `0x14b5310` | `0x205780` | `0x566e558` |
| P3 | `0x14b5340` | `0x205790` | `0x566e468` |
| P4 | `0x14b5370` | `0x2054b0` | `0x566e588` |
| P5 | `0x14b53a0` | `0x208650` | `0x566e4c8` |
| P6 | `0x14b53d0` | `0x203b20` | `0x566e4f8` |
| P7 | `0x14b5400` | `0x2072f0` | `0x566e5e8` |
| P8 | `0x14b5430` | `0x203110` | `0x566e438` |
| P9 | `0x14b5460` | `0x206820` | `0x566e498` |
| P10 | `0x14b5490` | `0x203810` | `0x566e5b8` |
| P11 | `0x14b54c0` | `0x203820` | `0x566e528` |

All comparands, FDE/CIE records, slots and raw RELA records are bound.
All 80,300 RELA entries are scanned. E8/E9 candidate scans find no direct
reference to these entries; short jumps and indirect references remain
outside that census. There are no outgoing calls or branches. Seventy-three
structural corruption controls pass separately from the whole-target digest.

## Qualification and reproduction

The independent pre-Rust oracle froze 121,792 input/expected records.
It uses a product of equality digits, a parsed binary string and unbounded
address arithmetic; Rust uses a u16 OR mask and wrapping addition. Member
zero exercises every 16-bit equality mask. Every member tests every byte
value in every position, all family constants, high address bits, exact
wrap boundaries and deterministic additional chunks. There are 2,641 full
matches, 12,672 wrapping destinations and 21 full matches with RAX zero.

All 487,168 observations match across opt0/opt3 and repeated builds. Library,
client and output hashes repeat exactly. Three units per profile, malformed
framing, invalid native selector input, two comparator controls and sixteen
effective compiled mutants pass their expected checks. All 142 raw command
streams, first counterexamples, source/compiler/linker hashes and commands
are retained losslessly. No captured code or instruction emulator runs.

Independent peer review rederived all 121,792 rows using 128-bit XOR,
positional quotient and mask complement, and manually parsed ELF headers
to bind every constant and exact instruction template. Its complete RELA
scan also proved each entry slot has exactly one overlapping writer, the
expected record, including checks for partial overlaps and other addends.
The post-source `verify_independent.py` retains that separate audit; the
pre-Rust oracle/static files remain unchanged. Peer static -O and full
proof/source review found no blocker.

Eight focused predecessor tests, rustfmt, doctor, verify, catalogue-check
and reproduce pass. Exact command streams and path-redaction hashes are
retained in `repository-checks.json.gz`. The shared baseline sweep finished
971 files/15,462 reported tests/69 skips. Its original exit 2 came solely
from three disk-full errors; all 20 affected tests passed an isolated retry.
This is not a successful repeat of the full sweep, a full-suite run on this
separate head or a skipped Linux-native qualification. Hosted checks are
tracked separately.

Use unchanged materialized pinned inputs. Python 3.14.3, Capstone 5.0.7,
GNU binutils 2.47.20260726 and Apple LLVM 17 provided static checks. Native
macOS aarch64 rustc1.94.1/LLVM21.1.8 is pinned to commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, compiler SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
From the repository root, using a fresh output directory:

```sh
make doctor
make verify
make catalogue-check
make reproduce
python3 -B -m unittest tests.test_foundation_chunk_equality -v
python3 -O -B research/work-items/RE-004-chunk-equality-family-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-chunk-equality-family-rust-94/verify_independent.py
python3 -O -B research/work-items/RE-004-chunk-equality-family-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-chunk-equality-family-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/chunk-equality-review
```

No root workspace or artificial lockfile is needed. This is a numeric
projection, excluding original ABI, SIMD results, flags, faults, MMIO,
concurrency and physical access traces. No original compiled-byte match,
whole-node equivalence, source identity or component gate is claimed.
Pins, progress and generated coverage remain unchanged.
