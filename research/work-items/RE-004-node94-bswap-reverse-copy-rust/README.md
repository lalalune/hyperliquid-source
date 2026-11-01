# RE-004 — node94 ordered byte-swap/reverse copy

This packet adds an independently authored, dependency-free `no_std` Rust
implementation of the complete leaf `[0x5632d90,0x5632dbb)`. It closes the
[prior foundation packet](../foundation-bswap-reverse-copy-94/README.md)'s
explicit restriction to a disjoint source snapshot: the new single-buffer API
preserves all valid byte-offset overlaps, each qword's read-before-write
ordering, the final buffer and the final raw RAX bits.

## Identity and boundary

Target node #94 is the 91,774,280-byte Linux x86-64 ELF with SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. All addresses are ELF
virtual addresses. The complete 43-byte body has 13 instructions and SHA-256
`d09c0b3ec0e07d25fd136956eaaf02a0512471313bd032d93bd4a18db0ff0f02`.

The leaf FDE is `.eh_frame+0x2d81c8`, using CIE offset zero. The next FDE begins
at `0x5632dc0`; five `int3` bytes follow the leaf. That neighbor is not
reconstructed. Complete caller bodies and their FDEs are also hash-bound:

| Caller range | Direct call | FDE offset | Instructions |
| --- | --- | --- | ---: |
| `[0x563ecc0,0x563ef9f)` | `0x563ed52` | `0x2d88b4` | 148 |
| `[0x563ff20,0x5640295)` | `0x563ff6f` | `0x2d89e8` | 187 |

Both caller FDEs use CIE offset zero. A 70,370,352-byte `.text` E8 scan finds
exactly these two call sites, qualified against complete caller decodes.
80,300 RELA records contain no addend naming this leaf. No callee, branch,
RIP-relative constant, table or external dependency exists in the leaf.
Incoming indirect references, caller meaning and complete caller behavior are
not claimed. Full instruction, FDE/CIE and caller facts are retained in
`frozen/ORACLE-FREEZE.json` and readable GNU exports.

## Recovered behavior and domain

The function reads source qwords at offsets 24, 16, 8 and 0, BSWAPs each, and
stores them at destination offsets 0, 8, 16 and 24 respectively. Every load
precedes its corresponding store, and every store precedes the next load.
RAX at return is the fourth swapped qword. The new API returns those raw bits,
without inferring an original source-language return type.

For disjoint regions, this reverses the whole 32-byte sequence. A snapshot of
all source bytes is wrong for some overlaps: self-copy of bytes 0..31 yields
31..16 followed by 16..31, with RAX `0x1f1e1d1c1b1a1918`. The Rust library
captures only the current qword and lets subsequent reads observe previous
writes. Source and destination may coincide or overlap at any byte offset.

The [proof](../../../src/node94-bswap-reverse-copy/PROOF.md) covers all byte
values and valid relative offsets. Both logical u64 offsets must name complete
32-byte regions in one mutable slice. A new `Bounds` refusal occurs before any
write and preserves the buffer; it does not model original faults or partial
fault effects. The target projection assumes valid nonwrapping regions and
ordinary memory permitting unaligned qword access. Native pointers, address
wrap, concurrent mutation, MMIO and faults remain outside scope.

## Independent freeze and actual native results

The backward byte-provenance oracle was frozen before Rust source existed at
`2026-11-01T20:43:52.491687+00:00`. Its unchanged SHA-256 is
`23706510b821159f2667df2af6c3e634f15b81eb30ef88c5b88de414c9dcf9a7`.
For each final output byte it recursively resolves which earlier destination
write could have supplied it, decreasing the write stage until reaching an
original input byte. It performs no forward mutation of a memory image. Final
RAX resolves source bytes immediately before the fourth write. The oracle
imports prior byte/FDE constants and ELF parsing, but never calls the prior
Python decoded-copy model or executes captured instructions.

There are 22,680 frozen cases: 21,457 valid, including 20,086 overlapping,
402 same-offset and 1,371 disjoint; 1,223 cases test the new bounds refusal.
Fixtures cover relative offsets -40..40 and every byte alignment modulo eight,
16,128 source bit-basis cases across every overlapping displacement -31..31,
exact bounds, short/empty buffers, u64 offset overflow edges, unchanged guard
bytes and 2,048 seeded additional valid layouts. The same-offset category is
a subset of the overlapping category.

The native client receives only synthetic inputs. Expected results remain in
the external comparator. Installed rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8, compiles the new library
and client at opt0 and opt3 twice each. Edition 2021, warnings denied,
overflow checks, `panic=abort`, one codegen unit and zero debug info are explicit.
All four independent runs match **all 22,680 cases**. Library, executable and
stdout hashes repeat exactly at each optimization level.

Ten wrong sources are actually compiled and run. Every mismatch below occurs
on a successful-original input, not merely a new refusal class:

| Native wrong behavior | Mismatching cases |
| --- | ---: |
| Snapshot all 32 source bytes | 8,498 |
| Read source qwords forward | 19,137 |
| Omit byte swap | 17,089 |
| Swap only low u32 | 17,737 |
| Execute qword groups backward | 15,169 |
| Reverse destination qword order | 19,137 |
| Omit fourth group | 11,521 |
| Return zero | 8,713 |
| Return first destination qword | 11,521 |
| Interleave individual byte reads and writes | 4,106 |

Actual mutation texts, source/binary/output hashes and first mismatches are in
`observed/results.json`. `selected-success-controls.json` retains concrete
successful-original witnesses. Eighteen static corruption controls reject
body, load/store offsets, swap, return, padding, FDE/CIE, both caller edges and
relocation changes while deliberately bypassing only the full-file SHA gate.
An independently corrupted expected row produces exactly one mismatch.

The first native validation attempt stopped when the wrong-return mutant
triggered `-Dwarnings` for an unused initial assignment. The mutant expression
was corrected without changing product Rust or the frozen oracle, and the
entire native validator was rerun successfully. A reproduced compiler-failure
record is retained in `observed/initial-mutant-failure.json`; final-run streams
are the successful complete run. This failed compile is not counted as an
effective semantic control.

## Commands, records and limits

```sh
python3 -B -O research/work-items/RE-004-node94-bswap-reverse-copy-rust/validate.py \
  --output work/node94-bswap-reverse-copy/recheck
python3 -B -O research/work-items/RE-004-node94-bswap-reverse-copy-rust/verify_recorded.py
python3 -m unittest discover -s tests -p test_foundation_bswap_reverse_copy.py -v
/opt/homebrew/opt/rustup/bin/rustfmt +1.94.1 --edition 2021 --check \
  src/node94-bswap-reverse-copy/lib.rs src/node94-bswap-reverse-copy/input_only_driver.rs
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH \
  make doctor verify catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-004-node94-bswap-reverse-copy-rust/MANIFEST.sha256
```

Observed host: macOS 27.0.1 arm64, Python 3.14.3, Capstone 5.0.7, GNU objdump
2.47.20260726. Native and stored-evidence validators run under Python `-O`;
evidence gates use explicit exceptions. Focused legacy tests passed **8/8**
(including their prior Python decoded-rule checks). Rustfmt, doctor, verify,
catalogue-check and reproduce passed. No duplicate full repository sweep,
hosted CI, Docker success, target execution/emulation or compiled target-byte
match is claimed.

`observed/raw-streams.json.gz` losslessly retains 94 stdout/stderr streams from
14 native runs and compilation/disassembly commands, with base64 bytes, labels
and hashes. `commands.json` and `results.json` remain readable. The readable
GNU disassembly views trim trailing whitespace; exact bytes remain archived.
This is presentation cleanup, not target-byte normalization. GNU's whole-ELF
frame output is explicitly excerpted to CIE zero and four FDEs in
`target.frames.txt`; it is not claimed fully retained. `verify_recorded.py`
audits the raw streams, all comparisons, source bindings, readable exports and
selected witnesses. Repository logs retain original and retained hashes with
only repository-root/home-path redactions. `MANIFEST.sha256` binds all new
source and packet files except itself.

Live open PRs/issues/recent merges and base `src/`/RE-004 evidence were checked
before selection and again before commit. `overlap-inventory.json.gz` retains
the public read-only records and hashes. The separately reserved modulo-index,
indexed-accumulator, record-cursor and wide-subtract work is excluded. Existing
foundation packets, pins, generated catalogues, byte windows and progress
gates remain unchanged.

New code/docs are independently authored under repository MIT. No unlicensed
inferred implementation was read or copied. Provider/client: OpenAI / Codex;
exact model identifier is not exposed in this session. This is a bounded
state/register reconstruction, not a node build or completed component gate.
Parent owns review and publication. Original ABI/types, complete callers,
concurrent/fault behavior and whole-node closure remain unresolved.
