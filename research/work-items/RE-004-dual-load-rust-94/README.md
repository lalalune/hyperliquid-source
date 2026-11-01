# RE-004: close both loaded dual-lookup windows

Component: foundation. Task: reconstruct the complete byte-indexed dual
load and resolve the B-window relocation caveat left by
`foundation-byte-indexed-dual-load-94`. The prior static packet pinned a
12-word A prefix, counted 127 B relocations, and explicitly excluded
their addends and runtime word contents. This contribution binds every
reachable word and independently implements the numeric RAX/RDX result.

Target node94: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF VAs. Baseline main is
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; the unchanged can1357
reference gitlink is `999556f6e0a474b8312db96ec3149e1c44e97c23`.
No inferred unlicensed source was copied. New Rust and evidence are
independently authored by OpenAI/Codex; the exact runtime model identifier
is unavailable. The original numeric data observations retain their
binary provenance; no captured instruction bytes implement the function.

The complete leaf is `[0x4e48600,0x4e4861d)`, 29 bytes/seven instructions,
with three following padding bytes. A=`0x7c13f8` and B=`0x5749c90` each
have a complete 256-qword reachable window. All 80,300 RELA records are
scanned for overlap. None touches A; exactly 127 unique, aligned,
symbol-zero RELATIVE records affect B. Every other B word retains file
bytes. The Rust constants and four mask words represent those measured
facts, and an explicit u64 bias supplies the loaded-image arithmetic.
For example B index 20 remains 98 even with a nonzero bias; adding the bias
to every word would be wrong. These windows are not claimed to be single
logical arrays or to have recovered source types.

[PROOF.md](PROOF.md) derives the complete relation and states successful
loader/stable-memory premises. No caller is inferred from the sole entry
naming relocation; the no-direct-E8 result is not a complete xref census.

## Before, after and qualification

Before Rust existed, the full static record, byte-image relocation oracle
and frozen input/output streams were committed to local evidence files.
The freeze pins their hashes and records source-directory absence. The
oracle applies all relocation records to an immutable initial image then
extracts qword bytes; Rust uses per-index constants and bit-mask selection.

All 38,140 frozen records match across four native runs (152,560 output
observations). Repeated artifacts and outputs are identical at opt0 and
opt3. The corpus covers every index at 131 shared biases, wrap thresholds
for every relocated word and seeded additional values. There are 19,119
relocated cases and 19,021 raw-word cases. All 15 compiled mutants differ:
relocating every entry changes 18,892 records; ignoring all relocations
changes 18,992; narrowing the bias to 32 bits changes 14,928. Three unit
tests/profile, malformed framing and two comparator controls pass.

Thirty static corruption controls verify meaningful downstream bindings,
including type/symbol/addend mutations in early/middle/last relocation
records. All 132 exact command streams are retained with content hashes
in `native-streams.json.gz`; `native-commands.json` and
`native-result.json` bind commands, tools, source, compiler/linker and
first divergent mutant observations. All archives are round-trip checked.

Twelve predecessor tests, rustfmt, doctor, verify, catalogue-check and
reproduce pass. `repository-checks.json.gz` records exact commands and
outputs with path-only redaction and original/retained hashes. The shared
971-file legacy sweep remains separately in progress; its three storage
errors have independently passed all 20 affected tests after cleanup.
No unfinished aggregate or queued hosted checks are claimed successful.

## Reproduce

Use materialized, unchanged pinned inputs. Static analysis used Python
3.14.3, Capstone 5.0.7, GNU binutils 2.47.20260726 and Apple LLVM 17. Native
qualification uses actual macOS aarch64 rustc 1.94.1/LLVM 21.1.8, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Exact versions, hashes and compiler flags are retained in the results.
From the repository root:

```sh
make doctor
make verify
make catalogue-check
make reproduce
python3 -B -m unittest tests.test_foundation_byte_indexed_dual_load -v
python3 -O -B research/work-items/RE-004-dual-load-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-dual-load-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-dual-load-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/dual-load-review
```

Use a fresh output directory. The new dependency-free component builds
directly through pinned rustc; no artificial root workspace or lockfile
is introduced. No captured executable or instruction emulator runs.

The result remains a numeric loaded-image projection. Arbitrary runtime
table mutations, loader faults, invalid process mappings, original input
faults, MMIO/concurrency, native ABI and compiled-target byte identity
are outside scope. The input byte and returned values have no inferred
application meanings. Component/progress gates, pins and generated
coverage remain unchanged; whole-node equivalence is not claimed.
