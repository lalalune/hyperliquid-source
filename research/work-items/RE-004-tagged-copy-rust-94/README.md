# RE-004: tagged copy under arbitrary input/output overlap

Component: foundation. This reconstructs the complete node94 tagged-copy
leaf `[0x22155a0,0x22155c0)`, previously documented only by the static
`foundation-tagged-copy-94` packet. The bounded question is whether its
full final memory and raw RAX relation can be independently implemented
without assuming disjoint source and destination.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Coordinates are linked ELF virtual addresses. Main baseline is
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unchanged can1357 gitlink
`999556f6e0a474b8312db96ec3149e1c44e97c23`. No inferred unlicensed
implementation was copied. New code and evidence are independently
authored by OpenAI/Codex; exact runtime model unavailable. Imported
instruction observations retain their target provenance and are not
transplanted into executable code.

The new safe image API snapshots all 32 input bytes before writing
the payload after the exact little-endian tag `0x8000000000000014`.
For identical source/destination, the copied payload retains the old
first eight source bytes; writing the tag first would corrupt it.
RAX is the complete numeric destination, rather than a tag or Boolean.
[PROOF.md](PROOF.md) derives every final byte and explains why one
32-byte payload copy is equivalent to the two original disjoint stores
after the full snapshot, under explicit stable-memory premises.

The full 32-byte/eight-instruction leaf, unique FDE/CIE, next-FDE
zero-padding boundary, absence of direct calls and absence of naming
or code-overlapping relocations are bound. GNU/LLVM/Capstone agree on
every byte and boundary; fifteen downstream corruption controls pass
without substituting a whole-file digest mismatch for structural checks.
Indirect callers, source types and the tag's application meaning remain
unknown.

## Qualification

The independent oracle and its 8,003 input/output records were frozen
before Rust existed. It uses a direct immutable final-byte relation;
Rust captures a local payload then performs writes. There are 6,136
normal results and 1,867 explicitly new atomic refusals, including
5,465 admitted overlaps and 368 same-address cases. Full overlap
displacements, alignment phases, every payload bit, exact-end and short
images, high numeric bases and seeded data are covered.

All 32,012 native observations match in four runs, with repeated
library/client/output hashes identical at opt0 and opt3. Three unit
tests/profile, malformed framing, two comparator controls and all
13 compiled mutants pass their expected checks. Twelve mutants change
admitted values; strict-boundary changes cause 150 false refusals only.
The complete 120 raw command streams are retained losslessly with
command, source, tool, compiler/linker and artifact hashes and first
counterexamples. The independent peer review rederived all frozen
records and reran static controls under Python `-O`, finding no blocker.

Ten predecessor tests, rustfmt, doctor, verify, catalogue-check and
reproduce pass. Repository command outputs retain original and
path-redacted hashes in `repository-checks.json.gz`. The shared
971-file legacy sweep is separately still running. Three earlier
storage errors passed all 20 affected tests on isolated retry; no
unfinished aggregate or queued hosted check is claimed successful.

## Reproduce and limits

Use unchanged materialized pinned inputs. Tools: Python 3.14.3,
Capstone 5.0.7, GNU binutils 2.47.20260726 and Apple LLVM 17. Native
qualification pins macOS aarch64 rustc 1.94.1/LLVM 21.1.8, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, compiler SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Exact tool versions and options are retained in the archives.

From the repository root:

```sh
make doctor
make verify
make catalogue-check
make reproduce
python3 -B -m unittest tests.test_foundation_tagged_copy -v
python3 -O -B research/work-items/RE-004-tagged-copy-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-tagged-copy-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-tagged-copy-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/tagged-copy-review
```

Use a fresh output directory. The dependency-free component builds
directly with rustc; no root workspace or artificial lockfile is added.
Only new Rust executes. Original faults, MMIO/concurrency, control/code
aliases, intermediate stores, flags/other registers and native ABI are
excluded. No captured execution, instruction emulator, target compiled
byte identity or whole-node equivalence is claimed. Pins, generated
coverage and progress/component gates remain unchanged.
