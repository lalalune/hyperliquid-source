# RE-004: deep comparator with the complete return pair

Component: foundation. This independently reconstructs the complete
node94 `[0x51c0c00,0x51c0c18)` leaf previously covered only by
`foundation-two-struct-deep-field-compare-94` static evidence. The
bounded question is its full RAX/RDX behavior and four-read memory
domain, including the partial-register result omitted by a Boolean API.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF VAs. Main baseline:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The can1357 reference
gitlink remains `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred
unlicensed implementation was copied. New code/evidence are independently
authored by OpenAI/Codex; the exact runtime model is unavailable.

Before this change the target's low-byte comparison was static evidence
with no Rust implementation. After it, the safe readonly-image API
returns both full numeric registers: RAX keeps the first deep value's
upper 56 bits while AL becomes the unsigned second-below-first result;
RDX keeps the second hop pointer. For values 0x1234 and 0x1000, RAX is
0x1201, not 1. The API preserves ordered reads, modular field addresses
and arbitrary readonly aliases. [PROOF.md](PROOF.md) states every path,
the checked-image domain and new refusal policy.

The entire 24-byte/seven-instruction leaf and complete 3,498-byte/
766-instruction caller are decoded by GNU/LLVM/Capstone with matching
bytes/boundaries. Exact FDE/CIE records, eight padding bytes, one
confirmed direct call and relocation checks close local dependencies.
Twelve structural corruption controls pass independently of the global
target digest. No helper or static data dependency exists. Indirect
callers and source/application meaning remain unclaimed.

## Qualification and reproduction

The pre-Rust oracle freezes 4,827 records (3,873 normal returns and 954
new refusals). It uses base-256 qword construction and quotient-based
low-byte replacement, independently of the Rust endian conversion and
bit mask. Every low-byte value, every bit, comparison extremes, aliases,
wrapping field addresses and exact/short bounds are exercised. All
19,308 native observations match in four runs, with identical repeated
library/client/output hashes at opt0 and opt3.

Three units/profile, malformed driver framing, two comparator controls
and 16 compiled mutants pass their expected checks. Zero-extending a
Boolean loses 3,441 normal results. All 138 raw command streams, first
counterexamples and source/tool/compiler/linker/artifact hashes are
retained losslessly. Independent peer review used a dictionary-backed
memory relation to recompute every row, reviewed the complete proof
and reran static controls under Python `-O`; no blocker.

Eight predecessor tests, rustfmt, doctor, verify, catalogue-check and
reproduce pass. `repository-checks.json.gz` retains exact command output
with path-only redaction and original/retained hashes. The shared
971-file legacy sweep remains in progress; its three earlier storage
errors separately passed all 20 affected tests after cleanup. Neither
unfinished aggregate nor queued hosted checks are claimed successful.

Tools: Python 3.14.3, Capstone 5.0.7, GNU binutils 2.47.20260726 and Apple
LLVM 17. Actual native macOS aarch64 rustc 1.94.1/LLVM 21.1.8 is pinned to
commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Use unchanged materialized pinned inputs. From the repository root:

```sh
make doctor
make verify
make catalogue-check
make reproduce
python3 -B -m unittest tests.test_foundation_two_struct_deep_field_compare -v
python3 -O -B research/work-items/RE-004-deep-compare-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-deep-compare-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-deep-compare-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/deep-compare-review
```

Use a fresh output directory. This dependency-free component builds
directly with rustc, without a root workspace or artificial lockfile.
Captured code and instruction emulators never run. Native faults,
MMIO/concurrency, control/code aliases, flags, timing and original ABI
are outside the numeric projection. No compiled-target byte identity,
whole-node equivalence or completed component gate is claimed. Pins,
generated coverage and progress remain unchanged.
