# RE-004: chained-field accessor pair with complete image effects

Component: foundation. This independently reconstructs the complete
node94 functions `[0x514ac20,0x514ac3f)` and `[0x514ac40,0x514ac5f)` as
one safe Rust family. The preceding `foundation-chained-field-pair-94`
packet bound their static rules but provided no Rust implementation.
The new question is the complete read/store relation under arbitrary
data aliases, including four-byte sign extension and full returned RAX.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF VAs. Main baseline is
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; the can1357 reference gitlink
remains `999556f6e0a474b8312db96ec3149e1c44e97c23`. No inferred unlicensed
implementation was copied. New source/evidence are independently authored
with OpenAI/Codex; exact runtime model unavailable.

Both members follow two qword pointers, load a selected deep field, store
one qword and return full RAX=1. The first reads only four value bytes and
sign-extends them: 0x80000000 becomes 0xffffffff80000000. The second reads
all eight bytes. Every read precedes the output store, so the output can
overlap any previously read data. New safe refusals preserve all bytes.
[PROOF.md](PROOF.md) states every read, wrapped field address, store and
checked-image premise. The adjacent indexed accumulator is excluded.

All 62 body bytes/fourteen instructions, exact FDE/CIE records, two padding
bytes, E8/E9 zero-candidate scans and 80,300 RELA records are bound. No
naming relocation, outgoing call or static-data dependency remains.
GNU/LLVM/Capstone agree on complete bytes and starts. Seventeen structural
corruption controls pass independently of the whole-target digest.

## Qualification and reproduction

The pre-Rust oracle froze 8,890 records: 6,641 normal results and 2,249 new
refusals. It uses base-256 arithmetic, mathematical sign extension and byte
replacement; Rust uses checked slices and integer/endian conversions.
Every output-byte position, read/output endpoint, value bit and neighbors,
signed boundaries, wrapped field addresses and additional alias layouts
are represented. Native fixtures have 256-byte capacity; the API does not
impose that capacity.

All 35,560 observations match at opt0/opt3 and repeated builds, including
full image bytes and raw RAX. Repeated library/client/output hashes agree.
Three units per profile, malformed framing/descriptor checks, two comparator
controls and seventeen effective compiled mutants pass their expected
checks. The early-output-check mutant changes only safe refusal ordering;
it is not presented as an admitted native-value counterexample. All 148
exact command streams, first counterexamples and source/tool hashes are
retained losslessly.

Eleven predecessor tests, rustfmt, doctor, verify, catalogue-check and
reproduce pass. `repository-checks.json.gz` retains exact command streams
with path-only redaction and original/retained hashes. The shared baseline
sweep completed 971 files/15,462 reported tests/69 skips. Its original exit
2 came solely from three disk-full errors; all 20 affected tests passed an
isolated retry. No successful repeat of the whole sweep, full-suite run on
this separate head, skipped Linux qualification or hosted success is claimed.

Tools: Python 3.14.3, Capstone 5.0.7, GNU binutils 2.47.20260726 and Apple
LLVM 17. Native macOS aarch64 rustc 1.94.1/LLVM 21.1.8 is pinned to commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, compiler SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Use unchanged materialized pinned inputs. From the repository root:

```sh
make doctor
make verify
make catalogue-check
make reproduce
python3 -B -m unittest tests.test_foundation_chained_field_pair -v
python3 -O -B research/work-items/RE-004-chained-field-pair-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-chained-field-pair-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-chained-field-pair-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/chained-field-review
```

Use a fresh output directory. No artificial root workspace or lockfile is
introduced. Captured binaries and instruction emulators never run. Original
ABI, fault timing, MMIO/concurrency, control/code aliases, flags and physical
access traces are excluded. No compiled-target identity, source identity,
whole-node equivalence or component gate is claimed. Pins, generated
coverage and progress remain unchanged.
