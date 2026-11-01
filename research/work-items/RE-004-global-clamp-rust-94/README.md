# RE-004: global clamp with closed tail stores and return

Component: foundation. This independently reconstructs the complete
node94 `[0x55539e0,0x5553a36)` function and actual tail helper
`[0x552fa70,0x552fa82)`. The existing `foundation-global-clamp-94`
packet left that helper unresolved; this contribution establishes the
three final output qwords and full returned RAX in safe Rust.

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are linked ELF VAs. Main baseline:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The can1357 reference
gitlink stays `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred
unlicensed implementation was copied. New source/evidence are independently
authored by OpenAI/Codex; the exact runtime model is unavailable.

For a runtime input of 0x10000040 the final state is
`[0x400000,0,0x10000040]` and RAX=0: the tail preserves the unshifted
normalized value while the first store caps the scaled value. Zero
produces `[1,0,1]`; every negative input clears all three words. The
input's captured `.data` initializer is -1, not a restriction on runtime
values. [PROOF.md](PROOF.md) closes every path and states the memory
premises of this numeric projection.

The 104 total main/helper bytes, 957-byte complete caller, exact FDE/CIE
records, two confirmed call sites, ten padding bytes, input `.data`
mapping, output `.bss`/PT_LOAD zero-fill mapping and 80,300 RELA records
are bound independently. GNU/LLVM/Capstone agree on complete bytes and
boundaries. Twenty-five static corruption controls pass independently
of the global digest. No helper result is fabricated or injected.

## Qualification and reproduction

The independent pre-Rust oracle froze 19,267 cases. Its piecewise
integer formula differs from Rust's shift/clamp implementation. All
77,068 observations match across opt0/opt3 and repeated builds; repeated
library, client and output hashes agree. Three units per profile,
malformed input framing, two comparator controls and 16 effective
compiled mutants exercise state, arithmetic and raw-return behavior.
Exact command streams, first counterexamples, source and tool hashes
are retained losslessly in the packet.

Independent peer review recomputed all 19,267 rows using a different
interval formula, reran all 25 static controls under Python -O, and
reviewed the complete source/proof; no blocker. All 138 exact native
command streams are archived.

The ten focused predecessor tests, rustfmt, doctor, verify, catalogue-check
and reproduce pass. `repository-checks.json.gz` retains exact command
output with path-only redaction and original/retained hashes. The shared
971-file baseline sweep completed with 15,462 reported tests and 69
skips. Its original make invocation exited 2 because three files hit
disk-full errors; all 20 tests in those files passed an isolated retry
after storage recovery. No clean repeat of the full sweep, full-suite
run on this separate head or skipped Linux qualification is claimed.
Hosted results are not claimed successful while queued.

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
python3 -B -m unittest tests.test_foundation_global_clamp -v
python3 -O -B research/work-items/RE-004-global-clamp-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-global-clamp-rust-94/oracle.py
python3 -O -B research/work-items/RE-004-global-clamp-rust-94/verify_rust.py \
  --rustc "$(rustup which --toolchain 1.94.1 rustc)" \
  --out work/global-clamp-review
```

Use a fresh output directory. No root workspace or artificial lockfile
is introduced. Captured code and instruction emulators never run. This
does not claim compiled-target identity, the original ABI, whole-node
equivalence or a completed component gate. Pins, generated coverage and
progress remain unchanged.
