# RE-002: node #115 CFA bases and saved RBP

- Component: `foundation`; bounded build-provenance question, not component ownership.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Claim: observed unwind-state census and selected instruction evidence; the
  build-wide `frame_pointers` setting remains **unknown**.
- Included: all 135,313 `.eh_frame` FDE records; selected complete FDE-described
  instruction ranges. Excluded: full unwind-register semantics, runtime execution,
  source/object attribution and compiler-flag recovery.

The active RE-002 provenance record asks for a prologue survey to resolve its
`frame_pointers` unknown. This packet establishes the measured #115 frame-policy
evidence needed before selecting candidate compiler settings: saving RBP and
using RBP to calculate the canonical frame address (CFA) are different facts.
It does not restore the retired #94 packet or transfer that target's acceptance.
Both native exports below were captured from #115 before this analyzer was written.
The analysis code is independently authored, uses existing shared ELF/FDE readers,
and adds no shared infrastructure or package dependency.
New analysis code and documentation use the repository's MIT terms; captured
instruction evidence retains its upstream rights. No inferred source is copied.
The active RE-002 analysis was blocked at CFA classification: `fde_extents.py`
provides ranges rather than CFA states, and the native tools format inherited
states differently. The small packet-local adapter reconciles those formats;
the resulting census and instruction examples are the research deliverable.

## Observations

GNU binutils 2.42 and LLVM 18.1.3 agree on every FDE's section-relative record
offset, CIE offset, start/end VA, changes to CFA, and whether any decoded row saves
RBP at a CFA-relative stack address. The existing `eh_frame_records` reader binds
both native record lists to the authenticated ELF; every range is contained in an
executable section. This is an FDE denominator, **not a function census**.

| CFA bases seen within one FDE | FDE records |
| --- | ---: |
| RSP only | 133,651 |
| RBP and RSP | 1,263 |
| RBP only | 365 |
| R11 and RSP | 33 |
| R11, RBP and RSP | 1 |
| Total | 135,313 |

1,629 records use an RBP-based CFA at some point. 45,978 records have a
CFA-relative saved-RBP rule; **44,349 of those never use RBP as the CFA base**.
The cross-tabulation is in `summary.json`. This does not count every `push rbp`
instruction or prove that a saved register is used for any particular purpose.

GNU emits no FDE rows for 11,827 records that only inherit their CIE state;
LLVM emits one initial row. The first exploratory comparison reported precisely
11,827 empty-versus-inherited differences. The final parser explicitly inherits
the referenced CIE's single state in that case, with no guessed default. Both
then expose 1,469,455 rows. The comparator removes only consecutive unchanged
CFA values, preserving the PC of each CFA change; it ignores other register
rules except the saved-RBP Boolean. It rejects unsupported CFA expressions.
No instruction, address, call target or relocation is normalized.

## Selected bytes and limits of prologue classification

All addresses are linked ELF VAs before load bias. `selected-bodies.json` gives
file offsets, FDE/CIE section offsets, full body hashes, native producer commands
and output hashes. GNU and LLVM disassembly byte columns independently reproduce
every byte of each selected FDE interval, without gaps or overlapping instructions.
The native files are unedited. Nearest-symbol labels printed by objdump do not
identify these stripped ranges or their source language.

| FDE-described interval | Observed distinction |
| --- | --- |
| `0x1419300..0x1419326` | RSP CFA; entry-shaped code, not assumed ordinary function |
| `0x141b3b0..0x141b3b6` | CIE-only inherited state; GNU has no FDE row |
| `0x141c240..0x141c267` | `55 48 89 e5`: push RBP, then move RSP to RBP; CFA becomes RBP+16 at `0x141c244` |
| `0x141f730..0x141fb33` | saves RBP, pushes other registers and subtracts `0x168` from RSP; CFA stays RSP-based throughout |
| `0x298af40..0x298b04d` | copies RSP to R11, subtracts `0x40000` from R11 and probes the stack in `0x1000` steps; CFA temporarily uses R11 |
| `0x5d20100..0x5d21214` | selected mixed RSP/RBP/R11 record; no recovered source owner claimed |
| `0x6367e53..0x6367e58` | one call to `abort@plt`, with RBP+16 already active; no local frame-setting prologue |

The last example directly warns against equating each FDE start with an
independent function entry. Calls and data references remain in raw disassembly;
their transitive closure, source identities and behavior are not reconstructed.
No incoming-xref completeness, Rust implementation or byte-equivalence window is
claimed. This packet requests no gate; all 92 full-scope gates remain unchanged.

## Reproduce

Use the materialized pinned artifacts and real pinned source submodules required
by the repository. Linux / Python 3.12.3, GNU readelf and objdump 2.42, and LLVM
dwarfdump/objdump 18.1.3 were used; `versions.json` retains full version output.
The commands run analysis tools only, never the captured node or visor.
From the repository root, with a new ignored output directory:

```sh
make doctor verify
mkdir -p work/node115-cfa/native
LC_ALL=C readelf --debug-dump=frames-interp artifacts/node/115/hl-node > work/node115-cfa/native/gnu-frames.txt 2> work/node115-cfa/native/gnu-frames.stderr
LC_ALL=C llvm-dwarfdump --eh-frame artifacts/node/115/hl-node > work/node115-cfa/native/llvm-frames.txt 2> work/node115-cfa/native/llvm-frames.stderr
python3 research/work-items/RE-002-node115-cfa-frame-policy/reconcile.py . work/node115-cfa/native work/node115-cfa/analysis
python3 research/work-items/RE-002-node115-cfa-frame-policy/capture.py . work/node115-cfa/native work/node115-cfa/analysis work/node115-cfa/packet
python3 research/work-items/RE-002-node115-cfa-frame-policy/check.py work/node115-cfa/packet
python3 research/work-items/RE-002-node115-cfa-frame-policy/controls.py
make verify test catalogue-check reproduce
```

Both complete exporters exited 0, with empty stderr. Full uncompressed exports
are 103,141,954 and 206,541,766 bytes. They and the full projected JSONL are
retained as working analysis output, **not committed payloads**. `summary.json`
binds the complete raw exports by SHA-256 and size. All three raw CIE records and
seven selected raw FDE records, both complete disassemblies for each selected
interval, the complete census/corruption results, and reproduction code are
committed. Regeneration checks these frozen outputs, including full-export hashes,
rather than accepting newly generated counts as their own expected answer.

Nine comparator corruption controls reject a missing/reordered FDE, changed
FDE/CIE offsets or range endpoints, changed CFA, saved-RBP Boolean, and CFA-change
PC. These operate on decoded native records; they are not execution or unwind
engine tests. Four additional controls alter the retained native CIE CFA, name
an unsupported CFA register, remove the referenced CIE, and supply a wrong
target image. The last refuses before reading native files or creating output.
Native/binary bounds and row-order guards are additional input checks.
No runtime ABI correctness is inferred from them.

Repository validation results are recorded in `VALIDATION.md`. Initial missing
tool PATH, unmaterialized current #115 LFS fixtures, and three failed test files
caused by missing Capstone are preserved in the private run evidence. The
corrected run uses actual tools, the current fixtures and isolated Capstone 5.0.6;
the packet's own native census does not depend on Capstone.

## Inference, unresolved fields and next question

The target contains mixed unwind conventions and examples with and without local
RBP frame setup. A blanket inference from `push rbp` to forced frame pointers is
unsupported. Because object/language ownership, hand-written assembly, unwind
metadata correctness, and code without FDEs remain unresolved, neither the exact
Rust `force-frame-pointers` setting nor all frame-chain conventions are recovered.
The existing generated provenance field stays unknown.

Next: attribute a bounded first-party #115 object/function family independently,
then compare candidate rustc 1.95.0 prologues and unwind states under explicitly
recorded compiler settings. Such a build experiment would still require body,
helper, data and relocation comparison before claiming reconstruction.
