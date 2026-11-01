# Observed author validation

The frozen result is [validation.json](validation.json). The selected ELF was
read as data; only Python static evidence/mathematical checks and native objdump
processes ran. No captured target, instruction evaluator, emulator, source
implementation, repository-wide suite, or network/transaction action ran.

## Positive evidence

* Full target SHA-256 and 91,774,280-byte size matched before collection.
* Both native tools consumed one authenticated private read-only snapshot;
  its complete SHA-256 was checked before and after native exports.
* GNU 2.47.20260726 and Apple LLVM 21.0.0 agreed on all 3,208 normalized
  instruction boundaries and byte strings across 19 complete FDEs / 13,772 bytes.
  Standalone LLVM LOCK prefixes are joined only to their adjacent instruction.
* An independent ELF64 PT_LOAD mapper matched all complete bodies and selected
  literals against the section mapper. It independently read the full tag-2
  compare, parity mask and sample vector capacity niche.
* Full selected FDE/CIE bytes and `.eh_frame_hdr` links were checked. The
  structural census retains 717 basic blocks and 607 control transfers.
  Ten FDEs have 73 retained LSDA call-site rows. LSDA metadata is separate from
  normal control-flow edges; no unwinder/action semantics is claimed.
* 647 byte obligations bind every decoded control transfer and selected semantic
  windows; 14 literal obligations bind seven Location records and path strings.
  All 45 required RELATIVE slots require type 8 **and symbol index zero**;
  three imported slots bind raw relocation and dynamic-symbol/name bytes.
* Two fresh collections reproduced every retained file byte for byte: normal
  Python with `PYTHONHASHSEED=13,TZ=UTC`, and Python `-O` with
  `PYTHONHASHSEED=97,TZ=Pacific/Honolulu`. Each used both native providers.

## Corruption and sensitivity controls

All **883 controls** passed. Most operate below the whole-input SHA gate and
require the relevant predicate's rejection, rather than claiming that a digest
failure validates a semantic operand:

| Control class | Count |
| --- | ---: |
| Selected control/semantic byte obligations | 647 |
| Literal records and source paths | 14 |
| RELATIVE addend, kind, and nonzero-symbol corruptions | 135 |
| FDE extent, FDE raw bytes, unique CIE raw bytes | 40 |
| LSDA call-site metadata | 10 |
| Import relocation, symbol-record, and name bytes | 9 |
| Actual operative-field mutants, dual-native decoded | 17 |
| Other mapping, unwind-index, native-input and output-preservation controls | 11 |

The 17 operative controls change actual tag, mask, offset, count, pivot, niche,
growth, reciprocal, multiplier, copy-scale and conditional-branch fields in a
private in-memory copy. The checker first reads and confirms the changed value,
requires the selected byte predicate to reject it, and asks both native tools
to decode the changed **entire owning FDE**. Their changed partitions agree.
Those mutant files are never executed. The controls establish sensitivity to
the stated operands; they do not replace the manual semantic proof.

A deliberate unselected producer-prologue mutation passes the selected
anchor/literal/relocation subset and fails full native-to-target comparison.
This exposes the subset's limit instead of treating selected anchors as a full
body proof. Missing native rows, a wrong native byte, a dangling LOCK prefix,
an independently shifted section mapping, bad unwind metadata, wrong target
identity and an already-existing output directory are separately rejected.

## Mathematical consequences

The separate Python contract checks cover all 12 full-node insertion positions,
66 nonfull insertion positions, 66 child-link update intervals, the exact
all-u64 reciprocal-error bound plus 21 boundary keys, and 40,360 raw-record
stream cases with empty/existing maps, repeated keys, stop tags, parity aliases,
byte guards and bit-pattern payloads. List insertion independently checks pair
and child-edge conservation for the split plan. A declarative prefix/filter
oracle checks the record fold's result. Six witnesses distinguish common wrong
alternatives or verify preserved payload bits.

These are mathematical consequences of the explicitly conditional manual proof.
They do not compare target outputs, prove scheduler completeness, establish
allocator/import behavior, or form a compiled Rust oracle.

## Commands

The successful author run was:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-007-funding-sample-storage-94/verify.py
```

It includes both fresh collection commands and the mathematical checks. A prior
standalone `python3 -B .../consequences.py` run also passed. `AUTHOR-CHECKS.json`
records the packet-only whitespace/EOF/JSON/gzip and manifest preparation checks.
The author freeze precedes independent review; no independent acceptance is
claimed by this document.
