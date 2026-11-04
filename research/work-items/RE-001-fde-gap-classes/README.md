# RE-001: node #115 gaps outside unwind ranges

The authenticated node #115 capture contains 133 same-section `.text` gaps
with bytes other than `int3`. This packet classifies their bytes and checks
selected references into them. Seven islands have 16 validated entrypoints;
a separate 334-byte island has only data-pointer references in this scan.
An island is not a validated function or an ownership assignment.

- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Component/task: RE-001 function-map work; component ownership unassigned.
- Migration input: PR #40 head `4536d01b4a9de66d5c54d5a0a956f617246576e4`.
- Current source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Observation: gap bytes, disassembly, relocation records and the references
  revalidated from containing FDE starts.
- Inference: an entered island may contain code without unwind information.
- Unresolved: boundaries within islands, source/library identity, register
  indirect targets, jump tables, CFG reachability and whole-node coverage.

## Reproduce

From the repository root, Python 3.13.2 and GNU objdump 2.47.20260726:

```sh
make PYTHON=/opt/miniconda3/bin/python3 fde-gaps
python3 -m unittest discover -s tests -p test_fde_gap_classes.py -v
python3 tools/verify_packets.py
```

`fde-gaps` accepts only the active #115 target. It authenticates the artifact
against the repository manifest before static decoding. No captured executable
is run. The migration was regenerated twice on macOS arm64 using native GNU
binutils against the Linux x86-64 bytes. Both TSV exports match the original
#115 records byte for byte. The JSON comparison changes only the recorded GNU
provider version. The second regeneration must match all three current files.
The older target's CLI option, Makefile invocation and active outputs were
removed; the original PR remains a Git parent and preserves that history.

## Method and evidence

The shared parser obtains actual `.eh_frame` extents and the same-section
gaps between them. Each non-int3 gap is disassembled from its start with
15 bytes of lookahead so an instruction cut by the gap end is detected.
A separate canonical-NOP byte matcher checks the leading fill classification.
The remaining ranges are split at int3 runs with fill trimmed at both ends.

The tool streams the complete `.text` disassembly for direct branches and
RIP-relative operands, reads RELATIVE/IRELATIVE relocation addends, and records
reads of the relevant relocation slots. Every code source is disassembled
again from its containing FDE start and must match the same instruction at
the same address. Only an FDE-covered source or relocation slot can establish
an entry, and the destination must be an instruction start. Pointer entries
also require an `endbr64` destination. Island-originated references cannot
establish an entry because data may decode as instructions.

| Classification | Count | Bytes |
| --- | ---: | ---: |
| Fill-only gaps | 128 | 2,057 |
| Zero-byte gap | 1 | 6 |
| Gaps with other non-fill bytes | 4 | 63,886 |

The nine trimmed islands comprise seven entered islands, one pointer-only
island, and one four-byte zero island. Their exact bounds, raw-byte SHA-256
values and entrypoint lists are in `node-115-gap-classes.json`. The zero island
is part of the six-byte gap; the remaining two bytes are fill. There are no
byte-matcher disagreements or gap ends inside decoded instructions in this
capture. `node-115-gap-xrefs.tsv` retains the bounded reference records.
Raw GNU output for all nine island intervals is under `raw/`; nearest-symbol
annotations are not source symbols and data decodes do not prove code.

## Validation and limits

Fifteen focused tests cover fill parsing, malformed/wrapped decode rejection,
source revalidation, mid-instruction destinations, data pointers, relocations,
NOBITS overlap and refusal of the retired target. Eighteen shared FDE parser
tests also passed. `migration-validation.json` records hashes, commands, the
provider comparison, repeat generation and repository-check outcomes.

The new worktree's artifact SHA-256 and signatures verified, but `make verify`
stopped because its upstream submodules were not initialized. Final integration
must run the repository checks with the existing pinned imports; this is not
claimed as a full `make verify` pass in the isolated worktree.

Independent Rust reconstruction and binary comparison: not implemented here.
No gates or reconstructed-byte registry entries change. These results do not
establish complete functions, ownership, behavioral equivalence or a whole-node
denominator. Next question: trace the #115 CPU-feature selection of the
relocation-backed entrypoints and determine bounded code/data ownership.
