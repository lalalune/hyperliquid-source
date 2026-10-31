# RE-001: One relocation-backed entry candidate at 0x54aa940

- Component ID: none; bounded function-map/reference evidence.
- Target: node #94, Linux x86-64, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`; independently authored analyzer/tests are hash-bound in METADATA.json.
- Reference source: no inferred can1357 implementation was used or copied.
- Claim status: observations (native instructions, FDE relationship, encoded slot and RELA record, data bytes); inference (one boundary candidate); unresolved (algorithm, original source identity, ABI and runtime dispatch).
- Included: candidate `[0x54aa940,0x54aaaf9)`, the selected encoded call at `0x14f92e3`, its slot/relative relocation, and three 16-byte data references.
- Excluded: other gap entries, higher-level hash consumers, a complete caller graph, caller selector/argument semantics, execution, Rust implementation, equivalence and progress-gate changes.

## Reproduce

Observed environment: Python 3.12.14, GNU objdump (GNU Binutils for Debian) 2.44,
Linux x86-64. Static parsing/disassembly only. Native tools read small owned
scratch slices: 441 bytes of candidate code and a 505-byte caller prefix.
No full-node scratch snapshot or whole-node disassembly is produced. Captured
code is not executed; no chain actions, signing, datasets or target networking
are involved.

From the repository root, with authenticated pinned inputs:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/node94_relocated_leaf_54aa940.py --output-dir work/relocated-leaf-repeat
cmp work/relocated-leaf-repeat/report.json research/work-items/RE-001-relocated-leaf-54aa940/report.json
cmp work/relocated-leaf-repeat/leaf-instructions.json research/work-items/RE-001-relocated-leaf-54aa940/leaf-instructions.json
cmp work/relocated-leaf-repeat/caller-prefix-instructions.json research/work-items/RE-001-relocated-leaf-54aa940/caller-prefix-instructions.json
cmp work/relocated-leaf-repeat/leaf.objdump research/work-items/RE-001-relocated-leaf-54aa940/leaf.objdump
cmp work/relocated-leaf-repeat/caller-prefix.objdump research/work-items/RE-001-relocated-leaf-54aa940/caller-prefix.objdump
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_node94_relocated_leaf_54aa940.py -v
```

The output directory must be absent. Two analyzer runs produce identical five
output files on the recorded tool version. METADATA.json pins the inputs,
sources, outputs, environment and seven focused test results. Required
repository checks are recorded separately on the final publication commit.

The existing RE-001 FDE packet identifies the larger non-fill gap at
`[0x54a54dd,0x54b41e0)`. This collector independently authenticates the
current base bytes and checks absence of an intersecting FDE for only the
selected 441-byte span. [PR #373](https://github.com/lalalune/hyperliquid-source/pull/373)
left the larger gap's contents open; its branch is not an input. Held parser
and higher-level hashing work is unchanged.

## Evidence

Coordinates are linked ELF virtual addresses, not runtime ASLR addresses.
Every selected record also carries its file offset, raw bytes and SHA-256.

| Separate observation | Count / span |
| --- | --- |
| Candidate code | `[0x54aa940,0x54aaaf9)`, 441 bytes |
| Native instructions / statically reachable instructions | 95 / 95 |
| Local basic blocks / direct branches / RET | 4 / 2 / 1 |
| Selected incoming reference edges | **1**, not a complete incoming-call count |
| Native caller prefix | `[0x14f90f0,0x14f92e9)`, 505 bytes / 105 instructions |
| Referenced read-only data | 3 distinct spans of 16 bytes; 48 bytes total |
| FDE records examined / intersecting the candidate | 121,299 / 0 |

The candidate starts with native-decoded ENDBR64 at `0x54aa940` and closes
at RET `0x54aaaf8`. Its two direct destinations are independently computed
from their actual signed displacement bytes: `0x54aaa8d → 0x54aaae9` and
`0x54aaae4 → 0x54aa9b1`. Both land on instruction starts inside the candidate.
Every selected instruction is reachable in the local CFG overapproximation.
This is a boundary candidate, not proof of an original Rust/source function,
feasible paths, a calling convention or behavior.

The selected reference chain is encoded in the actual target:

1. Call instruction `0x14f92e3` has bytes `ff 15 9f 6d 27 04`.
   Its next-IP plus signed disp32 computes slot `0x5770088`.
2. That instruction is a native decode boundary reached by linearly decoding
   from the real containing FDE start `0x14f90f0`. The FDE ends at
   `0x14f93de`; the collector stops its prefix at the call's end.
   It does not build the caller's CFG or resolve its indirect selector.
3. The one selected `.rela.dyn` record has `r_offset=0x5770088`,
   `r_info=8` (R_X86_64_RELATIVE, symbol index zero), and
   `r_addend=0x54aa940`. Thus ELF relocation metadata associates the slot
   with `load_bias + 0x54aa940`.
4. The slot's original eight file bytes are zero. They are retained as file
   evidence, not mistaken for an already relocated runtime function pointer.
   Runtime slot contents, overwrites, dispatch selection and execution are
   not observed.

The original caller FDE at `0xcf4438` and its CIE at `0xce1518`
are retained as 80-byte and 24-byte records. Their parser-source hashes are
recorded; no unwind record count is credited as a validated function denominator.

Three native MOVAPS memory operands reference `.rodata`. Each target is
computed from its encoded disp32 and checked against the native annotation:

| Instruction | Data VA | Bytes |
| --- | --- | ---: |
| `0x54aa94b` | `0x800580` | 16 |
| `0x54aa99f` | `0x8005a0` | 16 |
| `0x54aa9a7` | `0x800590` | 16 |

The 48 bytes, their hashes and section/file coordinates are retained without
algorithm attribution. All three mappings are allocated, file-backed,
non-executable and non-writable. The caller/leaf scratch decodes agree with
direct GNU decoding of the corresponding actual ELF windows on every
address/byte/width triple. This is two coordinate paths through one GNU
decoder, not independent decoder agreement.

## Implementation and comparison

The new collector authenticates the complete target before extraction and
again after extracting the small selected spans. It parses actual FDEs and
RELA metadata, validates byte-complete native decoding, recomputes local
branches and RIP-relative targets, and records the one selected edge
separately from candidate CFG counts. It imports only the unchanged maintained
ELF/FDE parsers; no unmerged collector is a dependency.

Seven actual-input controls cover:

1. The authenticated candidate CFG, caller FDE, selected edge and 48-byte data scope.
2. Native scratch-slice versus whole-ELF coordinate/decode agreement for both windows.
3. Retargeting the actual call disp32 by eight selects a different slot and
   is rejected as evidence for this edge.
4. Altering the actual RELA addend or relocation kind no longer binds this slot
   to this candidate and is rejected.
5. Moving the actual conditional target one byte into an instruction is rejected.
6. Retargeting an actual data-load displacement to the writable slot cannot
   be counted as a read-only constant reference.
7. Reusing native output after changing an actual selected instruction byte
   fails the byte binding.

Corruptions affect only owned small slices/records or output comparisons.
Original artifacts, shared hardlinks, imported evidence and pinned reference
worktrees are not edited. No independently authored Rust, source build,
runtime behavior comparator or normalization mask is implemented or claimed.

## Results and limitations

Focused controls pass 7/7 with no skips; repeat output sets match exactly.
The result is **one 95-instruction candidate CFG and one selected static
reference edge**, not a function/caller census or a completed component.
All acceptance gates remain unchanged and false.

Original source names, algorithm identity, ABI, caller selector feasibility,
runtime slot state and higher-level hashing consumers remain outside the
claim. The next question is whether separate approved evidence establishes
an original source/build identity or entry contract for this candidate.
