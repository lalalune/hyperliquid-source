# RE-001: Two boundary candidates inside node #94's unwindless 0x5631543 gap

- Component ID: none; binary-wide function-map input with no component ownership.
- Target: Linux x86-64 node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`; new analyzer and tests are independently authored and hash-bound in METADATA.json.
- Reference pin: can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23`; its inferred source was not used or copied.
- Claim status: observations (bytes, instruction boundaries, local CFGs, FDE absence); inference (two entry/boundary candidates); unresolved (original source functions, ABI, names, semantics and incoming indirect references).
- Included: only the non-fill span `[0x5631580,0x5631ef2)` inside one retained #94 gap.
- Excluded: the other assembly gap, a new unwind census, component ownership, execution, Rust reconstruction, equivalence and progress-gate changes.

## Reproduce

Static Python 3.12.14 and GNU objdump (GNU Binutils for Debian) 2.44 on Linux x86-64.
No captured code is executed. The native decoder reads a 2,418-byte scratch
slice, never an executable process. Raw instruction bytes are evidence, not
transplanted implementation. No source builds, installations, chain actions,
signing, public traffic or whole-node disassembly run is part of this packet.

From the repository root, with authenticated pinned inputs present:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/node94_gap_boundaries.py --output-dir work/gap-boundaries-repeat
cmp work/gap-boundaries-repeat/report.json research/work-items/RE-001-gap-boundaries-5631580/report.json
cmp work/gap-boundaries-repeat/instructions.json research/work-items/RE-001-gap-boundaries-5631580/instructions.json
cmp work/gap-boundaries-repeat/native.objdump research/work-items/RE-001-gap-boundaries-5631580/native.objdump
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_node94_gap_boundaries.py -v
```

The output directory must be absent. Two independently generated output sets
matched byte for byte on the recorded tool version. METADATA.json records their
hashes and the six observed focused test outcomes. A different objdump version
may print different operand text; identical printed text across providers is
not asserted. Required repository checks are recorded separately on the final
publication commit.

Motivation: [PR #373](https://github.com/lalalune/hyperliquid-source/pull/373)
explicitly leaves the contents of this gap as a next question after its raw
reach census. Its branch is not an input to this packet. The gap bounds below
are independently derived from the current base's actual ELF/FDE bytes using
the unchanged maintained parsers, not copied from that PR.

## Evidence

All intervals below are half-open linked ELF virtual addresses. File offsets
are separately recorded in report.json; the selected window begins at file
offset `0x5630580`.

| Observation | Region A | Region B |
| --- | ---: | ---: |
| Entry marker ENDBR64 | `0x5631580` | `0x56319fd` |
| Exclusive end, one byte after RET | `0x56319fd` | `0x5631ef2` |
| Bytes | 1,149 | 1,269 |
| Native-decoded instructions | 285 | 324 |
| Instructions reachable in the local CFG overapproximation | 285 | 324 |
| Basic blocks / direct branches | 9 / 6 | 9 / 6 |
| Decoded calls / RIP-relative operands | 0 / 0 | 0 / 0 |

These are two boundary **candidates**, not proven original Rust functions.
In particular, the second entry follows the first RET immediately, with no
alignment padding. A single non-fill gap therefore does not justify treating
its contents as one function.

The authenticated .eh_frame has 121,299 decoded FDE records; none intersects the
selected 2,418-byte window. Its preceding FDE describes
`[0x5631010,0x5631543)`, and its following FDE describes
`[0x5631f00,0x5632098)`. Their original FDE records at `0xfb9500` and
`0xfb9570`, and CIE at `0xce1518`, are retained as byte strings with file
coordinates and SHA-256 values in report.json. They bound a 2,493-byte gap:
61 bytes of `int3`, the two candidate regions, then 14 bytes of `int3`.
An FDE record count remains unwind metadata, not a validated function denominator.

Native decoding covers every selected byte contiguously. Each of the twelve
direct branch destinations is recomputed from its instruction's actual
signed displacement and checked against the decoder text. Every branch and
fallthrough reaches an instruction start inside the same candidate region.
Each candidate's CFG reaches all of its decoded instructions and closes at its
one terminal RET. No edge crosses between the candidates. Static reachability
does not prove that every path is feasible or safe.

The native raw-slice decode is also compared with GNU objdump decoding the
same addresses directly from the ELF: all 609 address/byte/width triples and
both resulting graphs agree. This corroborates coordinate extraction using
two invocations of the **same** decoder, not independent decoder agreement.
Nearest-symbol display labels are not treated as function names.

Data and references remain bounded:

- No RIP-relative operand or decoded call occurs in this selected span.
- All 80,300 ELF64 RELA records were examined. None places a relocation inside
  the span or has an R_X86_64_RELATIVE addend into it.
- A targeted byte search considers E8/E9 rel32 forms to only the two observed
  entry addresses. It examines 1,159,349 opcode-byte positions and finds zero
  candidates. This is not an instruction-decoded whole-node call graph and
  does not prove that the regions lack incoming indirect references.
- Register-derived memory access, arbitrary data words, source labels, original
  Rust ABI and higher-level behavior remain unresolved.

Raw native output, every decoded instruction, the local basic blocks/edges,
byte hashes, source-parser hashes and selected metadata records are retained
beside this document. Nothing is credited as a raw-equal reconstructed body.

## Implementation and comparison

The new MIT-authored `tools/node94_gap_boundaries.py` authenticates node #94,
derives the surrounding gap from its actual FDEs, extracts the small mapped
window, invokes the native decoder, checks every decoded byte and direct edge,
and retains a deterministic observation report. Existing `tools/fde_extents.py`
and `tools/elf_index.py` are read-only dependencies; their held PRs are unchanged.

The six target-grounded controls in `tests/test_node94_gap_boundaries.py` cover:

1. Exact authenticated window, adjacent FDE gap, partitions, local graphs and recorded counts.
2. Raw-slice versus whole-ELF native coordinate/decode agreement.
3. Altering the actual first conditional displacement by one byte makes its
   destination the interior of an instruction; CFG admission rejects it.
4. Inserting ENDBR64 bytes inside an actual MOVABS immediate creates no entry:
   markers must occur as complete native-decoded instructions.
5. Reusing the native output with a changed actual PUSH byte fails the byte binding.
6. Truncating the native output before the final RET fails completeness.

Mutations are confined to owned scratch slices or output text. Original
artifacts, reference worktrees, imported evidence and shared inputs are not edited.
No independently authored Rust, build result, behavior comparator, normalized
identity mask or whole-ELF equality is implemented or claimed.

## Results and limitations

The local result is 609 byte-bound native instructions in two closed CFG
candidates, with zero intersecting FDEs; focused controls pass 6/6 with no skips.
Deterministic reruns agree on all three retained output files. This is a
bounded function-map observation, not completion of RE-001 or any component.
All four component acceptance gates remain false.

The next question is whether decoded indirect call/data references establish
an original entry contract for either candidate, and which independently
licensed source or compiler provenance explains the two adjacent bodies.
That question is not answered by ENDBR64, RET, zero selected relocations or a
raw rel32 search.
