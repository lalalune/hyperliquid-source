# foundation-gated-dword-compare-94: what does the gated dword compare window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 31-byte FDE window with one padding byte, the gated dword compare rule with its exact field offsets and branch target, the exact incoming-call scan result (zero direct sites), and the single relocation slot.
- Excluded: what the gate byte and the two dwords mean, what reads the result, any wider compare-gate family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a gated dword compare that returns 0 when a gate byte is clear, and otherwise 1 exactly when one dword is strictly below another (unsigned). It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x53b1080`, no open pull request title mentions it or gated-dword-compare, and its bytes overlap nothing in packets #1–#90.

## Scout note

The round-14 scout note listed this window (ranked #3) with FDE `[0x53b1080, 0x53b109f)`, 31 bytes, 1 padding byte, zero direct callers, one R_X86_64_RELATIVE slot (`0x5764818`), and nearest claimed window three-field sum `0x53a3750` (packet #87) `0xd930` away. Every element verified exactly, including the full body, the branch target, the zero incoming sites, and the single slot address. No numeric correction to the scout's numbers was needed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_gated_dword_compare.py --check research/work-items/foundation-gated-dword-compare-94/evidence.json
python3 -m unittest tests.test_foundation_gated_dword_compare -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x53b1080 --stop-address=0x53b10a0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its one padding byte. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2b57d8` (this window) and `0x2b57ec` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2b57d8` describes `[0x53b1080, 0x53b109f)`, 31 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- One `int3` byte follows: the next FDE starts exactly at `0x53b10a0` (record at `.eh_frame+0x2b57ec`, range to `0x53b10b3`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a `0x409280`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: gated dword compare, one branch, no calls

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | f3 0f 1e fa | endbr64 |
| 0x04 | 0f b6 87 28 02 00 00 | movzbl 0x228(%rdi),%eax |
| 0x0b | 84 c0 | test %al,%al |
| 0x0d | 74 0f | je 0x53b109e |
| 0x0f | 8b 87 10 01 00 00 | mov 0x110(%rdi),%eax |
| 0x15 | 39 87 14 01 00 00 | cmp %eax,0x114(%rdi) |
| 0x1b | 0f 92 c0 | setb %al |
| 0x1e | c3 | ret |

Rule, derived step by step: the first load places the gate byte `[rdi+0x228]` (zero-extended) in eax; the test sets flags from that byte; the branch jumps to `ret` when it is zero, so the gated-off path returns 0. Otherwise eax is replaced with the dword `[rdi+0x110]`; the compare computes `[rdi+0x114] - eax` and sets flags, so `setb` writes 1 exactly when `[rdi+0x114]` is strictly below `[rdi+0x110]` as unsigned dwords, and 0 otherwise. The branch target is exact: the `je` at offset `0x0d` is 2 bytes with displacement `0x0f`, landing on the `ret` at offset `0x1e` (`0x53b109e`). No field is written, and no other register state is claimed.

No call opcode appears inside the window, and there is exactly one forward branch (the gate branch above).

### Incoming calls: zero direct sites

A byte-pattern scan over the full `.text` section (70,370,352 bytes) for `e8` sites whose rel32 lands on the window start finds zero sites. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. The window is therefore bound without any caller provenance, and no caller purpose is claimed.

### Data edge: one RELATIVE slot, reported as a list

One `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries):

`0x5764818`.

No meaning is claimed for the table it belongs to, and the single slot does not identify the window's provenance.

## Inferences

- The "gated dword compare" label is an inference from the observed rule: a gate byte enables an unsigned comparison of two adjacent dwords. It is kept separate from the rule itself.
- The gate byte and the two dwords are plausibly fields of some structure, but their owning type is unknown and not claimed.
- The single relocation slot suggests the window is referenced from data rather than called directly, but that is an inference from the relocation pattern, not a proven call graph.

## Unknowns

- What the gate byte and the two dwords mean, and what reads the result.
- Whether the window is reached via the single relocation slot, via an indirect call, or via a tail jump (all out of scope for the direct-e8 scan).
- The source-level function, type, and component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
