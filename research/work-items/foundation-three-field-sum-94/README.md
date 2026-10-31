# foundation-three-field-sum-94: what does the three-field sum window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 23-byte FDE window with nine padding bytes, the three-field sum rule with its exact field order and wraparound semantics, the exact incoming-call scan result (zero direct sites), and the single relocation slot.
- Excluded: what the three fields mean, what reads the sum, any wider sum family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a three-field sum that adds three qwords from the same base pointer and returns the wrapping result. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x53a3750`, no open pull request title mentions it or three-field-sum, and its bytes overlap nothing in packets #1–#86.

Thinness is stated head-on: this is a thin backup item (round-13 backup B1) — a single three-instruction sum with no caller and one relocation slot. It is bound only because the rule locks exactly from its own bytes (fixed field order, wraparound edge verified by hand computation), not because it is rich.

## Scout note

The round-13 scout note listed this window (backup B1) with FDE `[0x53a3750, 0x53a3767)`, 23 bytes, 9 padding bytes, zero direct callers, one R_X86_64_RELATIVE slot (`0x5764648`), and nearest claimed window hash bit-probe loop `0x538ca50` (packet #77) `0x16d00` away. Every element verified exactly, including the full body, the zero incoming sites, and the single slot address. No numeric correction to the scout's numbers was needed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_three_field_sum.py --check research/work-items/foundation-three-field-sum-94/evidence.json
python3 -m unittest tests.test_foundation_three_field_sum -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x53a3750 --stop-address=0x53a3770 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its nine padding bytes. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2b5218` (this window) and `0x2b522c` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2b5218` describes `[0x53a3750, 0x53a3767)`, 23 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Nine `int3` bytes follow: the next FDE starts exactly at `0x53a3770` (record at `.eh_frame+0x2b522c`, range to `0x53a377c`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a `0x3fb950`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: three-field sum, no calls, no branches

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | f3 0f 1e fa | endbr64 |
| 0x04 | 48 8b 87 b8 01 00 00 | mov 0x1b8(%rdi),%rax |
| 0x0b | 48 03 47 28 | add 0x28(%rdi),%rax |
| 0x0f | 48 03 87 d8 01 00 00 | add 0x1d8(%rdi),%rax |
| 0x16 | c3 | ret |

Rule, derived step by step: the first load places `[rdi+0x1b8]` in rax; the first add adds `[rdi+0x28]`; the second add adds `[rdi+0x1d8]`; `ret` returns rax. All three operands are 64-bit qwords from the same base pointer, added in the fixed order 0x1b8, 0x28, 0x1d8, with 64-bit wraparound (the adds discard overflow, as the x86-64 `add` instruction does). No field is written, and no other register state is claimed.

No call opcode appears inside the window, and there are no branches at all: the sequence is straight-line from `endbr64` to `ret`.

### Incoming calls: zero direct sites

A byte-pattern scan over the full `.text` section (70,370,352 bytes) for `e8` sites whose rel32 lands on the window start finds zero sites. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. The window is therefore bound without any caller provenance, and no caller purpose is claimed.

### Data edge: one RELATIVE slot, reported as a list

One `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries):

`0x5764648`.

No meaning is claimed for the table it belongs to, and the single slot does not identify the window's provenance.

## Inferences

- The "three-field sum" label is an inference from the observed rule: three qword fields from one base, summed in a fixed order. It is kept separate from the rule itself.
- The three fields are plausibly counters or accumulators of some structure, but their owning type is unknown and not claimed.
- The single relocation slot suggests the window is referenced from data rather than called directly, but that is an inference from the relocation pattern, not a proven call graph.

## Unknowns

- What the three fields mean, and what reads the sum.
- Whether the window is reached via the single relocation slot, via an indirect call, or via a tail jump (all out of scope for the direct-e8 scan).
- The source-level function, type, and component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
