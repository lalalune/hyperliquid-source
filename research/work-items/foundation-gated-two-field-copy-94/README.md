# foundation-gated-two-field-copy-94: what does the gated two-field copy window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 42-byte FDE window with six padding bytes, the gated two-field copy rule with its exact field offsets and branch targets, the exact incoming-call scan result (zero direct sites), and the single relocation slot.
- Excluded: what the gate byte, the pointer field, and the two copied fields mean, what reads the copied fields, any wider copy-gate family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a gated two-field copy that stores nothing when its pointer is null or its gate byte is clear, and otherwise copies two qwords from a pointed-to structure into a destination. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x53b1120`, no open pull request title mentions it or gated-two-field-copy, and its bytes overlap nothing in packets #1–#92.

## Scout note

The round-14 scout note listed this window (backup B1) with FDE `[0x53b1120, 0x53b114a)`, 42 bytes, 6 padding bytes, zero direct callers, one R_X86_64_RELATIVE slot (`0x57648b0`), and nearest claimed window three-field sum `0x53a3750` (packet #87) `0xd9d0` away. Every element verified exactly, including the full body, both branch targets, the zero incoming sites, and the single slot address. No numeric correction to the scout's numbers was needed.

One wording correction, stated head-on: the build brief paraphrased the gate as `[rdi+0x20]`. The bytes show the gate is the byte at `[rdi+0xb8]`; `0x20` is the offset of the first copied source field (`[p+0x20]`), not the gate. The corrected rule below is what the checker locks.

## Same-flag pair caveat

The immediately following FDE, `[0x53b1150, 0x53b116e)`, gates on the same byte `[rdi+0xb8]` and copies the 16 bytes at `[rsi+0x10..0x20]` into `[rdi+0x2b8]` when that byte is nonzero. That window is a same-flag pair with this one, and it is NOT claimed here: this packet binds only `0x53b1120`, so the pair is not double-claimed. The pair window's rule is described here only to mark the boundary.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_gated_two_field_copy.py --check research/work-items/foundation-gated-two-field-copy-94/evidence.json
python3 -m unittest tests.test_foundation_gated_two_field_copy -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x53b1120 --stop-address=0x53b1150 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its six padding bytes. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2b5864` (this window) and `0x2b5878` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2b5864` describes `[0x53b1120, 0x53b114a)`, 42 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Six `int3` bytes follow: the next FDE starts exactly at `0x53b1150` (record at `.eh_frame+0x2b5878`, range to `0x53b116e`). The unwind-index stride is therefore 48 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a `0x409320`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: gated two-field copy, two branches, no calls

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | f3 0f 1e fa | endbr64 |
| 0x04 | 48 8b 87 d8 02 00 00 | mov 0x2d8(%rdi),%rax |
| 0x0b | 48 85 c0 | test %rax,%rax |
| 0x0e | 74 19 | je 0x53b1149 |
| 0x10 | 80 bf b8 00 00 00 00 | cmpb $0x0,0xb8(%rdi) |
| 0x17 | 74 10 | je 0x53b1149 |
| 0x19 | 48 8b 50 20 | mov 0x20(%rax),%rdx |
| 0x1d | 48 8b 40 60 | mov 0x60(%rax),%rax |
| 0x21 | 48 89 56 10 | mov %rdx,0x10(%rsi) |
| 0x25 | 48 89 46 18 | mov %rax,0x18(%rsi) |
| 0x29 | c3 | ret |

Rule, derived step by step: the first load places the pointer `p = [rdi+0x2d8]` in rax; the test sets flags from it; the first branch jumps to `ret` when `p` is null, so the null path stores nothing. Otherwise the compare tests the gate byte `[rdi+0xb8]` against zero; the second branch jumps to the same `ret` when it is clear, so the gate-clear path also stores nothing. On the remaining path, `[p+0x20]` is loaded into rdx and `[p+0x60]` into rax, then rdx is stored at `[rsi+0x10]` and rax at `[rsi+0x18]`. Both branch targets are exact: the `je` at offset `0x0e` is 2 bytes with displacement `0x19`, and the `je` at offset `0x17` is 2 bytes with displacement `0x10`; both land on the `ret` at offset `0x29` (`0x53b1149`). No call opcode appears inside the window.

No boolean return is claimed: on the copy path rax ends holding `[p+0x60]`, on the null path rax is 0, and on the gate-clear path rax still holds `p`. The observable effect is the two stores, or their absence.

### Incoming calls: zero direct sites

A byte-pattern scan over the full `.text` section (70,370,352 bytes) for `e8` sites whose rel32 lands on the window start finds zero sites. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. The window is therefore bound without any caller provenance, and no caller purpose is claimed.

### Data edge: one RELATIVE slot, reported as a list

One `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries):

`0x57648b0`.

No meaning is claimed for the table it belongs to, and the single slot does not identify the window's provenance.

## Inferences

- The "gated two-field copy" label is an inference from the observed rule: a null check plus a gate byte enable copying two qwords from a pointed-to structure. It is kept separate from the rule itself.
- The pointer field, the gate byte, and the two copied fields are plausibly fields of some structure, but their owning type is unknown and not claimed.
- The single relocation slot suggests the window is referenced from data rather than called directly, but that is an inference from the relocation pattern, not a proven call graph.

## Unknowns

- What the gate byte, the pointer field, and the two copied fields mean, and what reads the copied fields.
- Whether the window is reached via the single relocation slot, via an indirect call, or via a tail jump (all out of scope for the direct-e8 scan).
- The source-level function, type, and component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- The adjacent same-flag window `0x53b1150` is not claimed by this packet.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
