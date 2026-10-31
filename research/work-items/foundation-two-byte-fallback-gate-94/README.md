# foundation-two-byte-fallback-gate-94: what does the two-byte fallback gate window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 23-byte FDE window with nine padding bytes, the two-byte fallback rule with its exact field offsets and branch target, the exact incoming-call scan result (zero direct sites), and the single relocation slot.
- Excluded: what the two bytes mean, what reads the result, any wider fallback-gate family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a two-byte fallback gate that returns the first flag byte when it is nonzero, and the second flag byte otherwise. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x51c09f0`, no open pull request title mentions it or two-byte-fallback-gate, and its bytes overlap nothing in packets #1–#88. The neighboring window at `0x51c0b20` shares the two field offsets but implements a different rule (an OR-gate with a third field at `0xc8`); it is a distinct window, not this one, and is not claimed here.

## Scout note

The round-14 scout note listed this window (ranked #1, the round's cleanest item) with FDE `[0x51c09f0, 0x51c0a07)`, 23 bytes, 9 padding bytes, zero direct callers, one R_X86_64_RELATIVE slot (`0x575ba28`), and nearest claimed window binary search `0x51cb570` (packet #76) `0xab80` away. Every element verified exactly, including the full body, the branch target, the zero incoming sites, and the single slot address. No numeric correction to the scout's numbers was needed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_two_byte_fallback_gate.py --check research/work-items/foundation-two-byte-fallback-gate-94/evidence.json
python3 -m unittest tests.test_foundation_two_byte_fallback_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x51c09f0 --stop-address=0x51c0a10 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its nine padding bytes. No caller file is included: the incoming scan found zero direct call sites, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x29fe38` (this window) and `0x29fe4c` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x29fe38` describes `[0x51c09f0, 0x51c0a07)`, 23 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Nine `int3` bytes follow: the next FDE starts exactly at `0x51c0a10` (record at `.eh_frame+0x29fe4c`, range to `0x51c0a21`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the usual entry marker.
- GNU objdump prints this window under a nearest-symbol label with a `0x218bf0`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: two-byte fallback gate, one branch, no calls

Complete instruction sequence, offsets relative to the FDE start:

| Offset | Bytes | Instruction |
| --- | --- | --- |
| 0x00 | f3 0f 1e fa | endbr64 |
| 0x04 | 0f b6 87 d0 00 00 00 | movzbl 0xd0(%rdi),%eax |
| 0x0b | 84 c0 | test %al,%al |
| 0x0d | 75 07 | jne 0x51c0a06 |
| 0x0f | 0f b6 87 f8 00 00 00 | movzbl 0xf8(%rdi),%eax |
| 0x16 | c3 | ret |

Rule, derived step by step: the first load places `[rdi+0xd0]` (zero-extended) in eax; the test sets flags from that byte; the branch jumps to `ret` when it is nonzero, so the first byte is returned unchanged; otherwise the second load replaces eax with `[rdi+0xf8]` (zero-extended) and `ret` returns it. The branch target is exact: the `jne` at offset `0x0d` is 2 bytes with displacement `0x07`, landing on the `ret` at offset `0x16` (`0x51c0a06`). No field is written, and no other register state is claimed.

No call opcode appears inside the window, and there is exactly one forward branch (the fallback branch above).

### Incoming calls: zero direct sites

A byte-pattern scan over the full `.text` section (70,370,352 bytes) for `e8` sites whose rel32 lands on the window start finds zero sites. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. The window is therefore bound without any caller provenance, and no caller purpose is claimed.

### Data edge: one RELATIVE slot, reported as a list

One `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries):

`0x575ba28`.

No meaning is claimed for the table it belongs to, and the single slot does not identify the window's provenance.

## Inferences

- The "two-byte fallback gate" label is an inference from the observed rule: the first of two flag bytes wins when nonzero, else the second. It is kept separate from the rule itself.
- The two bytes are plausibly flag or tag bytes of some structure, but their owning type is unknown and not claimed.
- The single relocation slot suggests the window is referenced from data rather than called directly, but that is an inference from the relocation pattern, not a proven call graph.

## Unknowns

- What the two bytes mean, and what reads the result.
- Whether the window is reached via the single relocation slot, via an indirect call, or via a tail jump (all out of scope for the direct-e8 scan).
- The source-level function, type, and component ownership of this window.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
