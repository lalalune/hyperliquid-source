# foundation-three-field-span-sum-94: what does the three-field span sum window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 20-byte FDE window with twelve padding bytes, the three-field span sum rule with its exact fields and wrapping arithmetic, the exact incoming-call scan result (zero direct sites), and the single naming relocation slot.
- Excluded: what the three fields mean, what the returned span-plus value is used for, any wider span-sum family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a span (one field minus another) plus a third field, returned in rax, with no field written and no call inside. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5276b80`, no open pull request title mentions it or three-field-span-sum, and its bytes overlap nothing in packets #1–#110.

## Scout note

The round-17 scout note listed this window (ranked #2, thin but perfectly clean) with FDE `[0x5276b80, 0x5276b94)`, 20 bytes, 12 padding bytes, zero direct callers, one naming relocation slot (`0x575fc28`), and nearest claimed window dual-zero test `0x5229860` (packet #36) `0x4d320` away. Every element verified exactly; no correction was needed.

## Thinness, stated plainly

This is a thin window: five instructions, one expression, one return. What it is not is ambiguous — the three field offsets, the subtract-then-add order, and the wrapping arithmetic are all fixed by the bytes with no room for an alternate reading. The packet claims exactly that one expression and nothing more.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_three_field_span_sum.py --check research/work-items/foundation-three-field-span-sum-94/evidence.json
python3 -m unittest tests.test_foundation_three_field_span_sum -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5276b80 --stop-address=0x5276ba0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its twelve padding bytes. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2a8a64` (this window) and `0x2a8a78` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2a8a64` describes `[0x5276b80, 0x5276b94)`, 20 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Twelve `int3` bytes follow: the next FDE starts exactly at `0x5276ba0` (record at `.eh_frame+0x2a8a78`, range to `0x5276bbc`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x5276b80`.

- Offset `0x00`: `endbr64` — entry marker.
- Offset `0x04`: `mov 0x70(%rdi),%rax` — first field load.
- Offset `0x08`: `sub 0x60(%rdi),%rax` — span subtract: rax = [rdi+0x70] − [rdi+0x60].
- Offset `0x0c`: `add 0x80(%rdi),%rax` — third field add: rax += [rdi+0x80].
- Offset `0x13`: `ret` — single return on every path.

### Decoded rule

Let `a = [rdi+0x70]`, `b = [rdi+0x60]`, `c = [rdi+0x80]`, all qwords. Then `rax = a − b + c`, all operations wrapping modulo 2^64. No field is written on any path. The order matters and is fixed by the bytes: the subtract happens before the add, so the intermediate span term can be negative (wrapping) before the third field is added.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on the window start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. No caller file is included for that reason.

### Data edge

Exactly one `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend — slot `0x575fc28` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries), reported as a slot list only, no meaning claimed.

### Packet #87 distinction, stated head-on

Packet #87 (`0x53a3750`, three-field sum) adds three fields (`[rdi+0x1b8]+[rdi+0x28]+[rdi+0x1d8]`, all adds). This window subtracts one field and adds a third (`[rdi+0x70]−[rdi+0x60]+[rdi+0x80]`) — different fields, different arithmetic. Byte-compare over the 20-byte overlap: only 6/20 bytes identical — not a twin. No shared primitive is claimed.

### Nearest claimed window

The nearest claimed window is dual-zero test `0x5229860` (packet #36), `0x4d320` away. It tests two fields for zero and returns a boolean; this window computes a span plus a third field and returns the sum. Different rule, different fields, no shared primitive claimed.

## Inferences

- The "three-field span sum" label is an inference from the instruction sequence: one subtract followed by one add over three struct fields. It is kept separate from the observed rule above.
- The field offsets (0x60, 0x70, 0x80) suggest three adjacent qword slots in one struct, but no struct layout, field meaning, or consumer is claimed.

## Unknowns

- What the three fields represent, what the returned value is used for, and why this window has zero direct callers (inlined helper, indirect-only target, or dead code) are all unknown and not claimed.
- Whether the naming relocation slot identifies any provenance is unknown; the slot is reported as a list only.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
