# foundation-cursor-retreat-or-wrap-94: what does the cursor retreat-or-wrap window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 41-byte FDE window with seven padding bytes, the cursor retreat-or-wrap rule with its exact fields and wrapping arithmetic, the exact incoming-call scan result (zero direct sites), and the single naming relocation slot.
- Excluded: what the bounds mean, what the cursor walks over, any wider cursor-component claim, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a cursor that steps back by one 8-byte element, or wraps to the far bound when it already equals the first bound, with no call inside. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x52c6ea0`, no open pull request title mentions it or cursor-retreat-or-wrap, and its bytes overlap nothing in packets #1–#119.

## Scout note

The round-22 scout note listed this window (ranked #3, the last ranked item this round) with FDE `[0x52c6ea0, 0x52c6ec9)`, 41 bytes, 7 padding bytes, zero direct callers, one naming relocation slot (`0x57615c8`), and the trio-component caveat below. Every element verified exactly; no correction was needed.

## Trio-component caveat, stated head-on

This window is one of exactly three self-contained members of one small component sharing the `[rdi+0x10]` bounds / `[rdi+0x20]` cursor / 8-byte-step idiom:

- `0x52c6e50` (20 bytes): length = `[rdx+8] − [rdx] + 0x28`, zero callers, slot `0x5761550`.
- `0x52c6e80` (27 bytes): if cursor != `[rdx+8]` then cursor += 8, zero callers, slot `0x57615c0`.
- `0x52c6ea0` (this packet, 41 bytes): retreat-or-wrap, zero callers, slot `0x57615c8`.

The three slots (`0x5761550`, `0x57615c0`, `0x57615c8`) are consistent with a shared relocation table for the component; that consistency is reported, not claimed as proof of a component. Only THIS window's rule is claimed here. The siblings are NOT separately claimed, and they must NOT be mined as follow-up packets from this one — ranking all three would be cluster-mining, following the round-17 `0x4ea41e0` precedent. Nothing about the trio as a component is claimed. Byte-compare vs the siblings shows a similar skeleton with different rules, not twins: 12/20 vs `0x52c6e50`, 14/27 vs `0x52c6e80`.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_cursor_retreat_or_wrap.py --check research/work-items/foundation-cursor-retreat-or-wrap-94/evidence.json
python3 -m unittest tests.test_foundation_cursor_retreat_or_wrap -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x52c6ea0 --stop-address=0x52c6ed0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its seven padding bytes. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2abcac` (this window) and `0x2abcc0` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2abcac` describes `[0x52c6ea0, 0x52c6ec9)`, 41 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Seven `int3` bytes follow: the next FDE starts exactly at `0x52c6ed0` (record at `.eh_frame+0x2abcc0`, range to `0x52c6ed5`). The unwind-index stride is therefore 48 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- Five `int3` bytes precede the window (the previous FDE `0x52c6e80` ends at `0x52c6e9b`); that gap is padding, not code, and the checker locks it as a boundary.
- The window opens with `endbr64`, the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x52c6ea0`.

- Offset `0x00`: `endbr64` — entry marker.
- Offset `0x04`: `mov 0x10(%rdi),%rdx` — bounds pointer load: rdx = [rdi+0x10].
- Offset `0x08`: `mov 0x20(%rdi),%rax` — cursor load: rax = [rdi+0x20].
- Offset `0x0c`: `cmp (%rdx),%rax` — compare cursor against the first bound.
- Offset `0x0f`: `je 0x52c6ec0` — equal: take the wrap path.
- Offset `0x11`: `sub $0x8,%rax` — step back one 8-byte element.
- Offset `0x15`: `mov %rax,0x20(%rdi)` — store the stepped cursor.
- Offset `0x19`: `ret` — step-back return.
- Offset `0x1a`: `nopw 0x0(%rax,%rax,1)` — six-byte alignment padding between the two paths, inside the FDE extent.
- Offset `0x20`: `mov 0x8(%rdx),%rax` — second bound load (wrap path).
- Offset `0x24`: `mov %rax,0x20(%rdi)` — store the wrapped cursor.
- Offset `0x28`: `ret` — wrap return.

### Decoded rule

Let `cursor = [rdi+0x20]`, `first = [[rdi+0x10]]`, `second = [[rdi+0x10]+8]`, all qwords. Then: if `cursor == first`, `[rdi+0x20] = second`; else `[rdi+0x20] = cursor − 8`, wrapping modulo 2^64. No other field is written on either path. rax holds the stored value incidentally; no return value of note is claimed. The wrap path never compares the cursor against the second bound — only the first bound is compared.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on the window start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. No caller file is included for that reason.

### Data edge

Exactly one `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend — slot `0x57615c8` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries), reported as a slot list only, no meaning claimed.

### Nearest claimed window

The nearest claimed window by full claimed-body byte-compare is `0x51a5d60` at only 14/41 bytes identical — not a twin. The shared bytes are common opcodes, not a shared body. No shared primitive is claimed.

## Inferences

- The "cursor retreat-or-wrap" label is an inference from the instruction sequence: a conditional step back by 8 or a replacement with the second bound. It is kept separate from the observed rule above.
- The field offsets (0x10, 0x20) and the two qwords behind `[rdi+0x10]` suggest a bounds pair plus a cursor in one struct, but no struct layout, field meaning, or consumer is claimed.

## Unknowns

- What the bounds represent, what the cursor walks over, and why this window has zero direct callers (inlined helper, indirect-only target, or dead code) are all unknown and not claimed.
- Whether the naming relocation slot identifies any provenance is unknown; the slot is reported as a list only.
- Whether the three trio members share a source-level component is unknown; only this member's rule is claimed.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
