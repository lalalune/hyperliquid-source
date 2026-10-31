# foundation-field-inequality-94: what does the field-inequality gate compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 22-byte FDE window, its 16-byte stub-FDE stride neighbor plus 10 int3 padding bytes, the zero naming relocations, the three direct call sites, and the exact field-inequality rule.
- Excluded: the fields' meaning, the base pointer's provenance, any caller behavior beyond call site and argument setup, the stub FDE's purpose, the next FDE, other inequality helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two field loads from the same base, one 64-bit comparison, one setne byte, no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5035a70`, no open pull request title mentions it or field-inequality, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, dual-zero, conditional-reduction, multiply-subtract, field-walk-shift, or pair-load packets.

This window is bound **alone**. No census of similar windows is claimed.

## No scout correction needed

Every scouted element verified exactly: the FDE range, the 22-byte body, all five instructions, the three direct call sites, and no naming relocation. The stride caveat below is a precision note about attribution, not a correction to any scouted byte: the scout note said the 26-byte stride to the next FDE contains a post-ret stub plus int3s, and the retained bytes confirm that — with the refinement that the stub is its own FDE record (see below), not part of this window's FDE.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_field_inequality.py --check research/work-items/foundation-field-inequality-94/evidence.json
python3 -m unittest tests.test_foundation_field_inequality -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5035a70 --stop-address=0x5035aa0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its stride neighbor and padding. The `caller.objdump.txt` file retains linear disassembly from each caller FDE start through its call site. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x291bf4`, the stub FDE at `0x6293a0`, and the next FDE at `0x62936c`. The checker locks the window FDE record and its CIE raw bytes, reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value), and locks the stub and next FDE records' raw bytes with their GNU-decoded ranges.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and stride

- `.eh_frame+0x291bf4` describes `[0x5035a70, 0x5035a86)`, 22 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5035a85` is inside the FDE).
- The window FDE record carries **no augmentation data and therefore no LSDA**: its 16-byte record is CIE pointer, 4-byte PC-relative initial_location, 4-byte range, and CFI nops only. So the bytes after the window's `ret` cannot be this FDE's landing pad.
- The stride to the next FDE at `0x5035aa0` is 48 bytes, in two attributed parts, and the checker locks both separately; stride is not the FDE extent:
  1. A **separate FDE record** at `.eh_frame+0x6293a0` describing `[0x5035a86, 0x5035a96)`, 16 bytes, whose body is a landing-pad stub: `mov %rbp,%rdi; call 0x5334cc0; mov %rbx,%rdi; call Unwind_Resume@plt`. It carries its own LSDA augmentation data and its own frame (CFA offset 32, rbx at CFA-32, rbp at CFA-24, r12 at CFA-16). It is **not analyzed** here and no shared routine with this window is claimed; its frame shape matches the next FDE's frame shape, which is consistent with a landing pad for that frame, but that attribution is explicitly not claimed.
  2. **10 int3 bytes** (`cc` × 10) from `0x5035a96` to `0x5035aa0`, where the next FDE starts (range 0xbd bytes to `0x5035b5d`).

### Instruction walk

All offsets are relative to the FDE start `0x5035a70`:

1. `endbr64` (bytes 0–3).
2. `mov 0x1458(%rdi),%rax` (bytes 4–10): `a = *(rdi + 0x1458)`.
3. `cmp %rax,0x1478(%rdi)` (bytes 11–17): compare `*(rdi + 0x1478)` against `a`.
4. `setne %al` (bytes 18–20): low byte of `rax` = 1 iff the two 64-bit fields differ, else 0.
5. `ret` (byte 21).

### Rule

```
low byte of rax = 1 iff *(rdi + 0x1458) != *(rdi + 0x1478) as 64-bit values, else 0
```

No store, no call, no branch. The comparison is 64-bit (`mov`/`cmp` with REX.W), so a difference in any bit — including only the high bit — makes the result 1; there is no low-32-bit subtlety.

### Low-byte caveat

No instruction zeroes `eax` before the `setne`, so only the **low byte** of the return value is the gate bit; the upper bytes are caller-state dependent — the same low-byte-only precedent as packets #27 and #32. This is unlike packet #35, where a `mov $0x9,%eax` zeroes the upper bits.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan). The absence of a naming relocation does not identify the window's provenance.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly three direct `e8` call sites targeting this window, each confirmed as an instruction start by linear disassembly from its caller FDE start, explicitly not a complete xref census:

- `0x4fbcd61` (caller FDE `0x4fbcca0..0x4fbdbb0`), bytes `e8 0a 8d 07 00`.
- `0x5035b3b` (caller FDE `0x5035aa0..0x5035b5d` — the next FDE after this window), bytes `e8 30 ff ff ff`.
- `0x50562cb` (caller FDE `0x5055f00..0x50566ed`), bytes `e8 a0 f7 fd ff`.

Argument setup observed at all three sites: each call is immediately preceded by `mov %rbx,%rdi`, so `rdi` is set from `rbx` before the call. Caller purpose beyond call site and argument setup is not claimed.

## Inferences (kept separate from observations)

- The label "field-inequality gate" is an inference from the two-field compare shape, not an observed name.
- The two compared fields' types and meaning are unknown.
- The base pointer's provenance (what `rdi` points to) is unknown.
- Nothing about callers, component ownership, or source-level identity is claimed.
- The stub FDE's purpose and any relationship to the next FDE are unknown and unclaimed.

## Unknowns

- Whether any caller reads only the low byte or the full `rax`.
- Whether the compared fields belong to one struct or two related objects.
- The meaning of the `0x1458` and `0x1478` offsets.
- What the stub FDE at `0x5035a86` belongs to.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
