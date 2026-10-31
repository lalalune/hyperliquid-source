# foundation-clamp-with-default-store-94: what does the clamp-with-default store window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 32-byte FDE window with zero padding bytes, the clamp-with-default store rule with its exact constants and field offset, the exact incoming-call scan result (three direct sites, all in three caller FDEs), and the zero-naming-relocation scan result.
- Excluded: what the node fields mean, what the stored word represents, any wider clamp family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a signed input clamped to a range with a default value for non-positive inputs, stored as a word at a fixed struct offset. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5488d00`, no open pull request title mentions it or clamp-with-default-store, and its bytes overlap nothing in packets #1–#102.

## Scout note

The round-16 scout note listed this window (ranked #1, the cleanest rule this round) with FDE `[0x5488d00, 0x5488d20)`, 32 bytes, 0 padding bytes, three direct callers (all boundary-confirmed), no naming relocation, and nearest claimed window bit-writer drain `0x5494050` (packet #84) `0xb350` away. Every element verified exactly; no scout correction was needed.

## Caller caveat

Three direct `e8` call sites reach this window, each confirmed as an instruction start by linear disassembly from its caller FDE start (retained in `caller.objdump.txt`): `0x5488d44` (FDE `0x5488d20..0x5488d4e`), `0x5488d82` (FDE `0x5488d50..0x5488d93`), and `0x5488e20` (FDE `0x5488dd0..0x5488f24`). The byte-pattern scan is explicitly not a complete xref census, and no caller purpose is claimed. The three callers are adjacent to the window itself (the first caller FDE starts exactly where this window ends), which is consistent with small related helpers but is not claimed as a shared primitive.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_clamp_with_default_store.py --check research/work-items/foundation-clamp-with-default-store-94/evidence.json
python3 -m unittest tests.test_foundation_clamp_with_default_store -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5488d00 --stop-address=0x5488d20 artifacts/node/94/hl-node
objdump -d --start-address=0x5488d20 --stop-address=0x5488d4e artifacts/node/94/hl-node
objdump -d --start-address=0x5488d50 --stop-address=0x5488d93 artifacts/node/94/hl-node
objdump -d --start-address=0x5488dd0 --stop-address=0x5488f24 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window (no padding follows it: the next FDE starts exactly at the window end). The `caller.objdump.txt` file retains complete disassembly of the three caller FDEs. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2be8fc` (this window), `0x2be910` (the next FDE, which is also the first caller FDE), `0x2be92c` (the second caller FDE), and `0x2be970` (the third caller FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2be8fc` describes `[0x5488d00, 0x5488d20)`, 32 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Zero padding bytes follow: the next FDE starts exactly at `0x5488d20` (record at `.eh_frame+0x2be910`, range to `0x5488d4e`). The unwind-index stride is therefore 32 bytes; the stride equals the FDE extent here, and the checker locks the body and the zero padding separately (the zero-padding claim is itself checked).
- The window opens with `endbr64`, the standard indirect-branch landing pad; that is the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x5488d00`. All comparisons are signed 32-bit.

- Offset `0x00`: `endbr64` — indirect-branch landing pad.
- Offset `0x04`: `mov $0xc,%eax` — upper clamp bound 12.
- Offset `0x09`: `mov $0x9,%edx` — default value 9.
- Offset `0x0e`: `cmp %eax,%esi` — compare the input against 12.
- Offset `0x10`: `cmovle %esi,%eax` — if `esi <= 12` (signed), `eax = esi`; otherwise `eax` stays 12.
- Offset `0x13`: `test %esi,%esi` — sign test on the input.
- Offset `0x15`: `cmovle %edx,%eax` — if `esi <= 0` (signed), `eax = 9`, overriding the previous step.
- Offset `0x18`: `mov %ax,0x40024(%rdi)` — store the low word of the result at struct offset `+0x40024`.
- Offset `0x1f`: `ret` — single return; no branch leaves the window and no call sits inside it.

### Decoded rule

Let `v = esi` as a signed 32-bit value. The stored word is:

- `v <= 0` → 9 (the default);
- `0 < v <= 12` → `v`;
- `v > 12` → 12 (the clamp).

No other field is written. The stored value is the low 16 bits of the clamped result (`mov %ax`); for inputs in the claimed range the result fits in a word by construction (9, 1..12). No return value is claimed: on exit `eax` holds the clamped value, but the packet claims only the store.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly three direct `e8` sites whose rel32 lands on the window start: `0x5488d44`, `0x5488d82`, and `0x5488e20`. Each was confirmed as an instruction start by linear disassembly from its caller FDE start, and all three caller FDEs are retained in `caller.objdump.txt` with their frame records in `frames.txt`. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation is reported as a scan result only; it does not identify the window's provenance.

### Nearest claimed window

Bit-writer drain `0x5494050` (packet #84) sits `0xb350` above this window. The two windows share no field offset, constant, or rule shape: #84 drains a bit-writer counter with byte-pair emission, while this window clamps one signed input and stores one word. No shared primitive is claimed.

## Inferences

- The "clamp-with-default store" label is an inference from the two-cmov clamp shape; the window itself names nothing.
- The default value 9 for non-positive inputs looks like a fallback for an unset or invalid index, but what the index selects is not claimed.
- The large fixed struct offset `+0x40024` suggests a field in a large struct or a table slot, but the struct layout is not claimed.

## Unknowns

- What the input `esi` represents and what the stored word at `+0x40024` controls.
- Whether any caller reaches this window through an indirect call or tail jump (outside the byte-pattern scan).
- What the three callers do with the stored word after the window returns.

## Limits

- No source-level function, type, or field meaning is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
