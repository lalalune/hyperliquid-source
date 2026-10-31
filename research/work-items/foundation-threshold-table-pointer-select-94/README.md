# foundation-threshold-table-pointer-select-94: what does the threshold table-pointer select window do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 25-byte FDE window with seven padding bytes, the threshold table-pointer select rule with its exact bound and lea target, the exact incoming-call scan result (zero direct sites), and the single naming relocation slot.
- Excluded: what the table at the selected address holds, what the returned pointer is used for, any wider select family, and any claim about which source-level function this might be; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: an unsigned index compared against 0x3f selects either a rip-relative table address or zero, with no field written and no call inside. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x54d76e0`, no open pull request title mentions it or threshold-table-pointer-select, and its bytes overlap nothing in packets #1–#109.

## Scout note

The round-17 scout note listed this window (ranked #1, the cleanest rule of the round) with FDE `[0x54d76e0, 0x54d76f9)`, 25 bytes, 7 padding bytes, zero direct callers, one naming relocation slot (`0x576a6a8`), and nearest claimed window byte-indexed table offset `0x54ccfb0` (packet #106) `0xa730` away. Every element verified exactly except one, stated head-on below.

## Scout correction

The scout note reported the lea target as `0x7da46c0`. That address is wrong. The retained bytes are `lea 0x292fcc(%rip),%rax` at `0x54d76ed`; the next instruction address is `0x54d76f4`, and `0x54d76f4 + 0x292fcc = 0x576a6c0` — the address GNU objdump itself prints for the instruction. The checker locks the displacement and the computed target `0x576a6c0`; the scout's `0x7da46c0` is not used anywhere in this packet. Nothing else in the scout note needed correction.

## Thinness, stated plainly

This is a thin window: six instructions, one comparison, one select, one return. What it is not is ambiguous — the bound, the select condition (unsigned above, via `cmova`), and the returned address are all fixed by the bytes with no room for an alternate reading. The packet claims exactly that one select and nothing more.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_threshold_table_pointer_select.py --check research/work-items/foundation-threshold-table-pointer-select-94/evidence.json
python3 -m unittest tests.test_foundation_threshold_table_pointer_select -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x54d76e0 --stop-address=0x54d7700 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its seven padding bytes. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2c175c` (this window) and `0x2c1770` (the next FDE), plus the shared CIE at offset `0`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2c175c` describes `[0x54d76e0, 0x54d76f9)`, 25 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Seven `int3` bytes follow: the next FDE starts exactly at `0x54d7700` (record at `.eh_frame+0x2c1770`, range to `0x54d7733`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the padding separately.
- The window opens with `endbr64`, the retained entry shape, not an assumption about how the window is reached.
- GNU objdump prints this window under a nearest-symbol label with a large offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Instruction sequence

Offsets are relative to the FDE start `0x54d76e0`.

- Offset `0x00`: `endbr64` — entry marker.
- Offset `0x04`: `cmp $0x3f,%rcx` — unsigned threshold compare on the index argument.
- Offset `0x08`: `mov $0x0,%edx` — zero candidate for the above-threshold path.
- Offset `0x0d`: `lea 0x292fcc(%rip),%rax` — table address; the next instruction is at `0x54d76f4`, so the target is `0x576a6c0`.
- Offset `0x14`: `cmova %rdx,%rax` — if `rcx` is above `0x3f` (unsigned), `rax` becomes 0; otherwise it keeps the lea address.
- Offset `0x18`: `ret` — single return on every path.

### Decoded rule

Let `i = rcx` (unsigned). Then `rax = (i <= 0x3f) ? 0x576a6c0 : 0`. No field is written on any path. The contents at `0x576a6c0` are not claimed: the packet reports the selected address only and does not decode the table it points at.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` sites whose rel32 lands on the window start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope. No caller file is included for that reason.

### Data edge

Exactly one `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend — slot `0x576a6a8` (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries), reported as a slot list only, no meaning claimed. As a bare address observation, the slot sits `0x18` below the lea target `0x576a6c0`; no relationship between the two is claimed.

### Packet #106 distinction

Packet #106 (`0x54ccfb0`, byte-indexed table offset, `0xa730` away) computes `base + zero-extended table[edx] + 224 x selector byte` and optionally stores the selector out. This window selects a whole pointer by a threshold and stores nothing. Different rule, different operands, different result shape; byte comparison over the 25-byte overlap gives only 6/25 identical bytes. No shared primitive is claimed.

### Adjacent pair, not claimed

The next FDE `0x54d7700` and its pair mate `0x54d7740` (the 51-byte flag-gated pointer pair the round-17 scout excluded as a twin pair) share only 6/25 bytes with this window over the overlap. They add two global-flag checks and different bounds; they are not claimed here.

## Inferences

- The "threshold table-pointer select" label is an inference from the compare-select-return shape; the window itself names nothing.
- The value `0x3f` reads as a table bound (64 entries), but whether the table has 64 entries, and what it holds, is not claimed.
- The returned address `0x576a6c0` is presumably a table base, but its contents and element size are not claimed.

## Unknowns

- What the table at `0x576a6c0` holds.
- What consumes the returned pointer, and whether any caller reaches this window through an indirect call or tail jump (outside the byte-pattern scan).
- Why the threshold is exactly `0x3f`.

## Limits

- No source-level function, type, or field meaning is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the relocation slot does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
