# foundation-global-clamp-94: what does the global clamp plus tail call do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 86-byte FDE window, its 10 int3 padding bytes, the zero naming relocations, the two direct call sites, the global read/write pair, and the exact clamp-plus-tail-call rule.
- Excluded: the globals' meaning, the tail callee's purpose, any caller behavior beyond call site, the next FDE, other clamp or tail-call helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one global load, one sign test, one shift, two conditional moves, one global store, and one tail jump. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x55539e0`, no open pull request title mentions it or global-clamp, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, dual-zero, conditional-reduction, multiply-subtract, field-walk-shift, pair-load, field-inequality, bsr-lookup, or multiply-mix-div61 packets.

This window is bound **alone**. No census of similar windows is claimed.

## No scout correction needed

Every scouted element verified exactly: the FDE range, the 86-byte body, all instructions, both direct call sites, and no naming relocation. One reading note, not a correction: the negative path is not a separate branch out of the window — the `js` at offset 14 jumps forward to the `xor %edi,%edi; xor %esi,%esi; jmp` block at offsets 80–85, which jumps back to the shared store at offset 53. The store instruction itself is single: both paths converge on it, and the checker locks that convergence (the negative store-jump displacement and its target).

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_global_clamp.py --check research/work-items/foundation-global-clamp-94/evidence.json
python3 -m unittest tests.test_foundation_global_clamp -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x55539e0 --stop-address=0x5553a40 artifacts/node/94/hl-node
objdump -d --start-address=0x54b9b60 --stop-address=0x54b9d00 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains linear disassembly from the caller FDE start through both call sites. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2cef44`, the next FDE at `0x2cef58`, the caller FDE at `0x2bfa24`, and the tail-target FDE at `0x2cba08`. The checker locks the window FDE record and its CIE raw bytes, reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value), and locks the next, caller, and tail FDE records' raw bytes with their GNU-decoded ranges.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and stride

- `.eh_frame+0x2cef44` describes `[0x55539e0, 0x5553a36)`, 86 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `jmp` at `0x5553a34` is inside the FDE).
- The stride to the next FDE at `0x5553a40` is 10 int3 bytes (`cc` × 10) from `0x5553a36` to `0x5553a40`, where the next FDE starts (range 0x10 bytes to `0x5553a50`). The checker locks body and padding separately; stride is not the FDE extent.

### Instruction walk

In order, with body offsets relative to `0x55539e0`:

1. `endbr64` (offsets 0–3).
2. `mov 0x2347f5(%rip),%rsi` (4–10): g = i64 global at `0x57881e0` (section `.data`).
3. `test %rsi,%rsi` (11–13), then `js 0x5553a30` (14–15): the negative path jumps forward to offsets 80–85.
4. `mov $0x1,%eax`, `mov $0x1,%edx`, `mov $0x400000,%ecx` (16–30): the three constants of the clamp, loaded before any conditional move.
5. `cmovle %rax,%rsi` (31–34): after the `test`, and with the negative case already diverted by `js`, this moves exactly when g == 0, so v = 1 when g == 0 else g.
6. `mov %rsi,%rdi` (35–37), `shr $0x6,%rdi` (38–41): v >>= 6.
7. `cmove %rdx,%rdi` (42–45): v = 1 when the shifted value is 0.
8. `cmp %rcx,%rdi` (46–48), `cmova %rcx,%rdi` (49–52): v = 0x400000 when v exceeds the cap.
9. `mov %rdi,0x45c27c(%rip)` (53–59): store v to global `0x59afc98` (section `.bss`). This is the single shared store: the negative path reaches it via its own jump (see below).
10. `lea 0x45c27d(%rip),%rdi` (60–66): rdi = `0x59afca0`, exactly the store target plus eight.
11. `jmp 0x552fa70` (67–71): tail call. The target has its own FDE `[0x552fa70, 0x552fa82)` and starts with a real function prologue; it is named only and never decoded here, following the packet #31 tail-gate precedent.
12. `nopl 0x0(%rax,%rax,1)` (72–79): 8-byte alignment padding inside the body, before the negative block.
13. Negative block (80–85): `xor %edi,%edi; xor %esi,%esi; jmp 0x5553a15` — zeroes the store value and jumps back to the shared store at offset 53. The checker locks both the block and its jump displacement.

### The clamp rule

Stored value = 0 when g < 0; otherwise clamp(max(max(g,1)>>6,1),0x400000). Worked edges from the retained bytes: g = -1 → 0; g = 0 → 1 (cmovle, then shift 0, then cmove); g = 63 → 1 (shift 0, then cmove); g = 64 → 1; g = 128 → 2; g = 0x10000000 → 0x400000 exactly; g = 0x10000040 → 0x400000 (shifted 0x400001, capped); g = 2^63 - 1 → 0x400000. The window sets no return value of its own: control leaves by tail jump, and the tail callee's return (if any) is not this window's claim.

### Callers

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly two direct `e8` call sites, each confirmed as an instruction start by linear disassembly from the caller FDE start, explicitly not a complete xref census:

- `0x54b9c6b` (bytes `e8 70 9d 09 00`), caller FDE `0x54b9b60..0x54b9f1d`.
- `0x54b9cc9` (bytes `e8 12 9d 09 00`), same caller FDE.

Caller purpose beyond call site is not claimed.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan).

### Tail-target distance note

The tail target `0x552fa70` sits `0x2db0` from packet #33's window `0x552cac0` — outside the ±0x2000 exclusion used by the scouts, and it is a call target here, not a claimed window. No shared routine with packet #33 is claimed.

## Inferences

- The label "global clamp plus tail call" is an inference from the observed load/shift/conditional-move/store/tail-jump shape; the source-level name, the globals' meaning, and the tail callee's purpose are unknown.
- The constants 1, 6, and 0x400000 are treated as clamp parameters only; no unit or domain meaning is claimed for them.

## Unknowns

- What the source global, the store global, and the tail callee represent.
- Whether other windows read or write either global (no census claimed).
- Why the tail argument is the store target plus eight.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- The tail callee is named, not decoded; nothing about its behavior is claimed.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
