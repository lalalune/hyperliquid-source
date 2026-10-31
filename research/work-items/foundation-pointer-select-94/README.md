# foundation-pointer-select-94: what does the pointer-select window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its call edges; its source-level name and types remain inferences.
- Included: the 30-byte FDE window, its two int3 padding bytes, four incoming direct calls with their caller FDEs, and the exact pointer-select rule.
- Excluded: the base pointer's and field's runtime meaning, the callers' behavior beyond their call sites and argument setups, the next FDE, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one conditional move selecting between two base offsets, one field load, no calls. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x552cac0`, no open pull request title mentions it or pointer-select, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, half-swap, xor-mixer, mask-builder, tail-gate, or double-gate packets.

This window is bound **alone**. No census of similar windows is claimed.

## Distinction from packet #27 (range-membership test, 0x5520e00)

The nearest claimed window, `0x5520e00`, sits `0xace0` away — within `0x2000` — but it is a different window, not a sibling of this one. Packet #27 tests a value against two `.bss` globals with `setae`/`setb` and returns only a low-byte membership bit. This window selects between two base offsets with `cmove` and loads an 8-byte field, with no globals, no `setcc`, and a fully determined `rax` return. The two windows share neither instructions, operands, nor FDE; each is verified from its own bytes.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_pointer_select.py --check research/work-items/foundation-pointer-select-94/evidence.json
python3 -m unittest tests.test_foundation_pointer_select -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x552cac0 --stop-address=0x552cae0 artifacts/node/94/hl-node
objdump -d --start-address=0x54cbd50 --stop-address=0x54cbfc7 artifacts/node/94/hl-node
objdump -d --start-address=0x54cbff0 --stop-address=0x54cc11f artifacts/node/94/hl-node
objdump -d --start-address=0x551e750 --stop-address=0x551e8ec artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains disassembly of each caller FDE from its start through its call site (`0x54cbd50`..`0x54cbfc7`, `0x54cbff0`..`0x54cc11f`, `0x551e750`..`0x551e8ec`); the full caller FDEs are `[0x54cbd50, 0x54cbfed)`, `[0x54cbff0, 0x54cc126)`, and `[0x551e750, 0x551e971)`, and only the retained regions are claimed here. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2caeb0`, the next FDE at `0x2caec4`, and the caller FDEs at `0x2c04b8`, `0x2c0528`, and `0x2c89c4`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value). It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x2caeb0` describes `[0x552cac0, 0x552cade)`, 30 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x552cadd` is inside the FDE).
- The unwind index stride to the next entry is 32 bytes, ending at `0x552cae0`, only because two `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "32-byte FDE-bounded" would overstate the frame by those two padding bytes, and the checker locks the 30-byte body and the padding separately. The next FDE starts exactly at `0x552cae0`.
- No relocation of any type in `.rela.dyn` maps a slot to `0x552cac0`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly four direct `e8` calls to the window, each subsequently visible as an instruction start in GNU disassembly from its caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: one conditional move, one field load, no calls

Decoded from the FDE start, the window takes its inputs in `rdi` (base pointer) and `esi` (selector):

| VA | Instruction | Role |
| --- | --- | --- |
| `0x552cac0` | `endbr64` | Landing pad |
| `0x552cac4` | `lea 0xe518(%rdi),%rax` | Alternative base: original rdi + 0xe518 |
| `0x552cacb` | `add $0xec10,%rdi` | Default base: rdi + 0xec10 |
| `0x552cad2` | `cmp $0x1,%esi` | Full 32-bit selector test for 1 |
| `0x552cad5` | `cmove %rax,%rdi` | Select the alternative base iff esi == 1 |
| `0x552cad9` | `mov 0x78(%rdi),%rax` | Load the 8-byte field at base + 0x78 |
| `0x552cadd` | `ret` | |

The rule, in full:

- If `esi == 1` (the full 32-bit value, compared by `cmp $0x1,%esi`), the base is `rdi + 0xe518` and the returned value is `*(rdi + 0xe518 + 0x78)` = `*(rdi + 0xe590)`.
- Otherwise the base is `rdi + 0xec10` and the returned value is `*(rdi + 0xec10 + 0x78)` = `*(rdi + 0xec88)`.
- The `lea` computes from the original `rdi` before the `add` overwrites it, so the two candidate bases are independent; the `cmove` picks one. The return value is fully determined: `rax` is loaded by the final `mov`, not set by a `setcc` byte, so unlike packet #27 there is no low-byte-only caveat here.
- The selector test is 32-bit: `cmp $0x1,%esi` compares the low 32 bits of `rsi`, so selection depends on those bits equaling `1`; the upper 32 bits of `rsi` are ignored by the compare (for example, `rsi = 0x100000001` selects the alternative base, because its low 32 bits are `1`).

### Incoming calls

| Call site | Caller FDE | Confirmed as instruction start | Argument setup |
| --- | --- | --- | --- |
| `0x54cbfc2` | `[0x54cbd50, 0x54cbfed)` | Yes, linear disassembly from FDE start | `mov 0x10(%rsp),%rdi; mov $0x2,%esi` — selects the default base |
| `0x54cc11a` | `[0x54cbff0, 0x54cc126)` | Yes, linear disassembly from FDE start | `mov 0x8(%rsp),%rdi; mov $0x2,%esi` — selects the default base |
| `0x551e8d0` | `[0x551e750, 0x551e971)` | Yes, linear disassembly from FDE start | `mov $0x1,%esi; mov %r12,%rdi` — selects the alternative base |
| `0x551e8e7` | `[0x551e750, 0x551e971)` | Yes, linear disassembly from FDE start | `mov $0x2,%esi; mov %r12,%rdi` — selects the default base |

Each call site's 5-byte `e8` + rel32 sequence is locked by the checker, and its target resolves exactly to `0x552cac0`. Caller purpose beyond the call site and argument setup is not claimed.

### No scout correction needed

Every scouted element verified exactly: FDE range, padding count, all seven instructions, both base displacements, the field offset, all four callers, and the absence of a naming relocation.

## Inferences

- The "pointer-select plus field load" label is an inference from the conditional-move shape. It is kept separate from the observed select-and-load rule.
- The two candidate bases differ by `0x6f8` (`0xec10 - 0xe518`); no meaning is attached to that difference or to either base.

## Unknowns

- The base pointer's runtime meaning, and what kind of quantity the field at +0x78 is.
- The window's source-level name, type, and component owner.
- The callers' purpose beyond their call sites and argument setups.
- Whether any caller relies on the returned value beyond the retained call sites.

## Limits

- No stdlib type, source-level function, base/field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
