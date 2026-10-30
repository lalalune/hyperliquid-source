# foundation-drop-thunk-168-94: what does the 168-byte-element drop thunk do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 39-byte FDE window, its nine int3 padding bytes, one incoming direct call, the outgoing tail jump through a relocated slot, and the exact integer formulas over the input domain.
- Excluded: the per-element call target body at `0x13ef370`, the tail-call target body at `0x54c8cb0`, the caller beyond its call site and argument setup, other dealloc/drop windows, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one call, one null guard, one multiply, and a tail jump that hands a computed pointer, size, and zero flag to a shared callee. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x14079a0`, no open pull request title mentions it or drop-thunk, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, or dealloc-size packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_drop_thunk_168.py --check research/work-items/foundation-drop-thunk-168-94/evidence.json
python3 -m unittest tests.test_foundation_drop_thunk_168 -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x14079a0 --stop-address=0x14079d0 artifacts/node/94/hl-node
objdump -d --start-address=0x1407040 --stop-address=0x14073b7 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x79d0` (this window) and `0x2e8bc0` (the caller). The checker locks these raw FDE records and their shared CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x79d0` describes `[0x14079a0, 0x14079c7)`, 39 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x14079c6` is inside the FDE).
- The unwind index stride to the next entry is 48 bytes, ending at `0x14079d0`, only because nine `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "48-byte FDE-bounded" would overstate the frame by those nine padding bytes, and the checker locks the 39-byte body and the padding separately.
- No `R_X86_64_RELATIVE` relocation maps any slot to `0x14079a0`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, at `0x1407367`, subsequently visible as an instruction start in GNU disassembly from the caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x1407040, 0x14073b7)`, 887 bytes. Before the call it sets `rdi` to `0x168(%rbx)` (a `lea` at `0x1407360`); the caller's full behavior and the meaning of that address are not closed here.

### Body behavior: one call, one null guard, one multiply, one tail jump

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x14079a0` | `push %rbx` | Save callee-saved register |
| `0x14079a1` | `mov %rdi,%rbx` | Struct pointer saved |
| `0x14079a4` | `call 0x13ef370` | Per-element call (target unnamed, behavior not claimed) |
| `0x14079a9` | `mov (%rbx),%rax` | Length taken from field+0 (u64) |
| `0x14079ac` | `test %rax,%rax` | Zero-length test |
| `0x14079af` | `je 0x14079c5` | Length 0 goes to `pop; ret` |
| `0x14079b1` | `mov 0x8(%rbx),%rdi` | Base pointer from field+8 |
| `0x14079b5` | `imul $0xa8,%rax,%rsi` | Length times 168 |
| `0x14079bc` | `xor %edx,%edx` | Flag cleared to 0 |
| `0x14079be` | `pop %rbx` | Restore callee-saved register |
| `0x14079bf` | `jmp *slot 0x576e010` | Tail jump to `0x54c8cb0` |
| `0x14079c5` | `pop %rbx` | Early-return path |
| `0x14079c6` | `ret` | Early-return path |

The formulas, with all arithmetic modulo 2^64, are:

- `size = length * 0xa8`
- `pointer = field+8` (on the fall-through path)
- `flag = 0` (on the fall-through path; `edx` is cleared and never set otherwise)

At the tail jump the registers are `rdi = pointer`, `rsi = size`, `rdx = 0`. Whether the callee reads any other register is not decoded here; the register facts themselves are retained.

One correction to the scout note that seeded this packet, established from the disassembly rather than assumed: the per-element call happens **before** the null guard, not after it. The window calls `0x13ef370` unconditionally on entry, and only then tests the length. Any description of the guard as gating the call would invert the observed order.

Checked edges from the decoded formula:

| Length | Size |
| --- | --- |
| 1 | `0xa8` |
| 2 | `0x150` |
| 16 | `0xa80` |
| 255 | `0xa758` |
| 4096 | `0xa8000` |

### The tail-call target

The tail jump goes through slot `0x576e010`, confirmed by a `R_X86_64_RELATIVE` relocation to `0x54c8cb0`. That address is a shared callee (per the scout shortlist, the unwrap-guard, fixed-88 dealloc-size, and generic dealloc-size windows already tail-call it) and is **not** re-bound or identified here: this packet claims only the caller window, its behavior, and its register handoff. The callee's body, return type, and the meaning of the flag argument are unknown.

### Landing pads

The retained FDE record for this window contains no landing-pad code: the only return path inside the FDE is the `ret` at `0x14079c6`, and no `Unwind_Resume` call appears in the window. What unwinding the per-element call at `0x14079a4` performs on an exception is not decoded here.

## Inferences and unknowns

- **Inferred:** this is a drop thunk for 168-byte elements: its single per-element call, length-times-168 size, pointer-plus-size-plus-zero handoff, and tail jump to a shared callee support that label. The binary has no recovered symbol name here. Neither the source-level function name nor the full struct layout, the per-element call's contract, or the callee's contract is proven.
- The per-element call target at `0x13ef370` is left unnamed: its own library ownership, behavior, and whether it drops one element or the whole range is not closed.
- The single incoming direct call is real, but the caller's full behavior, its other arguments, and whether other callers exist through register-indirect or data paths are not closed. The byte-pattern scan is not a complete xref census.
- The tail-call target at `0x54c8cb0` is left unnamed: its own library ownership, transitive callees, and non-returning behavior are not closed.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed window bytes, FDE extent, padding bytes, or relative relocation target;
- changed per-element call bytes or target, tail-jump bytes or slot, or caller call bytes or argument setup;
- a changed element-size constant, null-guard displacement, or flag-clear opcode;
- a changed size edge from the decoded formula;
- any second direct caller or any indirect caller through a window slot.
