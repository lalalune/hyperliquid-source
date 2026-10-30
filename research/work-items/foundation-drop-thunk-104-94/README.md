# foundation-drop-thunk-104-94: what does the 104-byte-element drop thunk do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 86-byte FDE window (including its in-FDE landing pad), its ten int3 padding bytes, two incoming direct calls, the outgoing tail jump through a relocated slot, and the exact integer formulas over the input domain.
- Excluded: the per-element call target body at `0x13ef560`, the resume call target body at `0x5660110`, the tail-call target body at `0x54c8cb0`, the callers beyond their call sites and argument setup, the adjacent window at `0x1452310`, other dealloc/drop windows, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one call, one null guard, one multiply, an in-FDE landing pad, and a tail jump that hands a computed pointer, size, and zero flag to a shared callee. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x14522b0`, no open pull request title mentions it or drop-thunk, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, or drop-thunk-168/240 packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_drop_thunk_104.py --check research/work-items/foundation-drop-thunk-104-94/evidence.json
python3 -m unittest tests.test_foundation_drop_thunk_104 -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x14522b0 --stop-address=0x1452310 artifacts/node/94/hl-node
objdump -d --start-address=0x14538e0 --stop-address=0x1453a71 artifacts/node/94/hl-node
objdump -d --start-address=0x1454620 --stop-address=0x14546d7 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of both caller FDE windows. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x2eed18` (this window), `0x2ef3dc` (caller A), and `0x2ef714` (caller B). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2eed18` describes `[0x14522b0, 0x1452306)`, 86 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the resume call at `0x1452301` ends at `0x1452306`).
- The unwind index stride to the next entry is 96 bytes, ending at `0x1452310`, only because ten `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "96-byte FDE-bounded" would overstate the frame by those ten padding bytes, and the checker locks the 86-byte body and the padding separately.
- No `R_X86_64_RELATIVE` relocation maps any slot to `0x14522b0`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly two direct `e8` calls to the window, at `0x1453a00` and `0x14546a7`, each subsequently visible as an instruction start in GNU disassembly from its caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- Caller A FDE is `[0x14538e0, 0x1453a71)`. Before the call it sets up `mov %rax,%r14; mov %rbx,%rdi`; the caller's full behavior and the meaning of those registers are not closed here.
- Caller B FDE is `[0x1454620, 0x14546d7)`. Before the call it sets up the same `mov %rax,%r14; mov %rbx,%rdi`; the caller's full behavior and the meaning of those registers are not closed here.

### Body behavior: one call, one null guard, one multiply, one landing pad, one tail jump

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x14522b0` | `push %r14` | Save callee-saved register |
| `0x14522b2` | `push %rbx` | Save callee-saved register |
| `0x14522b3` | `push %rax` | Stack slot for the call |
| `0x14522b4` | `mov %rdi,%rbx` | Struct pointer saved |
| `0x14522b7` | `call 0x13ef560` | Per-element call (target unnamed, behavior not claimed) |
| `0x14522bc` | `mov (%rbx),%rax` | Length taken from field+0 (u64) |
| `0x14522bf` | `test %rax,%rax` | Zero-length test |
| `0x14522c2` | `je 0x14522db` | Length 0 goes to restore + `ret` |
| `0x14522c4` | `mov 0x8(%rbx),%rdi` | Base pointer from field+8 |
| `0x14522c8` | `imul $0x68,%rax,%rsi` | Length times 104 |
| `0x14522cc` | `xor %edx,%edx` | Flag cleared to 0 |
| `0x14522ce` | `add $0x8,%rsp` | Drop the stack slot |
| `0x14522d2` | `pop %rbx` | Restore callee-saved register |
| `0x14522d3` | `pop %r14` | Restore callee-saved register |
| `0x14522d5` | `jmp *slot 0x576e010` | Tail jump to `0x54c8cb0` |
| `0x14522db` | `add $0x8,%rsp` | Early-return path |
| `0x14522df` | `pop %rbx` | Early-return path |
| `0x14522e0` | `pop %r14` | Early-return path |
| `0x14522e2` | `ret` | Early-return path |

The landing pad inside the FDE, at `0x14522e3..0x1452306`, is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x14522e3` | `mov %rax,%r14` | In-flight value saved |
| `0x14522e6` | `mov (%rbx),%rax` | Length reloaded from field+0 |
| `0x14522e9` | `test %rax,%rax` | Zero-length test |
| `0x14522ec` | `je 0x14522fe` | Length 0 skips the tail-slot call |
| `0x14522ee` | `mov 0x8(%rbx),%rdi` | Base pointer from field+8 |
| `0x14522f2` | `imul $0x68,%rax,%rsi` | Length times 104 |
| `0x14522f6` | `xor %edx,%edx` | Flag cleared to 0 |
| `0x14522f8` | `call *slot 0x576e010` | Same tail-slot callee, called (not jumped) |
| `0x14522fe` | `mov %r14,%rdi` | Saved value restored as argument |
| `0x1452301` | `call 0x5660110` | Resume call (GNU objdump labels the PLT stub `_Unwind_Resume@plt`) |

The formulas, with all arithmetic modulo 2^64, are:

- `size = length * 0x68`
- `pointer = field+8` (on the fall-through path, and on the landing-pad path when length is nonzero)
- `flag = 0` (on both paths; `edx` is cleared and never set otherwise)

At the tail jump the registers are `rdi = pointer`, `rsi = size`, `rdx = 0`. Whether the callee reads any other register is not decoded here; the register facts themselves are retained.

One correction to the scout note that seeded this packet, established from the disassembly rather than assumed: the per-element call happens **before** the null guard, not after it. The window calls `0x13ef560` unconditionally on entry, and only then tests the length. This matches the same correction for the 168-byte and 240-byte drop thunks. Any description of the guard as gating the call would invert the observed order.

Checked edges from the decoded formula:

| Length | Size |
| --- | --- |
| 1 | `0x68` |
| 2 | `0xd0` |
| 16 | `0x680` |
| 255 | `0x6798` |
| 4096 | `0x68000` |

### The tail-call target

The tail jump goes through slot `0x576e010`, confirmed by a `R_X86_64_RELATIVE` relocation to `0x54c8cb0`. That address is a shared callee (per the scout shortlist, the unwrap-guard, fixed-88 dealloc-size, generic dealloc-size, and 168/240-byte drop-thunk windows already tail-call it) and is **not** re-bound or identified here: this packet claims only the caller window, its behavior, and its register handoff. The callee's body, return type, and the meaning of the flag argument are unknown.

### The adjacent window is a different mechanism

The next FDE starts exactly at `0x1452310`, immediately after this window's padding. It is **not** a twin of this window: it calls `0x149a820`, then applies `lock decq (%rax)` with a nonzero check, and tail-jumps through a different slot, `0x576e658`. Adjacent address and a similar prologue do not make it the same mechanism, and no paired claim is made here.

## Inferences and unknowns

- **Inferred:** this is a drop thunk for 104-byte elements: its single per-element call, length-times-104 size, pointer-plus-size-plus-zero handoff, in-FDE landing pad, and tail jump to a shared callee support that label. The binary has no recovered symbol name here. Neither the source-level function name nor the full struct layout, the per-element call's contract, or the callee's contract is proven.
- The per-element call target at `0x13ef560` is left unnamed: its own library ownership, behavior, and whether it drops one element or the whole range is not closed.
- The resume call target at `0x5660110` is left unnamed beyond GNU objdump's PLT label: its body and contract are not closed.
- The two incoming direct calls are real, but the callers' full behavior, their other arguments, and whether other callers exist through register-indirect or data paths are not closed. The byte-pattern scan is not a complete xref census.
- The tail-call target at `0x54c8cb0` is left unnamed: its own library ownership, transitive callees, and non-returning behavior are not closed.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed window bytes, FDE extent, padding bytes, or relative relocation target;
- changed per-element call bytes or target, tail-jump bytes or slot, landing-pad bytes or targets, or caller call bytes or argument setup;
- a changed element-size constant, null-guard displacement, or flag-clear opcode;
- a changed size edge from the decoded formula;
- any third direct caller or any indirect caller through a window slot.
