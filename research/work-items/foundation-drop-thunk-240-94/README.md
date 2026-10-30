# foundation-drop-thunk-240-94: what does the 240-byte-element drop thunk do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 92-byte FDE window (body plus in-FDE landing pad), its four int3 padding bytes, one incoming direct call, the outgoing tail jump through a relocated slot, the landing-pad resume call, and the exact integer formulas over the input domain.
- Excluded: the per-element call target body at `0x15443a0`, the tail-call target body at `0x54c8cb0`, the resume target body at `0x5660110`, the caller beyond its call site and argument setup, other dealloc/drop windows, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one call, one null guard, one multiply, and a tail jump that hands a computed pointer, size, and zero flag to a shared callee, plus an in-FDE landing pad that repeats the same shape and then resumes unwinding. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x152f710`, no open pull request title mentions it or drop-thunk, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, or drop-thunk-168 packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_drop_thunk_240.py --check research/work-items/foundation-drop-thunk-240-94/evidence.json
python3 -m unittest tests.test_foundation_drop_thunk_240 -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x152f710 --stop-address=0x152f770 artifacts/node/94/hl-node
objdump -d --start-address=0x152bf80 --stop-address=0x152c040 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains disassembly of the caller region around the call site (0x152bf80..0x152c040); the caller FDE itself is 5520 bytes, so the full caller body is not retained — only the call site and its argument setup are claimed here. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x302128` (this window) and `0x301cb8` (the caller). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x302128` describes `[0x152f710, 0x152f76c)`, 92 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the resume call at `0x152f767` is inside the FDE).
- The unwind index stride to the next entry is 96 bytes, ending at `0x152f770`, only because four `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "96-byte FDE-bounded" would overstate the frame by those four padding bytes, and the checker locks the 92-byte body and the padding separately. The next FDE starts exactly at `0x152f770`.
- No `R_X86_64_RELATIVE` relocation maps any slot to `0x152f710`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, at `0x152bffc`, subsequently visible as an instruction start in GNU disassembly from the caller region. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x152aab0, 0x152c040)`, 5520 bytes. Before the call it sets `rdi` to `0x2f8(%rsp)` (a `lea` at `0x152bff4`); the caller's full behavior and the meaning of that address are not closed here.

### Body behavior: one call, one null guard, one multiply, one tail jump, one landing pad

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x152f710` | `push %r14` | Save callee-saved register |
| `0x152f712` | `push %rbx` | Save callee-saved register |
| `0x152f713` | `push %rax` | Stack slot for the landing pad's saved pointer |
| `0x152f714` | `mov %rdi,%rbx` | Keep the input pointer |
| `0x152f717` | `call 0x15443a0` | Per-element call, unconditional, before the null guard |
| `0x152f71c` | `mov (%rbx),%rax` | Length taken from field+0 (u64) |
| `0x152f71f` | `test %rax,%rax` | Null/zero test |
| `0x152f722` | `je 0x152f73e` | Length 0 goes to the return path |
| `0x152f724` | `mov 0x8(%rbx),%rdi` | Base pointer from field+8 |
| `0x152f728` | `imul $0xf0,%rax,%rsi` | Length times 240 |
| `0x152f72f` | `xor %edx,%edx` | Flag cleared |
| `0x152f731` | `add $0x8,%rsp` | Drop the stack slot |
| `0x152f735` | `pop %rbx` | Restore |
| `0x152f736` | `pop %r14` | Restore |
| `0x152f738` | `jmp *slot 0x576e010` | Tail jump to `0x54c8cb0` |
| `0x152f73e` | `add $0x8,%rsp` | Null path: drop the stack slot |
| `0x152f742` | `pop %rbx` | Restore |
| `0x152f743` | `pop %r14` | Restore |
| `0x152f745` | `ret` | Early-return path |
| `0x152f746` | `mov %rax,%r14` | Landing pad: save the exception pointer |
| `0x152f749` | `mov (%rbx),%rax` | Reload length from field+0 |
| `0x152f74c` | `test %rax,%rax` | Null/zero test again |
| `0x152f74f` | `je 0x152f764` | Length 0 skips the tail-slot call |
| `0x152f751` | `mov 0x8(%rbx),%rdi` | Base pointer from field+8 again |
| `0x152f755` | `imul $0xf0,%rax,%rsi` | Length times 240 again |
| `0x152f75c` | `xor %edx,%edx` | Flag cleared again |
| `0x152f75e` | `call *slot 0x576e010` | Tail-slot call to `0x54c8cb0` |
| `0x152f764` | `mov %r14,%rdi` | Restore the saved exception pointer |
| `0x152f767` | `call 0x5660110` | Resume unwinding (GNU objdump labels the target `_Unwind_Resume@plt`) |

The formulas, with all arithmetic modulo 2^64, are:

- `size = length * 0xf0`
- `pointer = field+8`
- `flag = 0`

At the tail jump the registers are `rdi = pointer`, `rsi = size`, `rdx = 0`. At the landing-pad tail-slot call they are the same. Whether the callees read further registers is not decoded here; the register facts themselves are retained.

Correction to the scout note that seeded this packet, established from the disassembly rather than assumed:

- The per-element call happens **before** the null guard, not after it — the window calls `0x15443a0` unconditionally on entry and only then tests the length. This matches packet #12's correction for the 168-byte thunk: the same call-first shape holds here. The scout note's "one call, null guard" ordering understated the order; the checker locks the call bytes at `0x152f717` ahead of the guard at `0x152f722`.

Checked edges from the decoded formula:

| Length | Size |
| --- | --- |
| 1 | `0xf0` |
| 2 | `0x1e0` |
| 16 | `0xf00` |
| 255 | `0xef10` |
| 4096 | `0xf0000` |

### The tail-call target and the resume target

The tail jump and the landing-pad call both go through slot `0x576e010`, confirmed by a `R_X86_64_RELATIVE` relocation to `0x54c8cb0`. That address is a shared callee (per the scout shortlist, the unwrap-guard, fixed-88, generic, and 168-byte-thunk windows already tail-call it) and is **not** re-bound or identified here: this packet claims only the caller window, its behavior, and its register handoffs. The callee's body, return type, and the meaning of the flag argument are unknown.

The landing-pad resume call is a direct `e8` to `0x5660110`, which GNU objdump labels `_Unwind_Resume@plt`; the PLT stub at that address is a standard `jmp *GOT` stub. The resume target's body and contract are not claimed here.

## Inferences and unknowns

- **Inferred:** this is a drop thunk for 240-byte elements: its element size `0xf0` (240), length-times-element-size shape, null guard, and tail jump to a shared callee support that label. The binary has no recovered symbol name here. Neither the source-level function name nor the full struct layout, the per-element call's contract, or the callee's contract is proven.
- The per-element call runs unconditionally even when the length is zero; whether that call is side-effect-free for a zero-length input is unknown, and no such guarantee is claimed.
- The single incoming direct call is real, but the caller's full behavior, its other arguments, and whether other callers exist through register-indirect or data paths are not closed. The byte-pattern scan is not a complete xref census.
- The tail-call target at `0x54c8cb0` is left unnamed: its own library ownership, transitive callees, and non-returning behavior are not closed.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed FDE extent, padding bytes, or relative relocation target;
- changed window bytes, per-element call bytes or target, tail-jump bytes or slot, landing-pad bytes or resume call target;
- changed element-size constants, null-guard displacements, or flag-clear opcodes;
- changed caller call bytes, caller argument setup, or incoming-call pattern;
- changed size edges.

## Limits

- No source-level function name, full struct layout, per-element-call contract, resume contract, or callee contract is claimed. The "drop thunk, 240-byte elements" label is an inference, kept separate from the observed behavior.
- The landing pad's exception-handling semantics (which exception object, which cleanup runs before it) are not decoded; only its instruction sequence and register handoffs are claimed.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
