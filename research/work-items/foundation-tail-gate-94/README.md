# foundation-tail-gate-94: what does the small gate with a tail-jump do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 50-byte FDE window, its fourteen int3 padding bytes, two incoming direct calls with their caller FDEs, and the exact gate rule including the v == 3 scout correction.
- Excluded: the field's meaning, the tail target's body and purpose, the callers' behavior beyond their call sites and argument setup, the next FDE, other gate helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one field load, one subtract, two unsigned compares, two conditional jumps, one tail jump, one return. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x250ab00`, no open pull request title mentions it or tail-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, half-swap, xor-mixer, or mask-builder packets.

This window is bound **alone**. No census of similar windows is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_tail_gate.py --check research/work-items/foundation-tail-gate-94/evidence.json
python3 -m unittest tests.test_foundation_tail_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x250ab00 --stop-address=0x250ab40 artifacts/node/94/hl-node
objdump -d --start-address=0x24fb610 --stop-address=0x24fc830 artifacts/node/94/hl-node
objdump -d --start-address=0x24fc8a0 --stop-address=0x24fdce8 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains disassembly of both caller FDEs from their starts through their call sites (`0x24fb610`..`0x24fc830` and `0x24fc8a0`..`0x24fdce8`); the full caller FDEs are `[0x24fb610, 0x24fc89f)` and `[0x24fc8a0, 0x24fdd54)`, and only the retained regions are claimed here. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x84f14`, the next FDE at `0x84f28`, both caller FDEs at `0x3e2958` and `0x3e29ac`, and the tail target's FDE at `0x3e4834`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value). It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x84f14` describes `[0x250ab00, 0x250ab32)`, 50 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `jmp` at `0x250ab2d` is inside the FDE; the `ret` at `0x250ab24` is also inside it).
- The unwind index stride to the next entry is 64 bytes, ending at `0x250ab40`, only because fourteen `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "64-byte FDE-bounded" would overstate the frame by those fourteen padding bytes, and the checker locks the 50-byte body and the padding separately. The next FDE starts exactly at `0x250ab40`.
- No relocation of any type in `.rela.dyn` maps a slot to `0x250ab00`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly two direct `e8` calls to the window, each subsequently visible as an instruction start in GNU disassembly from its caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The callers' argument setup is retained: each caller sets `rdi` to a stack address (`lea 0x8c0(%rsp),%rdi` and `lea 0xad8(%rsp),%rdi`) immediately before the call. Caller purpose is not claimed.

### Body behavior: one load, two compares, two jumps, one tail jump

Decoded from the FDE start, the window takes a struct pointer in `rdi` and reads a 64-bit field at offset 0:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x250ab00` | `mov (%rdi),%rax` | v = field+0 |
| `0x250ab03` | `lea -0x2(%rax),%rdx` | rdx = v - 2 |
| `0x250ab07` | `cmp $0x2,%rax` | Unsigned threshold compare |
| `0x250ab0b` | `mov $0x1,%ecx` | Default n = 1 |
| `0x250ab10` | `cmovae %rdx,%rcx` | n = v - 2 iff v >= 2 (unsigned) |
| `0x250ab14` | `cmp $0x1,%rcx` | n == 1 test |
| `0x250ab18` | `je 0x250ab25` | n == 1 path: offset 0x28 |
| `0x250ab1a` | `mov $0x30,%eax` | Default offset/return 0x30 |
| `0x250ab1f` | `test %rcx,%rcx` | n == 0 test |
| `0x250ab22` | `je 0x250ab2a` | n == 0 path: offset 0x30 |
| `0x250ab24` | `ret` | No-jump path returns 0x30 |
| `0x250ab25` | `mov $0x28,%eax` | n == 1 offset |
| `0x250ab2a` | `add %rax,%rdi` | Argument = rdi + offset |
| `0x250ab2d` | `jmp 0x2508760` | Tail jump to the shared callee |

The rule, in full:

- v < 2 (v ∈ {0, 1}): n = 1, so the `je` at `0x250ab18` fires and the window tail-jumps to `0x2508760` with `rdi+0x28`.
- v == 2: n = 0, so the `je` at `0x250ab22` fires and the window tail-jumps with `rdi+0x30`.
- v == 3: n = 1 (3 - 2), so the `je` at `0x250ab18` fires and the window tail-jumps with `rdi+0x28` — the same path as v < 2.
- v >= 4: n = v - 2 >= 2, so neither jump fires and the window returns `0x30` in `rax` without jumping.

The tail target `0x2508760` has its own FDE `[0x2508760, 0x2508889)`, 0x129 bytes, starting with a real function prologue (`push %rbp` and friends). It is named as the shared callee and explicitly **not** decoded here; no claim is made about what it does with the adjusted argument.

### Scout correction

The scout note said "v == 2 (n == 0) → tail-jump with rdi+0x30; v < 2 (n == 1) → tail-jump with rdi+0x28; v > 2 → return 0x30 without jumping". That last clause is wrong for v == 3: because n = v - 2, v == 3 gives n == 1, which takes the same `je` path as v < 2 and tail-jumps with `rdi+0x28`. Only v >= 4 returns `0x30` without jumping. The scout's FDE range, padding count, tail target, and both callers verified exactly; only the v > 2 summary needed this correction, and it is stated here rather than silently carried over.

### Incoming calls

| Call site | Caller FDE | Confirmed as instruction start |
| --- | --- | --- |
| `0x24fc82b` | `[0x24fb610, 0x24fc89f)` | Yes, linear disassembly from FDE start |
| `0x24fdce3` | `[0x24fc8a0, 0x24fdd54)` | Yes, linear disassembly from FDE start |

Each call site's 5-byte `e8` + rel32 sequence is locked by the checker, and its target resolves exactly to `0x250ab00`.

## Inferences

- The "tail-gate" label is an inference from the two-compare shape feeding a shared tail jump. It is kept separate from the observed gate rule.
- The two tail-jump offsets (0x28 and 0x30) are adjacent struct offsets, but no field meaning is claimed for either.

## Unknowns

- The field's meaning, and what kind of quantity the input struct holds.
- The tail target's behavior and what it does with the adjusted argument.
- The window's source-level name, type, and component owner.
- The callers' purpose beyond their call sites and argument setup.
- Whether any caller relies on the 0x30 return value beyond the retained call sites.

## Limits

- No stdlib type, source-level function, field meaning, tail-target purpose, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
