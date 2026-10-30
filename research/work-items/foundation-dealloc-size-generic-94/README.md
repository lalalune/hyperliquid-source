# foundation-dealloc-size-generic-94: what does the generic dealloc-size window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 86-byte FDE window, its ten int3 padding bytes, eight incoming direct calls, the outgoing tail jump through a relocated slot, and the exact integer formulas over the input domain.
- Excluded: the tail-call target body at `0x54c8cb0`, the eight callers beyond their call sites, other dealloc/drop windows, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose arithmetic reads directly from its own bytes: a count field, struct-read element size and alignment, two early returns, a two-gate flag, and a tail jump that hands a computed pointer, size, and flag to a shared callee. It is the generic form of the fixed-88 window bound in foundation-dealloc-size-94 (hardcoded `0x58` there, struct-read fields here). It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x140e430`, no open pull request title mentions it or dealloc-size, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, or fixed-88 dealloc-size packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_dealloc_size_generic.py --check research/work-items/foundation-dealloc-size-generic-94/evidence.json
python3 -m unittest tests.test_foundation_dealloc_size_generic -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x140e430 --stop-address=0x140e490 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the FDE at `.eh_frame` section offset `0x8260` (this window) and the shared CIE at offset `0x0`. The checker locks these raw FDE/CIE records and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x8260` describes `[0x140e430, 0x140e486)`, 86 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x140e485` is inside the FDE).
- The unwind index stride to the next entry is 96 bytes, ending at `0x140e490`, only because ten `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "96-byte FDE-bounded" would overstate the frame by those ten padding bytes, and the checker locks the 86-byte body and the padding separately.
- No `R_X86_64_RELATIVE` relocation maps any slot to `0x140e430`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly eight direct `e8` calls to the window, each confirmed as a `call 140e430` instruction start by linear disassembly: `0x141cee2`, `0x141d9f6`, `0x141e0e2`, `0x141e81c`, `0x141ef12`, `0x141f663`, `0x141fdb7`, `0x1420513`. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census, and the eight callers' behavior is not closed here.

### Body behavior: struct-read size/alignment, two early returns, two flag gates, one tail jump

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x140e430` | `mov 0x20(%rdi),%rsi` | Count taken from field+0x20 (u64) |
| `0x140e434` | `test %rsi,%rsi` | Zero-count test |
| `0x140e437` | `je 0x140e485` | Count 0 goes to `ret` |
| `0x140e439` | `mov 0x10(%rdi),%rax` | Alignment taken from field+0x10 |
| `0x140e43d` | `lea 0x1(%rsi),%rcx` | Count + 1 |
| `0x140e441` | `imul 0x8(%rdi),%rcx` | Times element size from field+0x08: padded |
| `0x140e446` | `lea (%rax,%rcx,1),%rdx` | Alignment + padded |
| `0x140e44a` | `dec %rdx` | Alignment + padded - 1 |
| `0x140e44d` | `mov %rax,%rcx` | Alignment copied |
| `0x140e450` | `neg %rcx` | Negated alignment |
| `0x140e453` | `and %rdx,%rcx` | Pad = (-align) & (align + padded - 1) |
| `0x140e456` | `add %rcx,%rsi` | Count plus pad |
| `0x140e459` | `add $0x11,%rsi` | Plus 17: the size |
| `0x140e45d` | `je 0x140e485` | Size 0 goes to `ret` |
| `0x140e45f` | `mov 0x18(%rdi),%rdi` | Base pointer from field+0x18 |
| `0x140e463` | `sub %rcx,%rdi` | Base minus pad: the pointer |
| `0x140e466` | `mov $0x40,%ecx` | tzcnt fallback: 64 |
| `0x140e46b` | `tzcnt %rax,%rcx` | Trailing-zero count of alignment (64 if 0) |
| `0x140e470` | `xor %edx,%edx` | Flag cleared |
| `0x140e472` | `cmp %rsi,%rax` | Alignment compared with size |
| `0x140e475` | `cmova %ecx,%edx` | Flag = tzcnt if alignment above size |
| `0x140e478` | `cmp $0x11,%rax` | Alignment compared with 17 |
| `0x140e47c` | `cmovae %ecx,%edx` | Flag = tzcnt if alignment at least 17 |
| `0x140e47f` | `jmp *slot 0x576e010` | Tail jump to `0x54c8cb0` |
| `0x140e485` | `ret` | Early-return path |

The formulas, with all arithmetic modulo 2^64, are:

- `padded = (count + 1) * elem_size`
- `pad = (-align) & (align + padded - 1)`
- `size = count + pad + 0x11`
- `pointer = base - pad`
- `flag = tzcnt(align) if (align > size or align >= 0x11) else 0`, with `tzcnt(0) = 64`

At the tail jump the registers are `rdi = pointer`, `rsi = size`, `rdx = flag`, `rcx = tzcnt(align)`, and `rax = align`. Whether the callee reads `rcx` or `rax` is not decoded here; the register facts themselves are retained.

One correction to the scout note that seeded this packet, established from the disassembly rather than assumed:

- The two `cmova`/`cmovae` gates are selectors, not a cap: they choose between 0 and `tzcnt(align)`, they never clamp the trailing-zero count itself. The exact predicate is `(align > size) OR (align >= 0x11)`. Note the `mov $0x40,%ecx` before `tzcnt`: it preloads 64, the value `tzcnt` yields for a zero input, as the fallback an older `bsf` decoding would leave untouched. On the fall-through path the flag is therefore 0 or `tzcnt(align)` (at most 63 for nonzero alignment); the value 64 arises only for alignment 0, which fails both gates and yields flag 0.

Checked edges from the decoded formula:

| Count | Align | Elem | Padded | Pad | Size | Flag |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 16 | 8 | `0x10` | `0x10` | `0x22` | 0 |
| 1 | 32 | 8 | `0x10` | `0x20` | `0x32` | 5 |
| 3 | 8 | 24 | `0x60` | `0x60` | `0x74` | 0 |
| 2 | 24 | 16 | `0x30` | `0x40` | `0x53` | 3 |
| 5 | 17 | 4 | `0x18` | `0x28` | `0x3e` | 0 (tzcnt 17 is 0, gate fires) |
| 1 | 64 | 1 | `0x2` | `0x40` | `0x52` | 6 |

On non-wrapping inputs the size is at least `0x12` (count at least 1, pad nonnegative, plus `0x11`), so the `align > size` gate never fires below the `0x11` threshold; the flag rule collapses to `tzcnt(align) if align >= 0x11 else 0`. The checker verifies that collapsed rule over a 4,800-case grid (counts 1..50, 16 alignments, 6 element sizes). The `align > size` gate can only matter when the 64-bit sum wraps, which no checked input does.

### The tail-call target

The tail jump goes through slot `0x576e010`, confirmed by a `R_X86_64_RELATIVE` relocation to `0x54c8cb0`. That address is a shared callee (per the scout shortlist, the unwrap-guard window already tail-calls it, as does the fixed-88 window) and is **not** re-bound or identified here: this packet claims only the caller window, its arithmetic, and its register handoff. The callee's body, return type, and the meaning of the flag argument are unknown.

## Inferences and unknowns

- **Inferred:** this is a generic dealloc-size helper: its struct-read element size and alignment, trailer-like `0x11`, base-minus-pad shape, and tail jump to a shared callee support that label. The binary has no recovered symbol name here. Neither the source-level function name nor the full struct layout, the meaning of the flag, or the callee's contract is proven.
- The `pad` formula is a bitwise `(-align) & (align + padded - 1)`, not a power-of-two alignment rounding: for non-power-of-two alignments (for example 24) the pad is not a multiple of the alignment, and no rounding-to-alignment property is claimed.
- The size-0 early return and the `align > size` flag gate both require 64-bit wrap on the fall-through path; whether any real caller can drive the sum into a wrap is unknown, and no such input is claimed reachable.
- The eight incoming direct calls are real, but the callers' full behavior, their other arguments, and whether other callers exist through register-indirect or data paths are not closed. The byte-pattern scan is not a complete xref census.
- The tail-call target at `0x54c8cb0` is left unnamed: its own library ownership, transitive callees, and non-returning behavior are not closed.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed field offsets, trailer/threshold/tzcnt-fallback constants, or window bytes;
- changed FDE extent, padding bytes, or relative relocation target;
- changed tail-jump displacement and changed caller call bytes;
- a changed or additional call-pattern candidate;
- changed arithmetic edges and a broken non-wrapping flag rule.

Structural mutations deliberately bypass only the digest gate in the test helper, so they exercise downstream checks instead of all failing at SHA-256. The command-line tool always authenticates the complete target first.

**No progress gate requested.** Foundation's four gates and generated progress files stay unchanged. The denominator here is one bounded window / eight call sites, not all dealloc helpers. Next question: attribute the shared callee at `0x54c8cb0` from its own window before reconstructing Rust, and establish the callers' struct provenance for the field+0x20 count.
