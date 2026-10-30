# foundation-dealloc-size-94: what does the fixed-88 dealloc-size window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 55-byte FDE window, its nine int3 padding bytes, one incoming direct call, the outgoing tail jump through a relocated slot, and the exact integer formulas over the input domain.
- Excluded: the tail-call target body at `0x54c8cb0`, the caller beyond its call site and argument setup, other dealloc/drop windows, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose arithmetic reads directly from its own bytes: a count field, a fixed element size, two early returns, and a tail jump that hands a computed pointer, size, and flag to a shared callee. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x1417c40`, no open pull request title mentions it or dealloc-size, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, or twin-take packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_dealloc_size.py --check research/work-items/foundation-dealloc-size-94/evidence.json
python3 -m unittest tests.test_foundation_dealloc_size -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1417c40 --stop-address=0x1417c80 artifacts/node/94/hl-node
objdump -d --start-address=0x143f520 --stop-address=0x143f670 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x88e4` (this window) and `0x2eda5c` (the caller). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x88e4` describes `[0x1417c40, 0x1417c77)`, 55 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x1417c76` is inside the FDE).
- The unwind index stride to the next entry is 64 bytes, ending at `0x1417c80`, only because nine `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "64-byte FDE-bounded" would overstate the frame by those nine padding bytes, and the checker locks the 55-byte body and the padding separately.
- No `R_X86_64_RELATIVE` relocation maps any slot to `0x1417c40`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, at `0x143f645`, subsequently visible as an instruction start in GNU disassembly from the caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x143f520, 0x143f670)`, 336 bytes. Before the call it sets `rdi` to `0x566a228` (a `lea` at `0x143f63b` into `r15`, then `mov %r15,%rdi`); the caller's full behavior and the meaning of that address are not closed here.

### Body behavior: one count, one floored product, two early returns, one tail jump

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1417c40` | `mov 0x8(%rdi),%rsi` | Count taken from field+8 (u64) |
| `0x1417c44` | `test %rsi,%rsi` | Zero-count test |
| `0x1417c47` | `je 0x1417c76` | Count 0 goes to `ret` |
| `0x1417c49` | `imul $0x58,%rsi,%rax` | Count times 88 |
| `0x1417c4d` | `add $0x67,%rax` | Plus 103 |
| `0x1417c51` | `and $0xfffffffffffffff0,%rax` | Low 4 bits cleared (floor to 16) |
| `0x1417c55` | `add %rax,%rsi` | Count plus floored product |
| `0x1417c58` | `add $0x11,%rsi` | Plus 17: the size |
| `0x1417c5c` | `je 0x1417c76` | Size 0 goes to `ret` |
| `0x1417c5e` | `mov (%rdi),%rdi` | Base pointer from field+0 |
| `0x1417c61` | `sub %rax,%rdi` | Pointer minus floored product |
| `0x1417c64` | `xor %edx,%edx` | Flag cleared |
| `0x1417c66` | `cmp $0x10,%rsi` | Size compared with 16 |
| `0x1417c6a` | `setb %dl` | 1 if size below 16, else 0 |
| `0x1417c6d` | `shl $0x2,%edx` | Flag: 4 if size below 16, else 0 |
| `0x1417c70` | `jmp *slot 0x576e010` | Tail jump to `0x54c8cb0` |
| `0x1417c76` | `ret` | Early-return path |

The formulas, with all arithmetic modulo 2^64, are:

- `floored = (count * 0x58 + 0x67) with low 4 bits cleared`
- `size = count + floored + 0x11`
- `pointer = field - floored`
- `flag = (size < 0x10) ? 4 : 0`

At the tail jump the registers are `rdi = pointer`, `rsi = size`, `rdx = flag`, and `rcx` still holds its entry value (the window never touches `rcx`). Whether the callee reads `rcx` is not decoded here; the register fact itself is retained.

Two corrections to the scout note that seeded this packet, both established from the disassembly rather than assumed:

- The rounding is a floor, not a round-up: the `and` instruction clears the low 4 bits of `count * 0x58 + 0x67`, so `floored` is the largest multiple of 16 at or below that sum. Count 1 gives `floored = 0xb0` (not `0xc0`) and `size = 0xc2`.
- The flag gate compares the **size**, not the count: the `cmp` at `0x1417c66` reads `rsi`, which by then holds `size`. The scout note's "count < 0x10" reading is wrong. The practical consequence is stronger: on the fall-through path count is at least 1, so `floored` is at least `0xb0` and `size` is at least `0xc2`, which is above 16. The flag is therefore always 0 on every non-wrapping input (checked for counts 1..10000); flag 4 requires the 64-bit sum to wrap into 1..15, and size exactly 0 (the second early return) requires a wrap to exactly 0.

Checked edges from the decoded formula:

| Count | Floored | Size | Flag |
| --- | --- | --- | --- |
| 1 | `0xb0` | `0xc2` | 0 |
| 15 | `0x580` | `0x5a0` | 0 |
| 16 | `0x5e0` | `0x601` | 0 |
| 255 | `0x5800` | `0x5910` | 0 |
| 4096 | `0x58060` | `0x59071` | 0 |

### The tail-call target

The tail jump goes through slot `0x576e010`, confirmed by a `R_X86_64_RELATIVE` relocation to `0x54c8cb0`. That address is a shared callee (per the scout shortlist, the unwrap-guard window already tail-calls it) and is **not** re-bound or identified here: this packet claims only the caller window, its arithmetic, and its register handoff. The callee's body, return type, and the meaning of the flag argument are unknown.

## Inferences and unknowns

- **Inferred:** this is a fixed-88 dealloc-size helper: its element size `0x58` (88), header-like `0x67`, trailer-like `0x11`, pointer-minus-floored-product shape, and tail jump to a shared callee support that label. The binary has no recovered symbol name here. Neither the source-level function name nor the full struct layout, the meaning of the flag, or the callee's contract is proven.
- The flag-4 arm exists in the bytes but is unreachable without 64-bit wrap on the non-returning path; whether any real caller can drive the sum into 1..15 is unknown, and no such input is claimed reachable.
- The single incoming direct call is real, but the caller's full behavior, its other arguments, and whether other callers exist through register-indirect or data paths are not closed. The byte-pattern scan is not a complete xref census.
- The tail-call target at `0x54c8cb0` is left unnamed: its own library ownership, transitive callees, and non-returning behavior are not closed.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed element size, header, trailer, threshold, or shift bytes;
- changed FDE extent, padding bytes, or relative relocation target;
- changed tail-jump displacement and changed caller call bytes;
- a changed or additional call-pattern candidate;
- changed arithmetic edges and a broken flag-always-zero bound.

Structural mutations deliberately bypass only the digest gate in the test helper, so they exercise downstream checks instead of all failing at SHA-256. The command-line tool always authenticates the complete target first.

**No progress gate requested.** Foundation's four gates and generated progress files stay unchanged. The denominator here is one bounded window / one call site, not all dealloc helpers. Next question: attribute the shared callee at `0x54c8cb0` from its own window before reconstructing Rust, and establish the caller's struct provenance for the field+8 count.
