# foundation-unsigned-clamp-94: what does the three-way unsigned clamp window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 69-byte FDE window, its eleven int3 padding bytes, one incoming direct call with argument setup, and the exact three-path unsigned formula.
- Excluded: the meaning of the tag and of the four fields, the caller's behavior beyond its call site and argument setup, other clamp or min helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one tag test, two field loads, one saturating subtraction, two unsigned minimum gates, and three exhaustive return paths with no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x15e4f70`, no open pull request title mentions it or unsigned-clamp, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or keyword-classifier packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_unsigned_clamp.py --check research/work-items/foundation-unsigned-clamp-94/evidence.json
python3 -m unittest tests.test_foundation_unsigned_clamp -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x15e4f70 --stop-address=0x15e4fc0 artifacts/node/94/hl-node
objdump -d --start-address=0x15e4610 --stop-address=0x15e4913 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the caller FDE window. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x1e1f0` (this window) and `0x3102ec` (the caller). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x1e1f0` describes `[0x15e4f70, 0x15e4fb5)`, 69 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x15e4fb4` is inside the FDE).
- The unwind index stride to the next entry is 80 bytes, ending at `0x15e4fc0`, only because eleven `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "80-byte FDE-bounded" would overstate the frame by those eleven padding bytes, and the checker locks the 69-byte body and the padding separately.
- No `R_X86_64_RELATIVE` relocation maps any slot to `0x15e4f70`, so the window has no indirect incoming call slot. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly one direct `e8` call to the window, at `0x15e482d`, subsequently visible as an instruction start in GNU disassembly from the caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The caller FDE is `[0x15e4610, 0x15e4913)`, 803 bytes. Before the call it sets `rdi` from `rsi` (`mov %rsi,%rdi` at `0x15e4827`) and saves `rdx` into `rbx` (`mov %rdx,%rbx` at `0x15e482a`); the caller's full behavior and the meaning of those values are not closed here. After the call it stores `rbx` at `0x58(%rsp)` and the return value `rax` at `0x60(%rsp)`; those stores are retained in the caller disassembly but their purpose is not claimed.

### Body behavior: one tag, three unsigned paths, no calls

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x15e4f70` | `mov (%rdi),%rax` | Tag taken from field+0 (u64) |
| `0x15e4f73` | `test %rax,%rax` | Tag-zero test, full 64-bit tag |
| `0x15e4f76` | `je 0x15e4f97` | Tag 0 goes to the min path |
| `0x15e4f78` | `cmp $0x1,%eax` | Tag-one test, low 32 bits only |
| `0x15e4f7b` | `jne 0x15e4fa7` | Any other tag goes to the zero path |
| `0x15e4f7d` | `mov 0x10(%rdi),%rcx` | Field+0x10 |
| `0x15e4f81` | `xor %eax,%eax` | Difference cleared |
| `0x15e4f83` | `sub 0x18(%rdi),%rcx` | Field+0x10 minus field+0x18 |
| `0x15e4f87` | `cmovae %rcx,%rax` | Difference kept only if field+0x10 >= field+0x18, else 0 (saturating subtraction) |
| `0x15e4f8b` | `mov 0x28(%rdi),%rcx` | Cap from field+0x28 |
| `0x15e4f8f` | `cmp %rax,%rcx` | Cap compared with the difference |
| `0x15e4f92` | `cmovb %rcx,%rax` | Unsigned minimum of difference and cap |
| `0x15e4f96` | `ret` | Tag-1 return |
| `0x15e4f97` | `mov 0x18(%rdi),%rax` | Tag-0: field+0x18 |
| `0x15e4f9b` | `mov 0x28(%rdi),%rcx` | Cap from field+0x28 |
| `0x15e4f9f` | `cmp %rax,%rcx` | Cap compared with field+0x18 |
| `0x15e4fa2` | `cmovb %rcx,%rax` | Unsigned minimum of field+0x18 and cap |
| `0x15e4fa6` | `ret` | Tag-0 return |
| `0x15e4fa7` | `xor %eax,%eax` | Other tags: result cleared to 0 |
| `0x15e4fa9` | `mov 0x28(%rdi),%rcx` | Cap from field+0x28 (loaded but never selected) |
| `0x15e4fad` | `cmp %rax,%rcx` | Cap compared with 0 |
| `0x15e4fb0` | `cmovb %rcx,%rax` | Unsigned: cap < 0 can never fire, so the result stays 0 |
| `0x15e4fb4` | `ret` | Other-tag return |

The formulas, with all arithmetic modulo 2^64 and all comparisons unsigned, are:

- tag == 0 → `min(field+0x18, field+0x28)`
- tag low 32 bits == 1 (and tag != 0) → `min(saturating_sub(field+0x10, field+0x18), field+0x28)`, where saturating_sub is `field+0x10 - field+0x18` when field+0x10 >= field+0x18, else 0
- any other tag → `0` exactly

Two precision notes, both established from the disassembly rather than assumed:

- The tag tests are not symmetric: the tag-0 test (`test %rax,%rax`) reads the full 64-bit tag, while the tag-1 test (`cmp $0x1,%eax`) reads only the low 32 bits. A tag of `0x100000001` therefore takes the tag-1 path, while a tag of `0x100000000` falls through to the zero path. The checker locks both edges.
- The other-tag path still loads the cap and runs the same `cmovb` gate, but the gate compares the cap against 0, which can never be less unsigned — so the path returns 0 exactly, and the cap load is dead. The formula above states that directly rather than calling the path "min(0, cap)".

Checked edges from the decoded formula:

| Tag | field+0x10 | field+0x18 | field+0x28 | Result |
| --- | --- | --- | --- | --- |
| 0 | 99 | 5 | 7 | 5 |
| 0 | 99 | 9 | 3 | 3 |
| 1 | 10 | 4 | 100 | 6 |
| 1 | 3 | 9 | 100 | 0 |
| 1 | 10 | 4 | 2 | 2 |
| 2 | 10 | 4 | 100 | 0 |
| `0x100000001` | 10 | 4 | 100 | 6 |
| `0x100000000` | 10 | 4 | 100 | 0 |

## Inferences and unknowns

- **Inferred:** this is a three-way unsigned clamp: the tag-selected minimum/saturating-subtraction shape supports that label. The binary has no recovered symbol name here. Neither the source-level function name, the struct layout, the meaning of the tag, nor the meaning of any field is proven.
- The single incoming direct call is real, but the caller's full behavior, its other arguments, and whether other callers exist through register-indirect or data paths are not closed. The byte-pattern scan is not a complete xref census.
- Whether the tag-1 path's low-32-bit quirk is reachable in practice depends on what values the tag field actually takes; no such input is claimed reachable.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed FDE extent, padding bytes, or relative relocation target;
- changed tag tests, branch displacements, field offsets, or gate opcodes;
- changed caller setup or call bytes, or a changed incoming-call set;
- changed formula edges, including the low-32-bit tag-1 quirk.

## Limits

- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
