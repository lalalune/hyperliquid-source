# foundation-flag-or-94: what does the byte-indexed flag-OR window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 21-byte FDE window, its eleven int3 padding bytes, the 20-entry flag table, the four relocation slots naming the window, and the exact no-caller scan result.
- Excluded: the meaning of the field and of the table, the two same-shape sibling windows, table entries at index 20 and above, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a byte argument selects one u32 table entry, and that entry is ORed into a struct field. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x15625e0`, no open pull request title mentions it or flag-or, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, or unsigned-clamp packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_flag_or.py --check research/work-items/foundation-flag-or-94/evidence.json
python3 -m unittest tests.test_foundation_flag_or -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x15625e0 --stop-address=0x1562600 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x17e18` (this window) and `0x17e2c` (the next window). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x17e18` describes `[0x15625e0, 0x15625f5)`, 21 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x15625f4` is inside the FDE).
- The unwind index stride to the next entry is 32 bytes, ending at `0x1562600`, only because eleven `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "32-byte FDE-bounded" would overstate the frame by those eleven padding bytes, and the checker locks the 21-byte body and the padding separately.
- The next FDE starts exactly at `0x1562600` (record at `.eh_frame+0x17e2c`, range `0x8b`).
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: one byte index, one table entry, one OR, no calls

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x15625e0` | `movzbl %sil,%eax` | Byte argument zero-extended to the index |
| `0x15625e4` | `lea -0x1310eff(%rip),%rcx` | Table base `0x2516ec` |
| `0x15625eb` | `mov (%rcx,%rax,4),%eax` | u32 table entry at the index |
| `0x15625ee` | `or %eax,0x1a0(%rdi)` | Entry ORed into field+0x1a0 |
| `0x15625f4` | `ret` | No return value; the field is updated in place |

The formula is `field+0x1a0 |= table[byte_index]`, where the index is the zero-extended byte in `sil` and the table is the u32 table at `0x2516ec` in `.rodata`.

### The flag table: exactly 20 single-bit entries, then multi-bit values

The first 20 u32 entries are a permutation of single bits 0..19:

| Index | Entry | Bit |
| --- | --- | --- |
| 0–7 | `0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80` | 0–7 |
| 8 | `0x200` | 9 |
| 9 | `0x800` | 11 |
| 10–17 | `0x1000, 0x2000, 0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000` | 12–19 |
| 18 | `0x100` | 8 |
| 19 | `0x400` | 10 |

One correction to the scout note that seeded this packet, established from the table bytes rather than assumed: the scout note described the permutation as bits 0–17 with indices 10–17 mapping to bits 12–17. The retained bytes show indices 16 and 17 hold bits 18 and 19, so the permutation covers bits 0–19, not 0–17.

Entry 20 is `0x01314a6c` (eleven bits set), and the following entries checked (21–39) are likewise multi-bit values, not single-bit masks. The packet therefore locks exactly the first 20 entries and claims no flag interpretation for indices 20 and above. The window itself would read `table[index]` for any byte index; only the first 20 entries are characterized here.

### Incoming edges: no direct calls, four relocation slots

- The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds zero direct `e8` calls to the window. This is explicitly not a complete xref census.
- Four `R_X86_64_RELATIVE` relocation records in `.rela.dyn` name this window as addend, at slots `0x5672668`, `0x5673070`, `0x5673830`, `0x5673958` (all in `.data.rel.ro`). The file stores 0 in those slots; the loader writes the window address at load time. So the window is referenced by data pointers, not by direct calls from `.text`. The contents and owners of those slots are not closed here.

### Same-shape siblings: bound alone, never as a family

Two same-shape windows exist and are explicitly not bound here: `0x1566100` (table `0x25178c`, field+0xa8) and `0x1568bb0` (table `0x251894`, field+0x1a0), each confirmed from its own disassembly (same five instructions, different table and field). This packet binds `0x15625e0` alone.

## Inferences and unknowns

- **Inferred:** this is a byte-indexed flag OR: its single-bit table entries, OR-into-field shape, and zero direct callers support that label. The binary has no recovered symbol name here. Neither the source-level function name, the struct layout, the meaning of the field, nor the meaning of any bit is proven.
- Whether any real caller drives a byte index of 20 or above through this window is unknown, and no such input is claimed reachable or meaningful.
- The four relocation slots' owners, and whether other callers exist through register-indirect or data paths, are not closed. The byte-pattern scan is not a complete xref census.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed window bytes, padding bytes, FDE records, or CIE;
- changed instruction bytes at fixed offsets (index load, table address, entry load, field OR, return);
- a changed table address target, changed table entries, a table that is not a permutation of bits 0..19, or a changed boundary entry 20;
- changed relocation slots naming the window, or any direct `e8` caller appearing in `.text`;
- changed formula edges.

## Limits

- No stdlib type, source-level function, field meaning, table meaning, or bit meaning is claimed. The "byte-indexed flag OR" label is an inference, kept separate from the observed behavior.
- Table entries at index 20 and above are not characterized as flags; the window's behavior for those indices is not claimed beyond the raw read the instructions perform.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
