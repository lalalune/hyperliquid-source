# foundation-error-name-94: what does the byte-tagged error-name window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 40-byte FDE window, its eight int3 padding bytes, the two .rodata name strings and the following name bytes they run into, the one relocation slot naming the window, and the exact no-caller scan result.
- Excluded: the meaning of the byte, of the names, and of the returned pointer/length pair; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one byte selects one of two pointers by a zero test, and a length is computed as 3*(byte^1)+14. Only bytes 0 and 1 land exactly on a name boundary; larger bytes return slices that run past "invalid length" into the following concatenated names. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x14b4e20`, no open pull request title mentions it or error-name, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, unsigned-clamp, flag-or, tagged-pointer, tzcnt-gate, or chunk-equality packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_error_name.py --check research/work-items/foundation-error-name-94/evidence.json
python3 -m unittest tests.test_foundation_error_name -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x14b4e20 --stop-address=0x14b4e50 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0xdbe0` (this window) and `0xdbf4` (the next window). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0xdbe0` describes `[0x14b4e20, 0x14b4e48)`, 40 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x14b4e47` is inside the FDE).
- The unwind index stride to the next entry is 48 bytes, ending at `0x14b4e50`, only because eight `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "48-byte FDE-bounded" would overstate the frame by those eight padding bytes, and the checker locks the 40-byte body and the padding separately.
- The next FDE starts exactly at `0x14b4e50` (record at `.eh_frame+0xdbf4`, range 293 bytes). It is a different window, not analyzed as part of this packet.
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: one byte, two pointers, one length formula, no calls

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x14b4e20` | `movzbl (%rdi),%ecx` | Byte at (rdi), zero-extended |
| `0x14b4e23` | `mov %rcx,%rax` | Copy byte to rax |
| `0x14b4e26` | `xor $0x1,%rax` | Byte xor 1 |
| `0x14b4e2a` | `lea (%rax,%rax,2),%rdx` | Three times (byte^1) |
| `0x14b4e2e` | `add $0xe,%rdx` | Plus 14: the length |
| `0x14b4e32` | `lea -0x1298e96(%rip),%rsi` | Second pointer `0x21bfa3` |
| `0x14b4e39` | `lea -0x1298eae(%rip),%rax` | First pointer `0x21bf92` |
| `0x14b4e40` | `test %rcx,%rcx` | Zero test on the byte |
| `0x14b4e43` | `cmovne %rsi,%rax` | Nonzero byte selects the second pointer |
| `0x14b4e47` | `ret` | Return |

The rule, with all arithmetic over the retained bytes, is:

- `byte = *(rdi) as an unsigned byte`
- `pointer = 0x21bf92 if byte == 0 else 0x21bfa3`
- `length = 3 * (byte ^ 1) + 14`
- `return (rax = pointer, rdx = length)`

The names live in `.rodata` (file offset = VA), adjacent with no separator:

- At `0x21bf92`: `invalid character` (17 bytes), immediately followed by
- At `0x21bfa3`: `invalid length` (14 bytes), immediately followed by `SystemTimeErrorUtf8Errorvalid_up_to...`

Exact edges from the decoded formula:

| Byte | Pointer | Length | Returned slice |
| --- | --- | --- | --- |
| 0 | `0x21bf92` | 17 | `invalid character` |
| 1 | `0x21bfa3` | 14 | `invalid length` |
| 2 | `0x21bfa3` | 23 | `invalid lengthSystemTim` |
| 3 | `0x21bfa3` | 20 | `invalid lengthSystem` |
| 4 | `0x21bfa3` | 29 | `invalid lengthSystemTimeError` |
| 255 | `0x21bfa3` | 776 | starts at `invalid length`, runs 776 bytes into `.rodata` |

Only bytes 0 and 1 land exactly on a name boundary. For byte >= 2 the returned slice starts at "invalid length" and runs past it into the following concatenated name bytes; no claim is made that such a slice is a meaningful name, and no claim is made about bytes beyond the verified 62-byte `.rodata` run starting at `0x21bf92`.

### Data edges: one relocation slot, no direct callers

- The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` callers — explicitly not a complete xref census.
- One `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend, at slot `0x566de38` in `.data.rel.ro` (file stores 0, applied only at load time) — the window is referenced by a data pointer, not by a direct call.

### No scout correction needed

Every scouted element verified exactly: FDE range, padding count, both pointers, both name strings, the length formula, and the byte >= 2 spanning caveat.

## Inferences and unknowns

- **Inferred:** this is a byte-tagged error-name selector: its two pointers, the zero test selecting between them, and the xor-then-scale length formula support that label. The binary has no recovered symbol name here. Neither the source-level function name, the meaning of the byte, nor the meaning of the returned pointer/length pair is proven.
- The byte is read from `(rdi)` with no bounds or validity check inside the window; whether callers restrict it to 0/1 is not closed here.
- The returned slice for byte >= 2 is a mechanical consequence of the formula, not evidence that such slices are intended names.
- The data-pointer reference's provenance beyond the one RELATIVE slot is not claimed, and the byte-pattern scan is not a complete xref census.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed window bytes, FDE extent, padding bytes, or relative relocation target;
- changed xor/length constants, pointer displacements, or name bytes;
- changed incoming-call scan result;
- changed selection-rule edges, including the byte >= 2 spanning slices.
