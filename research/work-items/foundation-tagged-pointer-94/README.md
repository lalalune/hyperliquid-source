# foundation-tagged-pointer-94: what does the tagged-pointer decision-tree window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 67-byte FDE window, its thirteen int3 padding bytes, the four-branch decision tree over three magic constants, the one relocation slot naming the window, and the exact no-caller scan result.
- Excluded: the meaning of the field, of the three constants, and of the two data pointers; the next FDE window at `0x15d6600` beyond its frame record; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one qword field is tested against three magic constants, and each of the four paths returns one exactly stated (rax, rdx) pair. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x15d65b0`, no open pull request title mentions it or tagged-pointer, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, unsigned-clamp, or flag-or packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_tagged_pointer.py --check research/work-items/foundation-tagged-pointer-94/evidence.json
python3 -m unittest tests.test_foundation_tagged_pointer -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x15d65b0 --stop-address=0x15d6600 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x1d860` (this window) and `0x1d874` (the next window). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x1d860` describes `[0x15d65b0, 0x15d65f3)`, 67 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x15d65f2` is inside the FDE).
- The unwind index stride to the next entry is 80 bytes, ending at `0x15d6600`, only because thirteen `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "80-byte FDE-bounded" would overstate the frame by those thirteen padding bytes, and the checker locks the 67-byte body and the padding separately.
- The next FDE starts exactly at `0x15d6600` (record at `.eh_frame+0x1d874`, range `0x3`). Its body is not analyzed here.
- GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: one field, three constants, four return pairs, no calls

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x15d65b0` | `mov (%rdi),%rcx` | Value taken from field+0 (u64) |
| `0x15d65b3` | `movabs $0x8000000000000002,%rdx` | High-tag constant |
| `0x15d65bd` | `cmp %rdx,%rcx` | Unsigned compare against the high tag |
| `0x15d65c0` | `jae 0x15d65dc` | Value at or above the high tag goes to the zero return |
| `0x15d65c2` | `mov %rdi,%rax` | Base pointer staged as the return value |
| `0x15d65c5` | `mov %rcx,%rdx` | Value copied for the negate test |
| `0x15d65c8` | `neg %rdx` | Negate; overflows only for `0x8000000000000000` |
| `0x15d65cb` | `jo 0x15d65df` | Overflow goes to the base-plus-8 return |
| `0x15d65cd` | `movabs $0x8000000000000001,%rdx` | Unit-tag constant |
| `0x15d65d7` | `cmp %rdx,%rcx` | Compare against the unit tag |
| `0x15d65da` | `jne 0x15d65eb` | Anything but the unit tag goes to the base return |
| `0x15d65dc` | `xor %eax,%eax` | Zero return value |
| `0x15d65de` | `ret` | Tag paths return here |
| `0x15d65df` | `add $0x8,%rax` | Base pointer plus 8 |
| `0x15d65e3` | `lea 0x40a05be(%rip),%rdx` | Data pointer `0x5676ba8` |
| `0x15d65ea` | `ret` | Neg-overflow path returns here |
| `0x15d65eb` | `lea 0x40a062e(%rip),%rdx` | Data pointer `0x5676c20` |
| `0x15d65f2` | `ret` | Base path returns here |

The decision tree, with all comparisons unsigned, is:

- `v >= 0x8000000000000002` → return `(rax = 0, rdx = 0x8000000000000002)`.
- `v == 0x8000000000000000` → the `neg` overflows, so `jo` is taken: return `(rax = rdi + 8, rdx = 0x5676ba8)`.
- `v == 0x8000000000000001` → the `jne` falls through to the zero return: return `(rax = 0, rdx = 0x8000000000000001)`.
- Otherwise → return `(rax = rdi, rdx = 0x5676c20)`.

Register precision matters on the two tag paths: the zero return keeps `rdx` holding the tag constant that was compared, so the two tag paths return different `rdx` values (`0x8000000000000002` vs `0x8000000000000001`). They are not the same `(0, 0)` pair, and the checker locks both.

Checked edges from the decoded tree:

| Value | Return (rax, rdx) |
| --- | --- |
| `0` | `(rdi, 0x5676c20)` |
| `2` | `(rdi, 0x5676c20)` |
| `0x7fffffffffffffff` | `(rdi, 0x5676c20)` |
| `0x8000000000000000` | `(rdi + 8, 0x5676ba8)` |
| `0x8000000000000001` | `(0, 0x8000000000000001)` |
| `0x8000000000000002` | `(0, 0x8000000000000002)` |
| `0xffffffffffffffff` | `(0, 0x8000000000000002)` |

### Data edges: no direct callers, one relocation slot, two data pointers

- The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` calls to this window. This is explicitly not a complete xref census: register-indirect references, other pointer paths, prefixes, and data sections are not covered by that scan.
- One `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend, at slot `0x5678ee8` in `.data.rel.ro`. The file stores 0 in that slot; the loader writes the window address at load time. So the window is referenced by a data pointer, not by a direct call.
- The two `lea` targets, `0x5676ba8` and `0x5676c20`, both live in `.data.rel.ro` and both hold file value 0. Their meanings are not claimed: they are data pointers whose contents are fixed up at load time, and no pointee is identified here.

## Inferences and unknowns

- **Inferred:** this is a tagged-pointer decision tree: the high-bit constants and the pointer-or-zero return shape support that label. The binary has no recovered symbol name here. Neither the source-level function name, the type being discriminated, the meaning of the field, nor the meaning of the two data pointers is proven.
- The single relocation slot shows the window is reachable through a data pointer, but the holder of that pointer and the call path that reaches it are not closed.
- The byte-pattern scan is not a complete xref census, so other callers through register-indirect or data paths are not excluded.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed window bytes, FDE extent, padding bytes, or branch displacements;
- changed magic constants, lea targets, or return opcodes;
- changed relocation slots or slot sections/values;
- changed incoming-scan results;
- changed decision-tree edges.

No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
