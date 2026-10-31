# foundation-byte-indexed-dual-load-94: what does the 29-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 29-byte FDE window, its three int3 padding bytes, the byte-indexed dual-load rule, the readable table-A head, the single naming relocation, the table-B load-time caveat, and the zero-direct-caller scan.
- Excluded: the meaning of the index byte, the meaning of either table, table-B runtime contents, the purpose of the naming slot, the caller's behavior (there is no direct caller), other indexed-load helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: seven instructions, no calls, no branches, and a rule fully determined by one byte load and two indexed qword loads. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x4e48600`, no open pull request title mentions it or byte-indexed-dual-load, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_byte_indexed_dual_load.py --check research/work-items/foundation-byte-indexed-dual-load-94/evidence.json
python3 -m unittest tests.test_foundation_byte_indexed_dual_load -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x4e48600 --stop-address=0x4e48620 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. There is no caller file: the incoming scan finds zero direct calls, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x274aec` and the next FDE at `0x274b00`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000` (segment VA base `0x1343c80`, file offset base `0x1342c80`); the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x274aec` describes `[0x4e48600, 0x4e4861d)`, 29 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x4e4861c` is inside the FDE).
- The unwind index stride to the next entry is 32 bytes, ending at `0x4e48620`, only because three `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "32-byte FDE-bounded" would overstate the frame by those three padding bytes, and the checker locks the 29-byte body and the padding separately.
- The next FDE starts exactly at `0x4e48620` (`[0x4e48620, 0x4e48824)`, 0x204 bytes); the checker locks its PC/range, and its full record is retained in `frames.txt`.

### Body behavior: one byte load, two indexed qword loads, no calls, no branches

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x4e48600` | `movzbl (%rdi),%eax` | Index byte, zero-extended |
| `0x4e48603` | `shl $0x3,%eax` | Scale index by 8 (qword entries) |
| `0x4e48606` | `lea -0x4687215(%rip),%rcx` | Table A base `0x7c13f8` (`.rodata`) |
| `0x4e4860d` | `mov (%rax,%rcx,1),%rdx` | `rdx = tableA[index]` |
| `0x4e48611` | `lea 0x901678(%rip),%rcx` | Table B base `0x5749c90` (`.data.rel.ro`) |
| `0x4e48618` | `mov (%rax,%rcx,1),%rax` | `rax = tableB[index]` |
| `0x4e4861c` | `ret` | |

The rule is therefore `i = movzbl [rdi]; rdx = tableA[i]; rax = tableB[i]`, with 8-byte entries and the index scaled by 8. There are no branches and no calls: the window is straight-line. The window opens directly with the byte load — no `endbr64` (an observation, not a scout deviation).

Table A is file-readable in `.rodata`; its first twelve entries are `8, 9, 3, 9, 14, 9, 14, 10, 8, 11, 6, 6`, and the checker locks them. Table B is not file-readable in any usable sense: its first eight file entries are all zero, and 127 `R_X86_64_RELATIVE` relocations target slots within its 256-entry range, so its runtime contents are load-time values that cannot be recovered from the file alone. No table-B content is claimed anywhere in this packet.

### Data edge: one naming relocation, plus a load-time table

The full `.rela.*` scan (80,022 `.rela.dyn` + 278 `.rela.plt` entries) finds exactly one record naming this window as addend: `R_X86_64_RELATIVE` at slot `0x57494c0` in `.data.rel.ro` (VA range `[0x56632a0, 0x576d770)`). It is a single naming slot, not a pointer table, and nothing about its purpose or owner is claimed. The checker locks exactly this one slot: any added, removed, or retyped slot fails the check.

Separately, the 127 `R_X86_64_RELATIVE` relocations landing in the table-B range are the reason table-B contents are unclaimable: they overwrite file zeros with loader-resolved values. The checker locks the count (127), not any content.

### Call edge: zero direct callers

The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds zero direct `e8` calls to this window. Register-indirect references, other pointer paths (including the single naming slot above, which is data, not a call), prefixes, and data sections are not a complete xref census, so indirect reachability is neither claimed nor excluded.

### Symbol hint, explicitly disclaimed

GNU objdump annotates the window's address with the nearest preceding symbol, a `ctype` `do_widen` label 0x15f800 bytes below. A nearest-symbol annotation at that distance proves nothing about provenance: no stdlib or private origin is claimed either way, and the label is not used as evidence anywhere in this packet.

### Scout notes

One scout correction, on the table-A head: the round-10 note listed table-A entries as "8, 9, 3, 9, 14, 14, 10, …". The exact file sequence is `8, 9, 3, 9, 14, 9, 14, 10, 8, 11, 6, 6, …` — the scout shorthand omitted the 9 at index 5. The checker locks the exact twelve entries above. All other scouted elements verified exactly (FDE range, 29-byte body, three padding bytes, both table bases, zero direct callers, one naming relocation, table-B file zeros).

### Nearest claimed window

The nearest previously claimed window is the double threshold gate at `0x5028a40` (packet #32), `0x1e0440` away; nothing in `0x4e486xx` is claimed.

## Inferences

- The "byte-indexed dual qword load" label is an inference from the two indexed-load shape; it is not a source-level name.
- Table A and table B are described as tables only because the window indexes two qword arrays by the same scaled byte; what either table maps is unknown.
- The single RELATIVE slot is described as a naming slot only because it is the sole relocation record naming this window; what names it, if anything, is unknown.

## Unknowns

- What the index byte represents, and what either table's entries mean.
- Table-B runtime contents (load-time values, unrecoverable from the file).
- Whether any caller reaches this window indirectly, and what the naming slot belongs to.
- The source-level function, type, or component this window belongs to.

## Limits

- No stdlib type, source-level function, table meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the single naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
