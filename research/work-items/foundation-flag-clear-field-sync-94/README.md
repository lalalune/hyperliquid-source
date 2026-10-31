# foundation-flag-clear-field-sync-94: what does the flag-clear plus field sync window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data edges; its source-level name and types remain inferences.
- Included: the 32-byte FDE window with zero padding bytes, the flag-clear plus field-sync rule it implements, the exact incoming-call scan result (two direct sites in two caller FDEs), and the absence of any relocation naming the window.
- Excluded: the meaning of the struct fields, the identity or purpose of the callers, whether the two effects belong to one operation, and any wider sync family; target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity conversion helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one previously unclaimed window whose behavior reads directly from its own bytes: a flag qword is cleared when nonzero, then one struct field is synced from another when they differ. It establishes a concrete entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5172fa0`, no open pull request title mentions it or flag-clear-field-sync, and its bytes overlap nothing in packets #1–#79.

## Scout note

The round-12 scout note listed this window (ranked #3) with FDE `[0x5172fa0, 0x5172fc0)`, 32 bytes, 0 padding bytes, two direct callers both boundary-confirmed, and no naming relocation. Every element verified exactly, including the zero-padding boundary (the next FDE starts exactly at `0x5172fc0`) and the nearest claimed window (tiny two-byte gate `0x51647b0`, packet #72, `0xe7f0` away). No numeric correction to the scout's numbers was needed. One phrasing point is reconciled explicitly: the scout's "zero calls" describes the window body (no call opcode inside it), while the two direct sites are incoming calls from two caller FDEs — the two statements are about different directions and do not conflict.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_flag_clear_field_sync.py --check research/work-items/foundation-flag-clear-field-sync-94/evidence.json
python3 -m unittest tests.test_foundation_flag_clear_field_sync -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5172fa0 --stop-address=0x5172fc0 artifacts/node/94/hl-node
objdump -d --start-address=0x5173ffc --stop-address=0x517402b artifacts/node/94/hl-node
objdump -d --start-address=0x517620e --stop-address=0x5176342 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window (zero padding bytes follow it). The `caller.objdump.txt` file retains complete disassembly of both caller FDEs, from which the two call sites were confirmed as instruction starts. The `frames.txt` file retains excerpts selecting the FDEs at `.eh_frame` section offsets `0x29c56c` (this window), `0x63632c` (the next FDE), `0x636418` and `0x636574` (the two caller FDEs), plus the shared CIEs at offsets `0` and `0x6205d0`. The checker locks these raw FDE records and their CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offset and VA. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x29c56c` describes `[0x5172fa0, 0x5172fc0)`, 32 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint.
- Zero `int3` bytes follow: the next FDE starts exactly at `0x5172fc0` (record at `.eh_frame+0x63632c`, range to `0x517379c`). The unwind-index stride is therefore 32 bytes; the stride is not the FDE extent, and the checker locks the body and the zero-padding boundary separately (the NEXT record lock pins the next FDE's PC to the body end).
- The window opens with `endbr64` (an observation, not a scout deviation).
- GNU objdump prints this window under a nearest-symbol label with a `0x1cb1a0`-byte offset; that is stripped-binary arithmetic, not an identity, and no source-level function is claimed from it.

### Body behavior: flag-clear plus field sync, no calls, two forward branches

Inputs: `rdi` = struct pointer. Fields read and written: flag qword at `[rdi]`, source qword at `[rdi+0x50]`, destination qword at `[rdi+0x58]`. Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5172fa0` | `endbr64` | Landing pad |
| `0x5172fa4` | `cmpq $0x0,(%rdi)` | Flag-zero test |
| `0x5172fa8` | `je 0x5172fb1` | Flag zero → skip the clear |
| `0x5172faa` | `movq $0x0,(%rdi)` | Clear the flag qword |
| `0x5172fb1` | `mov 0x50(%rdi),%rax` | Load the source field |
| `0x5172fb5` | `cmp 0x58(%rdi),%rax` | Compare source against destination |
| `0x5172fb9` | `je 0x5172fbf` | Equal → skip the sync |
| `0x5172fbb` | `mov %rax,0x58(%rdi)` | Sync the destination field |
| `0x5172fbf` | `ret` | |

Rule: if qword `[rdi]` is nonzero, set it to 0. Then load qword `[rdi+0x50]`; if it differs from qword `[rdi+0x58]`, set `[rdi+0x58]` to it. At `ret`, `rax` holds the loaded `[rdi+0x50]` value on both paths (an observed register state, not a claimed return contract — the callers' use of it is not claimed).

Worked edges: flag 0, source 5, dest 5 → no change, rax 5; flag 7, source 5, dest 5 → flag cleared only, rax 5; flag 7, source 5, dest 3 → flag cleared and dest synced to 5, rax 5; flag 0, source 5, dest 3 → sync only, rax 5; flag all-ones, source 0, dest 0 → flag cleared, rax 0; flag 3, source 0, dest 9 → flag cleared and dest synced to 0, rax 0; flag 0, source 9, dest 0 → dest synced to 9, rax 9.

### Incoming calls: two direct sites, not a census

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly two direct `e8` sites whose rel32 lands on the window start:

| Site | Caller FDE | Setup immediately before the call |
| --- | --- | --- |
| `0x5174001` (bytes `e8 9a ef ff ff`) | `[0x5173ffc, 0x517402b)` | `lea 0x10(%rsp),%rdi` |
| `0x5176259` (bytes `e8 42 cd ff ff`) | `[0x517620e, 0x5176342)` | `mov -0x310(%rbp),%rdi` |

Each site was confirmed as an instruction start by linear disassembly from its caller FDE start. This is explicitly not a complete xref census: indirect calls, tail jumps, and PLT references are out of scope for the scan. Caller purpose is not claimed; the setups are locked as bytes only.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan: 80,022 `.rela.dyn` + 278 `.rela.plt` entries). The absence of a naming relocation does not identify the window's provenance.

## Inferences

- The window is labeled "flag-clear plus field sync" for convenience. The label is an inference from the observed operations, kept separate from the rule above.
- The two effects are not claimed to belong to one operation: nothing in the bytes links the flag qword to the synced fields, and the README states this weakness head-on rather than smoothing it over.

## Unknowns

- What the struct is, what the flag qword guards, and what the two synced fields mean.
- What the callers do with the struct after the call, and whether they read `rax` at `ret`.
- Whether any indirect caller or tail-jump entrant reaches this window beyond the two direct sites found.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
