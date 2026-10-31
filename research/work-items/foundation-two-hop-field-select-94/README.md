# foundation-two-hop-field-select-94: what does the 40-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 40-byte FDE window, its zero padding, the two-hop field-select rule, the two confirmed callers, the no-naming-relocation scan, and the two-direct-caller scan.
- Excluded: the meaning of the struct fields, the meaning of the loaded values, the callers' behavior beyond the call itself, other field-select helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: ten instructions, no calls inside, one null test, and a rule fully determined by two loads and one fallback load. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5361710`, no open pull request title mentions it or two-hop-field-select, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_two_hop_field_select.py --check research/work-items/foundation-two-hop-field-select-94/evidence.json
python3 -m unittest tests.test_foundation_two_hop_field_select -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5361710 --stop-address=0x5361738 artifacts/node/94/hl-node
objdump -d --start-address=0x5380f50 --stop-address=0x53814d0 artifacts/node/94/hl-node
objdump -d --start-address=0x53825f0 --stop-address=0x5382c46 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window. The `caller.objdump.txt` file retains complete disassembly of both confirmed caller FDEs. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x2b2a18`, the next FDE at `0x65342c`, and the caller FDEs at `0x654500` and `0x65466c`. The checker locks these raw FDE records and their shared CIEs, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000` (segment VA base `0x1343c80`, file offset base `0x1342c80`); the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2b2a18` describes `[0x5361710, 0x5361738)`, 40 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5361737` is inside the FDE).
- The padding is exactly 0 bytes: the next FDE starts immediately at `0x5361738` (`[0x5361738, 0x53617d6)`, 0x9e bytes); the checker locks its PC/range, and its full record is retained in `frames.txt`. There is no int3 stride to lock, and any description of this window with a stride larger than 40 bytes would overstate the frame.
- The window opens with `endbr64` (an observation, not a scout deviation).

### Body behavior: two hops, one null test, no calls

Decoded from the FDE start, the window takes a struct pointer in `rdi`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5361710` | `endbr64` | Entry marker |
| `0x5361714` | `mov 0x8(%rdi),%rdx` | First hop: p = [rdi+0x8] |
| `0x5361718` | `mov 0x1e0(%rdx),%rax` | Second hop: q = [p+0x1e0] |
| `0x536171f` | `test %rax,%rax` | Null test on q |
| `0x5361722` | `je 0x5361730` | q == 0 → fallback load |
| `0x5361724` | `mov 0x8(%rax),%rax` | Nonzero path: return [q+0x8] |
| `0x5361728` | `ret` | |
| `0x5361729` | 7-byte `nopl 0x0(%rax)` | Unreachable alignment padding: it follows a `ret`, is targeted by no branch (the `je` at `0x5361722` lands directly on `0x5361730`), and is locked as body bytes, not an executed instruction |
| `0x5361730` | `mov 0x178(%rdx),%rax` | Fallback path: return [p+0x178] |
| `0x5361737` | `ret` | |

Rule:

- p = [rdi+0x8]; q = [p+0x1e0]; if q != 0 return [q+0x8]; else return [p+0x178].
- The result is a qword load in both paths; no register other than `rax`/`rdx` is written, and the window contains no calls.

### No scout correction needed

Every scouted element verified exactly: FDE range, 40-byte body, 0 padding bytes, both callers and their FDE ranges, no naming relocation, nearest claimed window. The scout's caller FDE ends match the frame records exactly (unlike the next-FDE-start pattern seen in packets #50/#51/#53/#55, no precision note applies here).

### Incoming calls: two direct callers, boundary-confirmed

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly two direct `e8` sites — `0x5380fb7` (bytes `e8 54 07 fe ff`) and `0x538265a` (bytes `e8 b1 f0 fd ff`) — each confirmed as an instruction start by linear disassembly from its caller FDE start (`0x5380f50..0x53814d0` and `0x53825f0..0x5382c46` respectively). This is explicitly not a complete xref census. Caller purpose and argument setup beyond the call itself are not claimed.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan of `.rela.dyn` and `.rela.plt`, counts locked in the checker). The absence of a naming relocation does not identify the window's provenance.

### Symbol hint, explicitly disclaimed

objdump annotates the address with a nearest preceding `ctype` `do_widen` symbol `0x3b9910` bytes below; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

### Nearest claimed window

Dual-zero test `0x5341920` (packet #36), `0x1fdf0` away; nothing in `0x53617xx` claimed.

## Inferences

- The "two-hop field select" label is an inference from the observed rule (two pointer hops, then a field load chosen by a null test). It is kept separate from the rule itself.
- No field meaning is inferred: what the structs at `rdi`, `p`, and `q` are, and what the loaded qwords represent, are unknown.

## Unknowns

- What the input struct represents, what the loaded values mean, and what the callers do with the result.
- Whether other callers reach the window indirectly (the scan covers direct `e8` sites only).
- The window's source-level name, type, and component ownership.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- The rule is stated for the window's own bytes; the fallback load reads from `p`, which the window itself loaded, so a null `p` would fault — but no null-`p` guard exists in the bytes, and no behavior is claimed for that input beyond what the instructions say.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
