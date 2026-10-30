# foundation-tzcnt-gate-94: what does the two-argument tzcnt-gate window dispatch?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 39-byte FDE window, its nine int3 padding bytes, the two dispatch slots and their relocation records, the one incoming GOT slot naming the window, the endbr64 prefixes of the two slot targets, the zero-direct-caller scan result, and the exact dispatch formula over the input domain.
- Excluded: the callee bodies at `0x54c06b0` and `0x54c2670`, caller attribution beyond the pattern scan, other tzcnt/gate windows, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose dispatch reads directly from its own bytes: two unsigned comparisons, one tzcnt test, and two GOT-slot jumps. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x14bf180`, no open pull request title mentions it or tzcnt-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk-168, drop-thunk-240, drop-thunk-104, keyword-classifier, unsigned-clamp, flag-or, or tagged-pointer packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_tzcnt_gate.py --check research/work-items/foundation-tzcnt-gate-94/evidence.json
python3 -m unittest tests.test_foundation_tzcnt_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x14bf180 --stop-address=0x14bf1b0 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0` and the FDEs at offsets `0xe49c` (this window) and `0xe4b0` (the next window). The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no label is claimed below.

### Entry, FDE extent, and padding

- `.eh_frame+0xe49c` describes `[0x14bf180, 0x14bf1a7)`, 39 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the slot-A jump at `0x14bf1a1` is inside the FDE).
- The unwind index stride to the next entry is 48 bytes, ending at `0x14bf1b0`, only because nine `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "48-byte FDE-bounded" would overstate the frame by those nine padding bytes, and the checker locks the 39-byte body and the padding separately.
- One `R_X86_64_RELATIVE` record in `.rela.dyn` names this window as addend, at slot `0x576fd50` in `.got` (the file stores 0 there, applied only at load time): the window is referenced by a data pointer, not by a direct call. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds zero direct `e8` calls to the window. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.

### Body behavior: two unsigned comparisons, one tzcnt test, two slot jumps

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x14bf180` | `cmp $0x11,%rsi` | Second argument against 17 |
| `0x14bf184` | `setb %al` | al = 1 if rsi < 0x11 (unsigned), else 0 |
| `0x14bf187` | `cmp %rdi,%rsi` | Second argument against first argument |
| `0x14bf18a` | `setbe %cl` | cl = 1 if rsi <= rdi (unsigned), else 0 |
| `0x14bf18d` | `test %cl,%al` | AND of the two flag bits |
| `0x14bf18f` | `jne 0x14bf1a1` | Both true → slot-A jump |
| `0x14bf191` | `tzcnt %rsi,%rsi` | Trailing-zero count (64 for input 0) |
| `0x14bf196` | `test %rsi,%rsi` | Tzcnt-zero test |
| `0x14bf199` | `je 0x14bf1a1` | Tzcnt == 0 (rsi odd) → slot-A jump |
| `0x14bf19b` | `jmp *slot 0x576e290` | Slot B → `0x54c2670` |
| `0x14bf1a1` | `jmp *slot 0x576dfd8` | Slot A → `0x54c06b0` |

The dispatch rule, with all comparisons unsigned and all arithmetic modulo 2^64, is:

- `dispatch(rdi, rsi) = A if (rsi < 0x11 and rsi <= rdi) or tzcnt(rsi) == 0, else B`

There are no calls inside the window: no instruction start in the locked body is a call opcode.

Checked edges from the decoded rule:

| rdi | rsi | Result | Why |
| --- | --- | --- | --- |
| 0 | 0 | A | First gate: 0 < 17 and 0 <= 0 |
| 16 | 16 | A | First gate: 16 < 17 and 16 <= 16 |
| 15 | 16 | B | First gate fails (16 <= 15 false); tzcnt(16) = 4 |
| 100 | 17 | A | First gate fails (17 < 17 false); tzcnt(17) = 0 |
| 100 | 18 | B | First gate fails; tzcnt(18) = 1 |
| 5 | 3 | A | First gate: 3 < 17 and 3 <= 5 |
| 0xffffffffffffffff | 0x8000000000000000 | B | First gate fails; tzcnt(2^63) = 63 |

Note: `rsi == 0` never reaches the tzcnt branch — the first gate already takes it (0 < 0x11 and 0 <= rdi for every rdi), even though tzcnt(0) = 64 would not take the second gate.

### Data edges: two dispatch GOT slots, one incoming GOT slot, endbr64 prefixes only, no direct callers

- Slot A `0x576dfd8` is a `R_X86_64_RELATIVE` relocation in `.got` with addend `0x54c06b0`; slot B `0x576e290` is a `R_X86_64_RELATIVE` relocation in `.got` with addend `0x54c2670`. The file stores 0 in both slots, applied only at load time.
- Incoming data edge: slot `0x576fd50` in `.got` is a `R_X86_64_RELATIVE` relocation with this window as addend; the file stores 0 there, applied only at load time. This is the window's only relocation-recorded incoming edge; its referrer is not identified.
- Both slot targets live in `.text` and begin with the four bytes `f3 0f 1e fa` (`endbr64`). Their bodies are **not** decoded here by design: the packet can only say the window "dispatches to callee A vs callee B" without decoding them, and no callee contract is claimed.
- One addition beyond the scout note, verified from bytes: the incoming GOT slot `0x576fd50` naming this window (the scout note recorded only the zero-direct-caller result). Every scouted element otherwise verified exactly (FDE range, padding count, both dispatch slot targets, no direct callers).

## Inferences and unknowns

- **Inferred:** this is a two-argument tzcnt gate: its threshold constant `0x11`, order test, tzcnt test, and two-way slot dispatch support that label. The binary has no recovered symbol name here. Neither the source-level function name nor the meaning of the arguments, the threshold, or the callees is proven.
- The callee bodies at `0x54c06b0` and `0x54c2670` are not decoded; their behavior, return types, and contracts are unknown, and whether any caller drives a particular dispatch path is not closed.
- The single-window scan is not a complete xref census: register-indirect callers, data-pointer paths beyond `.rela.dyn`, and prefixed encodings are not covered.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence comparison, normalization mask, behavioral execution, or whole-ELF match is claimed. All are **not yet implemented/measured**. The raw instruction bytes in the checker are static evidence locks, not executable reconstruction or transplanted code. New checker/test/documentation code is independently authored; imported bytes and disassembly retain the artifact's original rights.

The repository's required verification, catalogue, and test recipes are run for this change below. After the change, the new checker and the new unit test pass. The added controls use the authenticated real target (explicitly skip if LFS is absent), not fabricated behavior fixtures. They reject:

- wrong identity and truncation;
- changed window bytes, FDE extent, padding bytes, or FDE/CIE records;
- changed instruction bytes, branch displacements, branch targets, or jump displacements and targets at fixed offsets;
- changed dispatch-slot relocations, slot sections, slot file values, or target sections;
- changed endbr64 prefix of either dispatch target;
- any call opcode inside the window, any direct incoming call, or any change to the relocation slot naming the window itself;
- changed dispatch edges, including the tzcnt(0) = 64 rule and the first-gate-takes-zero case.

## Limits

- No source-level function name, argument meaning, threshold meaning, or callee contract is claimed. The "two-argument tzcnt gate" label is an inference, kept separate from the observed dispatch behavior.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
