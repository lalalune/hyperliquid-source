# foundation-two-path-tail-gate-94: what does the small gate with two tail jumps do?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 42-byte FDE window, its six int3 padding bytes, four incoming direct calls with their caller FDEs and argument setup, and the exact two-path gate rule.
- Excluded: the fields' meaning, the tail targets' bodies and purposes, the callers' behavior beyond their call sites and argument setup, the next FDE, other gate helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: one byte load, two compares, two conditional jumps, two adds, two tail jumps, one return. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x1fc7780`, no open pull request title mentions it or two-path-tail-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate (#31), double-threshold, pointer-select, nonzero-and-below, 9/8-gate, dual-zero, conditional-reduction, multiply-subtract, field-walk, pair-load, field-inequality, bsr-table, multiply-mix-div61, global-clamp, two-field-byte-gate, cursor-walk, pointer-sum, three-field-tail-gate, bsr-clamp-ladder, mask-rounding, byte-remap, negate-or-zero, byte-indexed-byte-load, stack-arg-shift-sum, two-table-lookup, bsr-normalize, multi-field-store, keyword-classifier-gas, tiny-byte-store, or length-prefix-encoder packets.

This window is bound **alone**. No census of similar windows is claimed.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_two_path_tail_gate.py --check research/work-items/foundation-two-path-tail-gate-94/evidence.json
python3 -m unittest tests.test_foundation_two_path_tail_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1fc7780 --stop-address=0x1fc77b0 artifacts/node/94/hl-node
objdump -d --start-address=0x2033080 --stop-address=0x2034d5f artifacts/node/94/hl-node
objdump -d --start-address=0x2035170 --stop-address=0x2036370 artifacts/node/94/hl-node
objdump -d --start-address=0x20367d0 --stop-address=0x2037853 artifacts/node/94/hl-node
objdump -d --start-address=0x203a190 --stop-address=0x203bf6c artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains disassembly of all four caller FDEs from their starts through their call sites (`0x2033080`..`0x2034d5f`, `0x2035170`..`0x2036370`, `0x20367d0`..`0x2037853`, and `0x203a190`..`0x203bf6c`); the full caller FDEs are `[0x2033080, 0x2034eae)`, `[0x2035170, 0x2036453)`, `[0x20367d0, 0x2037936)`, and `[0x203a190, 0x203c0bb)`, and only the retained regions are claimed here. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x4a120`, the next FDE at `0x389b38`, the four caller FDEs at `0x395958`, `0x3959fc`, `0x395aa0`, and `0x395bec`, and the two tail-target FDEs at `0x383390` and `0x383cb4`. The checker locks these raw FDE records and their CIE, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value). It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x4a120` describes `[0x1fc7780, 0x1fc77aa)`, 42 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x1fc77a9` is inside the FDE; both tail jumps are inside it too).
- The unwind index stride to the next entry is 48 bytes, ending at `0x1fc77b0`, only because six `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "48-byte FDE-bounded" would overstate the frame by those six padding bytes, and the checker locks the 42-byte body and the padding separately. The next FDE starts exactly at `0x1fc77b0`.
- No relocation of any type in `.rela.dyn` or `.rela.plt` maps a slot to `0x1fc7780`, so the window has no naming relocation. The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds exactly four direct `e8` calls to the window, each subsequently visible as an instruction start in GNU disassembly from its caller FDE start. Register-indirect references, other pointer paths, prefixes, and data sections are not a complete xref census.
- The callers' argument setup is retained: each caller sets `rdi` from `r13` (`mov %r13,%rdi`) immediately before the call. Caller purpose is not claimed.

### Body behavior: one load, two compares, two adds, two tail jumps, one return

Decoded from the FDE start, the window takes a struct pointer in `rdi` and reads a byte at offset `0x15`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1fc7780` | `movzbl 0x15(%rdi),%eax` | tag = byte+0x15, zero-extended |
| `0x1fc7784` | `cmp $0x3,%eax` | Tag-three test |
| `0x1fc7787` | `je 0x1fc7797` | Tag 3 path: confirmation |
| `0x1fc7789` | `cmp $0x4,%eax` | Tag-four test |
| `0x1fc778c` | `jne 0x1fc77a9` | Other tag: return |
| `0x1fc778e` | `add $0x20,%rdi` | Tag 4 argument adjustment |
| `0x1fc7792` | `jmp 0x1fa9a90` | Tag 4 tail jump |
| `0x1fc7797` | `cmpb $0x3,0xd40(%rdi)` | Confirmation test |
| `0x1fc779e` | `jne 0x1fc77a9` | Unconfirmed: return |
| `0x1fc77a0` | `add $0x60,%rdi` | Tag 3 argument adjustment |
| `0x1fc77a4` | `jmp 0x1fabc20` | Tag 3 tail jump |
| `0x1fc77a9` | `ret` | No-jump path |

The rule, in full:

- byte+0x15 == 3 and byte+0xd40 == 3: the window tail-jumps to `0x1fabc20` with `rdi+0x60`.
- byte+0x15 == 3 but byte+0xd40 != 3: the window returns without jumping.
- byte+0x15 == 4: the window tail-jumps to `0x1fa9a90` with `rdi+0x20`, regardless of the confirmation byte.
- Any other tag byte: the window returns without jumping.

The two adds and the two targets are distinct — the paths are not merged. The window opens directly with the tag load — no `endbr64` (an observation, not a scout deviation).

The tail targets `0x1fa9a90` and `0x1fabc20` each have their own FDE (`[0x1fa9a90, 0x1fa9b3a)` and `[0x1fabc20, 0x1fabcbc)`). They are named as the tail callees and explicitly **not** decoded here; no claim is made about what they do with the adjusted argument.

### Scout verification

Every scouted element verified exactly: the FDE range, the 42-byte body, the six padding bytes, the two adds, the two tail targets, all four callers, and the absence of a naming relocation. No behavior correction was needed.

### Incoming calls

| Call site | Caller FDE | Confirmed as instruction start |
| --- | --- | --- |
| `0x2034d5a` | `[0x2033080, 0x2034eae)` | Yes, linear disassembly from FDE start |
| `0x203636b` | `[0x2035170, 0x2036453)` | Yes, linear disassembly from FDE start |
| `0x203784e` | `[0x20367d0, 0x2037936)` | Yes, linear disassembly from FDE start |
| `0x203bf67` | `[0x203a190, 0x203c0bb)` | Yes, linear disassembly from FDE start |

Each call site's 5-byte `e8` + rel32 sequence is locked by the checker, and its target resolves exactly to `0x1fc7780`.

## Inferences

- The "two-path tail gate" label is an inference from the two-compare shape feeding two distinct tail jumps. It is kept separate from the observed gate rule.
- The two tail-jump offsets (0x20 and 0x60) are struct offsets, but no field meaning is claimed for either, nor for the tag byte or the confirmation byte.

## Unknowns

- The fields' meaning, and what kind of quantity the input struct holds.
- The tail targets' behavior and what they do with the adjusted argument.
- The window's source-level name, type, and component owner.
- The callers' purpose beyond their call sites and argument setup.
- Whether any caller relies on the ret-path return value beyond the retained call sites.

## Limits

- No stdlib type, source-level function, field meaning, tail-target purpose, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
