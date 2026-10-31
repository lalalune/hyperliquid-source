# foundation-nine-eight-gate-94: what does the two-condition 9/8 gate window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 28-byte FDE window, its four int3 padding bytes, the two direct call sites and their argument setup, and the exact 9/8 rule.
- Excluded: the compared values' meaning, the constants' meaning beyond their file bytes, the callers' behavior beyond their argument setup, the next FDE, other gate helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two 32-bit comparisons, two sete results ANDed, 9 minus that bit, no calls, no branches at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5229860`, no open pull request title mentions it or nine-eight-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, or nonzero-below packets.

This window is bound **alone**. No census of similar windows is claimed.

## Correction against the build brief

The build brief's draft instruction sequence (mov $0x9 first, sete %cl, and %cl,%dil, and so on) and its draft caller list (0x516bd6d, 0x52c8d04) do **not** match the retained bytes. The verified sequence is cmp $0x1,%esi; sete %al; xor %edx,%edx; cmp $0x4,%edi; sete %dl; and %eax,%edx; mov $0x9,%eax; sub %edx,%eax; ret, and the verified direct callers are 0x5154497 and 0x5154726, both inside FDE 0x5154460. The round-7 scout note's sequence and caller list verified exactly. The checker locks the verified bytes, not the draft.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_nine_eight_gate.py --check research/work-items/foundation-nine-eight-gate-94/evidence.json
python3 -m unittest tests.test_foundation_nine_eight_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5229860 --stop-address=0x5229880 artifacts/node/94/hl-node
objdump -d --start-address=0x5154460 --stop-address=0x51547cd artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains complete disassembly of the caller FDE. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2a48e4`, the next FDE at `0x2a48f8`, and the caller FDE at `0x6347c8`. The checker locks the window FDE records and their CIE raw bytes, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value). It decodes the caller FDE's PC/range by scanning records rather than locking its long raw bytes. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x2a48e4` describes `[0x5229860, 0x522987c)`, 28 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x522987b` is inside the FDE).
- The unwind index stride to the next entry is 32 bytes, ending at `0x5229880`, only because four `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "32-byte FDE-bounded" would overstate the frame by those four padding bytes, and the checker locks the 28-byte body and the padding separately. The next FDE starts exactly at `0x5229880` (range 11 bytes to `0x522988b`).
- No relocation record of any type in any `.rela.*` section names this window as addend (full readelf -r scan).

### Instruction sequence

Offsets are relative to the FDE start `0x5229860`:

| Offset | Bytes | Instruction |
| ------ | ----- | ----------- |
| 0x00 | `f3 0f 1e fa` | `endbr64` |
| 0x04 | `83 fe 01` | `cmp $0x1,%esi` — first condition, low 32 bits |
| 0x07 | `0f 94 c0` | `sete %al` — 1 iff esi == 1 |
| 0x0a | `31 d2` | `xor %edx,%edx` — clear the second accumulator |
| 0x0c | `83 ff 04` | `cmp $0x4,%edi` — second condition, low 32 bits |
| 0x0f | `0f 94 c2` | `sete %dl` — 1 iff edi == 4 |
| 0x12 | `21 c2` | `and %eax,%edx` — 1 iff both conditions hold |
| 0x14 | `b8 09 00 00 00` | `mov $0x9,%eax` — also zeroes the upper bits of eax |
| 0x19 | `29 d0` | `sub %edx,%eax` — 9 minus the AND bit |
| 0x1b | `c3` | `ret` |

### The decoded rule

Return **8** only when both conditions hold, else **9**:

- (esi == 1) && (edi == 4) → 8.
- Any other combination → 9.

The comparisons are 32-bit (`cmp $imm,%esi` and `cmp $imm,%edi`), so only the low 32 bits of rsi and rdi matter: rsi = 0x100000001 satisfies the first condition (low 32 bits are 1), and rdi = 0x100000004 satisfies the second. The return value is fully determined: `mov $0x9,%eax` zeroes the upper bits of eax before the subtract, so no low-byte-only caveat applies here, unlike packets #27/#32.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly two direct `e8` call sites, each confirmed as an instruction start by linear disassembly from the caller FDE start, explicitly not a complete xref census. Both sit inside the single caller FDE `0x5154460..0x51547cd`:

- `0x5154497` (`e8 c4 53 0d 00`): preceded at `0x5154482` by `xor %esi,%esi`, with no esi modification before the call, so esi = 0, the first condition is false, and this call returns 9 regardless of edi.
- `0x5154726` (`e8 35 51 0d 00`): immediately preceded by `mov $0x1,%esi` and `mov $0x4,%edi`, so both conditions hold and this call returns 8.

Caller purpose beyond these call sites and argument setups is not claimed.

### Relation to the classifier windows

The constant 9 coincides with the classifier windows' output byte 0, but this window returns 9/8 in eax from two integer comparisons — a different mechanism, and no connection to packets #15/#25 is claimed.

## Inferences

- The "two-condition 9/8 gate" label is an inference from the observed instruction shape (two comparisons, two sete results, AND, 9 minus bit). It is kept separate from the observed rule above.
- Nothing else is inferred: no source-level function, no value meaning, no constant meaning, no caller purpose, and no component ownership are claimed.

## Unknowns

- What the two compared values represent, why the constants are 1 and 4 and the base is 9, and whether any caller reaches this window through a register-indirect or data path the byte-pattern scan cannot see.
- The next FDE at `0x5229880` (11 bytes) is a different window and is not analyzed here.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of other direct callers does not prove the window is unreachable by other paths.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
