# foundation-dual-zero-94: what does the dual-zero test window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 32-byte FDE window, its zero padding (there is none — the next FDE starts exactly at the window end), the single naming relocation, the zero direct call sites, and the exact dual-zero rule.
- Excluded: the compared fields' meaning, the pointer's provenance, any caller behavior, the next FDE, other gate helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a pointer dereference, two 64-bit zero comparisons, one conditional branch to the return, one sete — no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5341920`, no open pull request title mentions it or dual-zero, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, or nine-eight-gate packets.

This window is bound **alone**. No census of similar windows is claimed.

## No scout correction needed

Every element of the round-7 scout note verified exactly from the retained bytes: the FDE range, the zero padding, all eight instructions, both field offsets, zero direct callers, and the RELATIVE slot 0x5762a78 with file value 0. The checker locks the verified bytes.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_dual_zero.py --check research/work-items/foundation-dual-zero-94/evidence.json
python3 -m unittest tests.test_foundation_dual_zero -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5341920 --stop-address=0x5341940 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window. There is intentionally no `caller.objdump.txt`: the window has zero direct callers, consistent with packets #32 and earlier zero-caller packets. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2b0904`, and the next FDE at `0x2b0918`. The checker locks the window FDE records and their CIE raw bytes, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value).
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x2b0904` describes `[0x5341920, 0x5341940)`, 32 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x534193f` is inside the FDE).
- Padding is **zero bytes**: the next FDE starts exactly at `0x5341940` (range 81 bytes to `0x5341991`). There is no stride tail to lock, and the checker pins this by locking the next FDE's record at section offset `0x2b0918` with PC/range `0x5341940..0x5341991`. Any description of this window as padded would overstate the frame.
- The single naming relocation is described below; it is a data-pointer reference, not a call edge.

### Instruction sequence

Offsets are relative to the FDE start `0x5341920`:

| Offset | Bytes | Instruction |
| ------ | ----- | ----------- |
| 0x00 | `f3 0f 1e fa` | `endbr64` |
| 0x04 | `48 8b 57 08` | `mov 0x8(%rdi),%rdx` — pointer load |
| 0x08 | `31 c0` | `xor %eax,%eax` — result starts at 0 |
| 0x0a | `48 83 ba 28 09 00 00 00` | `cmpq $0x0,0x928(%rdx)` — first field, full 64 bits |
| 0x12 | `75 0b` | `jne 0x534193f` — first field nonzero → ret with eax still 0 |
| 0x14 | `48 83 ba 48 09 00 00 00` | `cmpq $0x0,0x948(%rdx)` — second field, full 64 bits |
| 0x1c | `0f 94 c0` | `sete %al` — 1 iff second field is zero |
| 0x1f | `c3` | `ret` |

### The decoded rule

Return **1** iff both 64-bit fields are zero, else **0**:

- (`*(rdx+0x928)` == 0) && (`*(rdx+0x948)` == 0) → 1.
- Any other combination → 0.

The comparisons are 64-bit (`cmpq`), so the full field values matter: any nonzero bit in either field makes the result 0 — there is no low-32-bit subtlety here. The return value is fully determined: `xor %eax,%eax` zeroes all of eax before both comparisons, so no low-byte-only caveat applies here, unlike packets #27/#32. The branch target `0x534193f` is the `ret` itself, so the first-nonzero path returns 0 without touching eax again.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` call sites — explicitly not a complete xref census. The window may still be reached through a data-pointer path (see below) or a register-indirect call the scan cannot see; neither is claimed.

### Data edge

Exactly one relocation record in any `.rela.*` section names this window as addend: `R_X86_64_RELATIVE` (type 8) in `.rela.dyn`, at slot `0x5762a78` in `.data.rel.ro`, with file value 0 (applied only at load time). That is a data-pointer reference to the window, not a direct call, and it does not identify the window's provenance.

## Inferences

- The "dual-zero test" label is an inference from the observed instruction shape (pointer load, two zero comparisons, one branch, one sete). It is kept separate from the observed rule above.
- Nothing else is inferred: no source-level function, no field meaning, no pointer provenance, no caller purpose, and no component ownership are claimed.

## Unknowns

- What the two compared fields represent, what structure the loaded pointer points to, and whether any caller reaches this window through a register-indirect or data path the byte-pattern scan cannot see.
- The next FDE at `0x5341940` (81 bytes) is a different window and is not analyzed here.

## Limits

- The byte-pattern scan is not a complete xref census, and the absence of direct callers does not prove the window is unreachable by other paths.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94.
