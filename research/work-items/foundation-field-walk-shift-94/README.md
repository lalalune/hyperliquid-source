# foundation-field-walk-shift-94: what does the field-walk shift store window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 42-byte FDE window, its 6 int3 padding bytes, the absence of any naming relocation, the zero direct call sites, and the exact field-walk shift-store rule.
- Excluded: the walked fields' meaning, the pointers' provenance, any caller behavior, the next FDE, other shift-store helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two pointer loads, two field loads from the same walked base, one subtraction, one arithmetic shift, one store, and a constant return — no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x514ab20`, no open pull request title mentions it or field-walk-shift, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, dual-zero, conditional-reduction, or multiply-subtract packets.

This window is bound **alone**. No census of similar windows is claimed.

## No scout correction needed

Every element of the round-7 scout note verified exactly from the retained bytes: the FDE range, the 42-byte body, all nine instructions, zero direct callers, and no naming relocation. The checker locks the verified bytes. Two precision notes, stated so the scout shorthand cannot be misread: the subtraction is of two loaded values (both read from the same walked base `*(rdi+0x788)+0x30`), not a difference of pointers; and the shift is arithmetic (`sar`), so a negative difference sign-extends rather than zero-filling.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_field_walk_shift.py --check research/work-items/foundation-field-walk-shift-94/evidence.json
python3 -m unittest tests.test_foundation_field_walk_shift -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x514ab20 --stop-address=0x514ab50 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window. There is intentionally no `caller.objdump.txt`: the window has zero direct callers, consistent with packets #32 and #36. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x29a0b0`, and the next FDE at `0x29a0c4`. The checker locks the window FDE records and their CIE raw bytes, and reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value).
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and padding

- `.eh_frame+0x29a0b0` describes `[0x514ab20, 0x514ab4a)`, 42 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x514ab49` is inside the FDE).
- Padding is **6 int3 bytes** (`cc` × 6) from `0x514ab4a` to the 48-byte stride end `0x514ab50`, where the next FDE starts (range 20 bytes to `0x514ab64`). The checker locks the body and the padding separately; stride is not the FDE extent.
- The next FDE at `0x514ab50` is a different window (a `movslq` field load with the same store-and-return-1 tail shape). It is not analyzed, not claimed, and no shared routine is inferred from the adjacent tail shape.

### Instruction walk

All offsets are relative to the FDE start `0x514ab20`:

1. `endbr64` (bytes 0–3).
2. `mov 0x788(%rdi),%rax` (bytes 4–10): `p = *(rdi + 0x788)`.
3. `mov 0x30(%rax),%rdx` (bytes 11–14): `q = *(p + 0x30)`.
4. `mov 0xb20(%rdx),%rax` (bytes 15–21): `a = *(q + 0xb20)`.
5. `sub 0xb18(%rdx),%rax` (bytes 22–28): `rax = a - *(q + 0xb18)`. Both operands are loaded values from the same base `q`; this is not a pointer difference.
6. `sar $0x4,%rax` (bytes 29–32): arithmetic shift right by 4. The difference is treated as signed 64-bit, so a negative difference sign-extends.
7. `mov %rax,(%rsi)` (bytes 33–35): store the shifted difference through `rsi`.
8. `mov $0x1,%eax` (bytes 36–40) and `ret` (byte 41): the window always returns 1, regardless of the stored value.

### Rule

```
q = *(*(rdi + 0x788) + 0x30)
*(rsi) = (int64)(*(q + 0xb20) - *(q + 0xb18)) >> 4   (arithmetic, wrapping mod 2^64)
return 1
```

Edge cases, restated from the bytes (not executed): a difference of `0x100` stores `0x10`; a difference of `1` stores `0` (shifted out); a difference of `-16` stores `-1` (all-ones, sign extension); a difference of `0` stores `0`. The subtraction wraps modulo 2^64 before the signed shift.

### Call and data edges

- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` call sites — explicitly not a complete xref census.
- Data edge: no relocation record of any type in any `.rela.*` section names this window as addend (full-section scan). The absence of a naming relocation does not identify the window's provenance.

## Inferences vs unknowns

- Inference: the label "field-walk shift store" describes the observed two-load chain, subtraction, shift, and store; it is not a source-level name.
- Unknown: what the walked structure, the two fields, and the shifted difference mean; what calls this window indirectly (if anything); whether the store destination `rsi` points to a caller field or a fresh out-parameter.
- Not claimed: any stdlib type, any caller purpose, any component mapping beyond this single window.

## Limits

- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
