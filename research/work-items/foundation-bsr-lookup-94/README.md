# foundation-bsr-lookup-94: what does the bsr-indexed table lookup compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 59-byte FDE window, its 5 int3 padding bytes, the zero naming relocations, the single direct call site, and the exact bsr-indexed lookup rule.
- Excluded: the fields' meaning, the base pointer's provenance, the table's contents and meaning, any caller behavior beyond call site and argument setup, the next FDE, other bsr or table-lookup helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two field loads from the same base, two guarded branches, one bsr, one indexed table load, no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x55442e0`, no open pull request title mentions it or bsr-lookup, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, dual-zero, conditional-reduction, multiply-subtract, field-walk-shift, pair-load, or field-inequality packets.

This window is bound **alone**. No census of similar windows is claimed.

## No scout correction needed

Every scouted element verified exactly: the FDE range, the 59-byte body, all instructions, the single direct call site, and no naming relocation. One precision note about an elided instruction, not a correction to any scouted byte: the scout summary described the bsr tail as "rcx += esi; rsi = *(rdi + 0x1088 + rcx*8)". The retained bytes add `mov %ecx,%edx` between the add and the load, so the load itself reads `*(rdi + 0x1088 + rdx*8)`. Because the index is at most 127, the 32-bit copy zero-extends to the same value, and the rule is unchanged; the checker locks the mov and the rdx-indexed load exactly as retained.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_bsr_lookup.py --check research/work-items/foundation-bsr-lookup-94/evidence.json
python3 -m unittest tests.test_foundation_bsr_lookup -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x55442e0 --stop-address=0x5544320 artifacts/node/94/hl-node
objdump -d --start-address=0x5522780 --stop-address=0x5522960 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains linear disassembly from the caller FDE start through its call site. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2cd9e8`, the next FDE at `0x2cd9fc`, and the caller FDE at `0x2c94a0`. The checker locks the window FDE record and its CIE raw bytes, reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value), and locks the next FDE record's raw bytes with its GNU-decoded range.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and stride

- `.eh_frame+0x2cd9e8` describes `[0x55442e0, 0x554431b)`, 59 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x554431a` is inside the FDE).
- The stride to the next FDE at `0x5544320` is 5 int3 bytes (`cc` × 5) from `0x554431b` to `0x5544320`, where the next FDE starts (range 0xc bytes to `0x554432c`). The checker locks body and padding separately; stride is not the FDE extent.

### Instruction walk

All offsets are relative to the FDE start `0x55442e0`:

1. `endbr64` (bytes 0–3).
2. `mov 0x1490(%rdi),%rax` (bytes 4–10): `a = *(rdi + 0x1490)`.
3. `test %rax,%rax` (bytes 11–13).
4. `jne 0x5544302` (bytes 14–15): if `a != 0`, go to step 10.
5. `mov 0x1488(%rdi),%rax` (bytes 16–22): `a = *(rdi + 0x1488)`.
6. `xor %esi,%esi` (bytes 23–24): index bias = 0.
7. `test %rax,%rax` (bytes 25–27).
8. `jne 0x5544307` (bytes 28–29): if `a != 0`, go to step 11.
9. `mov %rsi,%rax` (bytes 30–32) then `ret` (byte 33): both fields zero, so return 0 (esi was xor'd to 0, so the full rax is 0).
10. `mov $0x40,%esi` (bytes 34–38): index bias = 64; falls through to step 11.
11. `bsr %rax,%rcx` (bytes 39–42): `rcx` = index of the highest set bit of `a`, 0..63. Both paths guard `a != 0` before reaching bsr, so the undefined bsr(0) case is never taken by the retained bytes.
12. `add %esi,%ecx` (bytes 43–44): `rcx += bias` (64 or 0).
13. `mov %ecx,%edx` (bytes 45–46): copy the index into edx; the copy zero-extends, and the index is at most 127, so the value is unchanged.
14. `mov 0x1088(%rdi,%rdx,8),%rsi` (bytes 47–54): `rsi = *(rdi + 0x1088 + index*8)`.
15. `mov %rsi,%rax` (bytes 55–57) then `ret` (byte 58): return the table entry.

### Rule

```
if *(rdi + 0x1490) != 0: return *(rdi + 0x1088 + (bsr(*(rdi + 0x1490)) + 64)*8)
elif *(rdi + 0x1488) != 0: return *(rdi + 0x1088 + bsr(*(rdi + 0x1488))*8)
else: return 0
```

No store, no call. The return value is fully determined (rax is loaded from rsi in both return paths, not a setcc byte), so no low-byte-only caveat applies here, unlike packets #27 and #32. The table base is `rdi + 0x1088` and the entry size is 8 bytes; the table's contents and meaning are not claimed.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` call site — `0x5522959` (call bytes `e8 82 19 02 00`, target `0x55442e0`), confirmed as an instruction start by linear disassembly from its caller FDE start (`0x5522780..0x5522d66`). The scan is explicitly not a complete xref census. Caller purpose beyond call site is not claimed.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan).

## Inferences

- The "bsr-indexed table lookup" label is an inference from the instruction shape: two field loads, guarded branches, a bsr, and an indexed load. It is kept separate from the observed rule above.
- The two fields and the table may be parts of one structure addressed from rdi, but no field meaning, table meaning, or structure layout is claimed.
- The single caller may pass a base pointer in rdi; its argument setup beyond the call site is not analyzed here.

## Unknowns

- What the two fields and the table entries mean, and what source-level function or type this window belongs to.
- Whether any indirect or PLT-mediated caller exists; the byte-pattern scan covers direct `e8` sites only.
- The provenance of the window (stdlib, crate, or private helper); the absence of a naming relocation does not identify it.

## Limits

- No stdlib type, source-level function, field meaning, table meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
