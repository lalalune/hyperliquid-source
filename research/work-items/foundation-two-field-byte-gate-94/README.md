# foundation-two-field-byte-gate-94: what does the two-field byte gate compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 26-byte FDE window, its 6 int3 padding bytes, the single naming relocation, the zero direct call sites, and the exact byte-gate rule.
- Excluded: the fields' meaning, the base pointer's provenance, any caller behavior beyond call-site scanning, the next FDE, other byte-gate helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: two zero-extending byte loads, one conditional branch, one xor, no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x51384e0`, no open pull request title mentions it or two-field-byte-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, dual-zero, conditional-reduction, multiply-subtract, field-walk-shift, pair-load, field-inequality, bsr-lookup, multiply-mix-div61, or global-clamp packets.

This window is bound **alone**. No census of similar windows is claimed.

## No scout correction needed

Every scouted element verified exactly: the FDE range, the 26-byte body, all instructions, zero direct call sites, and the single naming relocation at slot `0x575af60` with file value 0.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_two_field_byte_gate.py --check research/work-items/foundation-two-field-byte-gate-94/evidence.json
python3 -m unittest tests.test_foundation_two_field_byte_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x51384e0 --stop-address=0x5138500 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. There is no `caller.objdump.txt` because the window has zero direct callers, consistent with packets #32/#36/#39/#40/#42. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x299888`, and the next FDE at `0x29989c`. The checker locks the window FDE record and its CIE raw bytes, reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value), and locks the next FDE record's raw bytes with its GNU-decoded range.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and stride

- `.eh_frame+0x299888` describes `[0x51384e0, 0x51384fa)`, 26 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x51384f9` is inside the FDE).
- The stride to the next FDE at `0x5138500` is 6 int3 bytes (`cc` × 6) from `0x51384fa` to `0x5138500`, where the next FDE starts (range 0x11 bytes to `0x5138511`). The checker locks body and padding separately; stride is not the FDE extent.

### Instruction walk

All offsets are relative to the FDE start `0x51384e0`:

1. `endbr64` (bytes 0–3).
2. `movzbl 0x160(%rdi),%eax` (bytes 4–10): `a = *(rdi + 0x160)`, zero-extended to 32 bits.
3. `test %al,%al` (bytes 11–12).
4. `je 0x51384f9` (bytes 13–14): if `a == 0`, go to step 7 (the `ret`), so the return value is the zero from step 2.
5. `movzbl 0x189(%rdi),%eax` (bytes 15–21): `a = *(rdi + 0x189)`, zero-extended to 32 bits.
6. `xor $0x1,%eax` (bytes 22–24): `a ^= 1` (low byte only; the upper bits were already zero from the movzbl).
7. `ret` (byte 25): return `a`.

### Rule

```
if *(rdi + 0x160) == 0: return 0
else: return *(rdi + 0x189) ^ 1
```

No store, no call. The return value is fully determined (movzbl zero-extends both bytes, so eax holds 0..255 in both paths), so no low-byte-only caveat applies here, unlike packets #27/#32. The gate byte and the value byte are independent fields of the same base pointer; their meaning is not claimed.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds zero direct `e8` call sites — explicitly not a complete xref census. Caller purpose is not claimed.

### Data edge

Exactly one relocation record in any `.rela.*` section names this window as addend: `R_X86_64_RELATIVE` (type 8) in `.rela.dyn`, at slot `0x575af60` in `.data.rel.ro`, file value 0 (applied only at load time) — a data-pointer reference, not a direct call.

## Inferences

- The "two-field byte gate" label is an inference from the instruction shape: two zero-extending byte loads, one conditional branch, one xor. It is kept separate from the observed rule above.
- The two bytes may be fields of one structure addressed from rdi, but no field meaning or structure layout is claimed.
- The naming relocation suggests the window's address is stored in a data table, but the table's contents and purpose are not analyzed here.

## Unknowns

- What the two bytes mean, and what source-level function or type this window belongs to.
- Whether any indirect or PLT-mediated caller exists; the byte-pattern scan covers direct `e8` sites only.
- The provenance of the window (stdlib, crate, or private helper); the naming relocation does not identify it.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
