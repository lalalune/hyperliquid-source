# foundation-multiply-mix-div61-94: what does the multiply-mix plus divide-by-61 store compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 87-byte FDE window, its 9 int3 padding bytes, the 64-byte .rodata lookup table, the zero naming relocations, the three direct call sites, and the exact multiply-mix plus divide-by-61 rule.
- Excluded: the fields' meaning, the base pointer's provenance, the table's meaning, any caller behavior beyond call site and argument setup, the next FDE, other mixer or division-idiom helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: a multiply-add state mix, a table lookup by the mix's top bits, a multiply, and a mulhi division idiom, with no calls at all. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5553fe0`, no open pull request title mentions it or multiply-mix-div61, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, keyword-classifier (#15), unsigned-clamp, flag-OR, tagged-pointer, tzcnt-gate, chunk-equality, error-name, tagged-copy, checked-subtract, dual-table-lookup, keyword-classifier (#25), byte-range-select, range-test, lane-reversal, xor-mixer, mask-builder, tail-gate, double-gate, pointer-select, nonzero-below, nine-eight-gate, dual-zero, conditional-reduction, multiply-subtract, field-walk-shift, pair-load, field-inequality, or bsr-lookup packets.

This window is bound **alone**. No census of similar windows is claimed.

## No scout correction needed

Every scouted element verified exactly: the FDE range, the 87-byte body, all nineteen instructions, the three direct call sites, and no naming relocation. One builder re-verification, not a correction: the scout note claimed the mulhi tail equals unsigned division by 61, citing 20,000 random values plus edges. The builder re-ran that check independently — 0 mismatches on 55,003 values (including the full 64-bit range) for the full quotient, and 0 mismatches on 20,000 realistic table-byte times sign-extended-field combinations for the stored low 32 bits — so the packet states the division rule as verified, not as scout hearsay. A precision note about the ordering, not a correction: the scout's instruction list reads the table-base lea and the field movslq after the mix add, but the retained bytes place both before the add (lea at bytes 14–20, movslq at bytes 31–34, add at bytes 35–37); the rule is unaffected, and the checker locks the retained order.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_multiply_mix_div61.py --check research/work-items/foundation-multiply-mix-div61-94/evidence.json
python3 -m unittest tests.test_foundation_multiply_mix_div61 -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5553fe0 --stop-address=0x5554040 artifacts/node/94/hl-node
objdump -d --start-address=0x5554b50 --stop-address=0x5555862 artifacts/node/94/hl-node
objdump -d --start-address=0x5555bd0 --stop-address=0x5556417 artifacts/node/94/hl-node
objdump -d --start-address=0x55566f0 --stop-address=0x5556f83 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. The `caller.objdump.txt` file retains linear disassembly from each caller FDE start through its call site. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2cefe4`, the next FDE at `0x2ceff8`, and the caller FDEs at `0x2cf138`, `0x2cf164`, and `0x2cf1cc`. The checker locks the window FDE record and its CIE raw bytes, reads their PC/range fields (initial_location is a 4-byte signed PC-relative value under the CIE's zR encoding; range is a 4-byte unsigned value), and locks the next FDE record's raw bytes with its GNU-decoded range.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`; the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

GNU objdump prints this window under a nearest-symbol label with a tens-of-megabytes offset; that is stripped-binary arithmetic, not an identity, and no symbol name is claimed for this window.

### Entry, FDE extent, and stride

- `.eh_frame+0x2cefe4` describes `[0x5553fe0, 0x5554037)`, 87 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x5554036` is inside the FDE).
- The stride to the next FDE at `0x5554040` is 9 int3 bytes (`cc` × 9) from `0x5554037` to `0x5554040`, where the next FDE starts (range 721 bytes to `0x5554311`). The checker locks body and padding separately; stride is not the FDE extent.
- Unlike most packets in this run, the window has **no endbr64**: it starts directly with `movabs`. That is retained as observed, not normalized.

### Instruction walk

All offsets are relative to the FDE start `0x5553fe0`:

1. `movabs $0x5851f42d4c957f2d,%rax` (bytes 0–9): mix multiplier C.
2. `imul (%rsi),%rax` (bytes 10–13): `rax = C * old_state` (low 64 bits).
3. `lea -0x4d52e75(%rip),%rcx` (bytes 14–20): `rcx = 0x801180`, the .rodata table base (next-instruction address `0x5553ff5` plus the signed displacement).
4. `movabs $0x14057b7ef767814f,%rdx` (bytes 21–30): mix addend D.
5. `movslq 0x4(%rdi),%r8` (bytes 31–34): `r8` = sign-extended 32-bit field at `rdi+0x4`.
6. `add %rdx,%rax` (bytes 35–37): `mixed = C * old_state + D` mod 2^64.
7. `mov %rax,(%rsi)` (bytes 38–40): `*(rsi) = mixed` — the state update is unconditional.
8. `shr $0x3a,%rax` (bytes 41–44): `idx = mixed >> 58`, 0..63.
9. `movzbl (%rcx,%rax,1),%esi` (bytes 45–48): `t = table[idx]`, a single byte.
10. `movabs $0xc9714fbcda3ac11,%rax` (bytes 49–58): division magic M.
11. `imul %r8,%rsi` (bytes 59–62): `x = t * r8` (low 64-bit product).
12. `mul %rsi` (bytes 63–65): `rdx:rax = M * x` (unsigned 128-bit product; `rdx` is the high word).
13. `mov $0x1,%eax` (bytes 66–70): return value staged early.
14. `sub %rdx,%rsi` (bytes 71–73): `rsi = x - hi`.
15. `shr $1,%rsi` (bytes 74–76): `rsi >>= 1`.
16. `add %rsi,%rdx` (bytes 77–79): `rdx = hi + (x - hi)/2`.
17. `shr $0x5,%rdx` (bytes 80–83): `rdx >>= 5`.
18. `mov %edx,(%rdi)` (bytes 84–85): `*(rdi) = (edx)`, the quotient's low 32 bits only.
19. `ret` (byte 86): return 1.

### Rule

```
mixed = (0x5851f42d4c957f2d * old_state + 0x14057b7ef767814f) mod 2^64
*(rsi) = mixed
idx = mixed >> 58
t = table_byte[0x801180 + idx]
x = (t * sign_extend_32(*(rdi + 0x4))) mod 2^64
*(rdi) = (x // 61) mod 2^32
return 1
```

The division step is the mulhi idiom of steps 12 and 14–17: with `hi = (M * x) >> 64`, the quotient is `(hi + (x - hi)/2) >> 5`, which equals `x // 61` for unsigned 64-bit `x` (builder-verified, see above). Because the mul is unsigned, a negative sign-extended field still divides as a large u64 value; because the store is 32-bit, only the quotient's low 32 bits are written. The return value is fully determined (`mov $0x1,%eax` before `ret`), so no low-byte-only caveat applies here, unlike packets #27 and #32.

The table's 64 bytes at `0x801180` (in `.rodata`) are locked by the checker:
`fe d3 bb a9 9c 90 87 7f 78 71 6b 66 61 5d 59 55 51 4d 4a 47 44 41 3e 3c 39 37 35 32 30 2e 2c 2a 28 27 25 23 21 20 1e 1d 1b 1a 18 17 15 14 13 12 10 0f 0e 0d 0c 0a 09 08 07 06 05 04 03 02 01 00`.
The table's meaning is not claimed.

### Incoming calls

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly three direct `e8` call sites, each confirmed as an instruction start by linear disassembly from its caller FDE start — `0x555585d` (call bytes `e8 7e e7 ff ff`, FDE `0x5554b50..0x5555bcc`), `0x5556412` (call bytes `e8 c9 db ff ff`, FDE `0x5555bd0..0x555661f`), `0x5556f7e` (call bytes `e8 5d d0 ff ff`, FDE `0x55566f0..0x5557058`). The scan is explicitly not a complete xref census. The first two callers immediately precede the call with `lea` pairs setting `rsi` to a base+`0x70` and `rdi` to the same base+`0x98`; the third caller's retained tail shows `rdi` set to a base+`0x98`. Caller purpose beyond call site and argument setup is not claimed.

### Data edge

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan).

## Inferences

- The "multiply-mix plus divide-by-61 store" label is an inference from the instruction shape: a multiply-add state update, a table lookup, a multiply, and a mulhi division tail. It is kept separate from the observed rule above.
- The state word, the field, and the table may be parts of one structure addressed from `rdi`/`rsi`, but no field meaning, table meaning, or structure layout is claimed.
- The division magic is consistent with unsigned division by 61 only; no claim is made that 61 has any domain meaning.

## Unknowns

- What the state word, the field, and the table entries mean, and what source-level function or type this window belongs to.
- Whether any indirect or PLT-mediated caller exists; the byte-pattern scan covers direct `e8` sites only.
- The provenance of the window (stdlib, crate, or private helper); the absence of a naming relocation does not identify it.

## Limits

- No stdlib type, source-level function, field meaning, table meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
