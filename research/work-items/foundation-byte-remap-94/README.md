# foundation-byte-remap-94: what does the byte-remap window compute?

- Component: `foundation`, a bounded part of its first time/quantity mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985` (main).
- Reference pin: can1357/hl was a search lead only. No inferred implementation
  was copied, and every claim below is grounded in target bytes.
- Claim: observations about one target instruction window and its call/data
  edges; its source-level name and types remain inferences.
- Included: the 78-byte window, its stride padding, its FDE record plus the
  next FDE, a 3-site sample of incoming direct calls (each boundary-confirmed),
  and the full relocation scan showing no naming relocation.
- Excluded: other windows, all #115 addresses, target execution, Rust
  reconstruction, complete caller behavior, a caller census, and any meaning
  for the byte values or the remap itself.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet binds one small, previously unclaimed
window whose rule reads directly from its own bytes: a low-byte range test
with an early return, a low-range mask/or, two single-tag mask/or branches,
and an otherwise-unchanged fallthrough.

## Reproduce

Working directory: repository root. The checker and tests use Python's
standard library only. GNU objdump was used for the retained disassembly
(`objdump -d` for the window/callers, `objdump --dwarf=frames` for FDE
records); no LLVM, Ghidra, or Java tooling is needed to reproduce the
retained results.

```sh
make doctor
python3 tools/foundation_byte_remap.py --check research/work-items/foundation-byte-remap-94/evidence.json
python3 -m unittest tests.test_foundation_byte_remap -v
make verify test catalogue-check
```

No target binary, captured service, networked node, chain operation or
model-backed program was executed.

## Observations

- Window: [0x25acc20, 0x25acc6e), 78 bytes (`.eh_frame+0x94080`, CIE at
  offset 0, `zR` pcrel sdata4: field VA 0xd755a0 + 0x01837680 = 0x25acc20,
  range 0x4e). 2 int3 padding bytes to the 80-byte stride ending at
  0x25acc70 — stride is not the FDE extent; the checker locks body and
  padding separately. Next FDE starts exactly at 0x25acc70
  ([0x25acc70, 0x25accfa), field VA 0xd755b4 + 0x018376bc).
- The window opens directly with the first move — no `endbr64` (an
  observation, not a scout deviation).
- Decoded behavior, verified from bytes, zero calls, branches only:
  `mov %edi,%eax` → `movzbl %al,%ecx` (b = low byte of edi) →
  `lea -0xc0(%rcx),%edx` → `cmp $0x20,%edx` → `jae 0x25acc31` →
  `ret` (early return, eax still edi) → `cmp $0x8f,%ecx` →
  `jle 0x25acc54` → `cmp $0x90,%ecx` → `je 0x25acc63` →
  `cmp $0xa0,%ecx` → `jne 0x25acc51` (shared return) →
  `and $0x1f,%sil` → `or $0xa0,%sil` → `mov %esi,%eax` → `ret`
  (0x25acc51) → `test %ecx,%ecx` → `je 0x25acc51` →
  `and $0xf,%sil` → `or $0x80,%sil` → `mov %esi,%eax` → `ret`
  (0x25acc54 path) → `and $0xf,%sil` → `or $0x90,%sil` →
  `mov %esi,%eax` → `ret` (0x25acc63 path).
- Rule, with b the low byte of edi and all returns full-register moves
  into eax (so zero-extended, fully determined, no low-byte-only caveat):
  b in [0xc0, 0xe0) → edi unchanged; else b ≤ 0x8f → b == 0 ? esi
  unchanged : (sil & 0xf) | 0x80; else b == 0x90 → (sil & 0xf) | 0x90;
  else b == 0xa0 → (sil & 0x1f) | 0xa0; else → esi unchanged.
- Locked edges: (0x123456c0, esi) → 0x123456c0; (0x123456df, esi) →
  0x123456df; (0xe0, esi) → esi (0xe0 is outside [0xc0, 0xe0): the
  unsigned difference is exactly 0x20, so `jae` falls through); (0xbf,
  esi) → esi; (0x00, 0xabcdef12) → 0xabcdef12; (0x01, 0xabcdef12) → 0x82;
  (0x8f, 0x123456ff) → 0x8f; (0x90, 0x12345678) → 0x98; (0x91,
  0x12345678) → 0x12345678; (0xa0, 0x12345678) → 0xb8; (0xa1,
  0x12345678) → 0x12345678.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  124 direct `e8` sites — a heavily-shared utility shape, the same order
  of magnitude as packet #26's 113. Only a sample of 3 is
  boundary-confirmed here (each confirmed as an instruction start by
  linear disassembly from its caller FDE start): 0x1dfe6d5 (bytes
  `e8 46 e5 7a 00`, caller FDE 0x1dfe650..0x1dfe798), 0x1dfe713 (bytes
  `e8 08 e5 7a 00`, same caller FDE), 0x1e00885 (bytes `e8 96 c3 7a 00`,
  caller FDE 0x1e007f0..0x1e009c6). This is explicitly not a complete
  xref census, and no caller census is claimed.
- Data edge: no relocation record of any type in any `.rela.*` section
  names this window as addend (full-section scan of `.rela.dyn` and
  `.rela.plt`).
- Nearest claimed window: tail-gate 0x250ab00 (packet #31), 0xa2120
  away; nothing in 0x25accxx is claimed.

## Scout precision note (not a behavior correction)

The round-9 scout listed the two sampled caller FDE ends as 0x1dfe7a0
and 0x1e009d0. The exact FDE ends from `objdump --dwarf=frames` are
0x1dfe798 and 0x1e009c6 (the scout ends appear to be the following FDE
starts). The call sites, call bytes, and the window rule all verified
exactly as scouted; only the caller FDE end values are corrected here,
and the checker locks the exact ends.

## Inferences

- The "byte remap" label is an inference from the observed shape (a
  low-byte range test feeding mask/or branches). No source-level
  function, argument meaning, or purpose is claimed.
- The objdump symbol annotation on the retained disassembly is not
  treated as an identification: a matching label cannot establish the
  mapping this packet binds from bytes.

## Unknowns

- What the window's callers pass as `edi`/`esi`, and what the returned
  value means to them, beyond the three sampled call sites listed above.
- The full caller set: the 124 scan hits are a byte-pattern count, not
  a validated census.
- The provenance of the window: the absence of a naming relocation does
  not identify it as library or private code.

## Limits

- No stdlib type, source-level function, or caller purpose is claimed
  anywhere.
- The byte-pattern scan is not a complete xref census.
- No progress gate is requested or claimed. Foundation's gates and
  generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation
  was copied, and every claim is grounded in target bytes for node #94.
