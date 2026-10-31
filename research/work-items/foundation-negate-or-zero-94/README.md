# foundation-negate-or-zero-94: what does the negate-or-zero window compute?

- Component: `foundation`, a bounded part of its first time/quantity mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985` (main).
- Reference pin: can1357/hl was a search lead only. No inferred implementation
  was copied, and every claim below is grounded in target bytes.
- Claim: observations about one target instruction window and its call/data
  edges; its source-level name and types remain inferences.
- Included: the 18-byte window, its stride padding, its FDE record plus the
  next FDE, all 6 incoming direct calls (each boundary-confirmed, all in a
  single caller FDE), and the full relocation scan showing no naming
  relocation.
- Excluded: other windows, all #115 addresses, target execution, Rust
  reconstruction, complete caller behavior, a caller census, and any meaning
  for the −119 bound or the negation itself.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet binds one small, previously unclaimed
window whose rule reads directly from its own bytes: a full-width unsigned
comparison against a sign-extended constant, selecting between a 32-bit
negation and zero. Its small size is not its content; the exactness of the
range rule is.

## Reproduce

Working directory: repository root. The checker and tests use Python's
standard library only. GNU objdump was used for the retained disassembly
(`objdump -d` for the window/callers, `objdump --dwarf=frames` for FDE
records); no LLVM, Ghidra, or Java tooling is needed to reproduce the
retained results.

```sh
make doctor
python3 tools/foundation_negate_or_zero.py --check research/work-items/foundation-negate-or-zero-94/evidence.json
python3 -m unittest tests.test_foundation_negate_or_zero -v
make verify test catalogue-check
```

No target binary, captured service, networked node, chain operation or
model-backed program was executed.

## Observations

- Window: [0x555ac00, 0x555ac12), 18 bytes (`.eh_frame+0x2cfa04`, CIE at
  offset 0, `zR` pcrel sdata4: field VA 0xfb0f24 + 0x045a9cdc = 0x555ac00,
  range 0x12). 14 int3 padding bytes to the 32-byte stride ending at
  0x555ac20 — stride is not the FDE extent; the checker locks body and
  padding separately. Next FDE starts exactly at 0x555ac20
  ([0x555ac20, 0x555ac97), field VA 0xfb0f38 + 0x045a9ce8).
- Decoded behavior, verified from bytes, zero calls, no branches:
  `endbr64` → `mov %edi,%eax` → `xor %edx,%edx` → `neg %eax` →
  `cmp $0xffffffffffffff88,%rdi` → `cmovbe %edx,%eax` → `ret`.
- Rule, in its literal unsigned form (rdi is the full 64-bit input, and
  the result is the zero-extended 32-bit negation): rdi unsigned ≤
  0xffffffffffffff88 → 0; else → (−low32(rdi)) mod 2^32. The comparison
  is on all of rdi, not on the low word alone: 0x1ffffff89 has low word
  0xffffff89 yet returns 0, because its full value is below the mask.
- Signed reading, valid exactly for sign-extended inputs: signed rdi in
  [−119, −1] → −edi; else 0. The bound comes from the unsigned
  `cmovbe` against −0x78 sign-extended to 64 bits (0x88 as an imm8 under
  `83 /7`): values above the mask are exactly the 64-bit encodings of
  −119 through −1. This spelling-out matters — "small negatives" alone
  would hide both the bound and the full-width comparison.
- Locked edges: −1 → 1; −119 → 119; −120 → 0 (the mask value itself is
  below-or-equal, so `cmovbe` moves zero); 0 → 0; 1 → 0; 119 → 0;
  mask+1 (i.e. −119) → 119; 0x1ffffff89 → 0 (full-width comparison, see
  above). The whole signed range [−119, −1] is exhaustively covered by
  the unit tests.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  exactly 6 direct `e8` sites, all boundary-confirmed (each confirmed as
  an instruction start by linear disassembly from its caller FDE start)
  and all in a single caller FDE 0x55d9d60..0x55dad7c: 0x55da082 (bytes
  `e8 79 0b f8 ff`), 0x55da0c7 (`e8 34 0b f8 ff`), 0x55da276
  (`e8 85 09 f8 ff`), 0x55da68e (`e8 6d 05 f8 ff`), 0x55dad00
  (`e8 fb fe f7 ff`), 0x55dad37 (`e8 c4 fe f7 ff`). This is explicitly
  not a complete xref census, and no caller census is claimed.
- Data edge: no relocation record of any type in any `.rela.*` section
  names this window as addend (full-section scan of `.rela.dyn` and
  `.rela.plt`).
- Nearest claimed window: multiply-mix 0x5553fe0 (packet #43), 0x6c20
  away; nothing in 0x555acxx is claimed.

## Scout precision note (not a behavior correction)

The round-9 scout listed the caller FDE end as 0x55dad80. The exact FDE
end from `objdump --dwarf=frames` is 0x55dad7c (the scout end appears to
be the following FDE start). The call sites, call bytes, and the window
rule all verified exactly as scouted; only the caller FDE end value is
corrected here, and the checker locks the exact end.

## Inferences

- The "negate-or-zero gate" label is an inference from the observed shape
  (a range test selecting between a negation and zero). No source-level
  function, argument meaning, or purpose is claimed.
- The objdump symbol annotation on the retained disassembly is not
  treated as an identification: a matching label cannot establish the
  mapping this packet binds from bytes.

## Unknowns

- What the window's callers pass as `rdi`, and what the returned value
  means to them, beyond the six call sites listed above.
- The full caller set: the 6 scan hits are a byte-pattern count, not a
  validated census.
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
