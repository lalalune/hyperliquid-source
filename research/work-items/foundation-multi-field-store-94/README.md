# foundation-multi-field-store-94: what does the multi-field default/store window do?

- Component: `foundation`, a bounded part of its first time/quantity mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985` (main).
- Reference pin: can1357/hl was a search lead only. No inferred implementation
  was copied, and every claim below is grounded in target bytes.
- Claim: observations about one target instruction window and its call/data
  edges; its source-level name and types remain inferences.
- Included: the 90-byte window, its stride padding, its FDE record plus the
  next FDE, the single incoming direct call (boundary-confirmed), and the
  full relocation scan showing no naming relocation.
- Excluded: other windows, all #115 addresses, target execution, Rust
  reconstruction, complete caller behavior, a caller census, and any meaning
  for the source value or the five fields.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet binds one small, previously unclaimed
window whose rule reads directly from its own bytes: a store of a source
value plus four field defaults/clamps, all decided by unsigned 32-bit
compares. Its interest is not its size but its exactness — the wrap-around
in the field +0x4 default, the saturating difference for field +0x10, and
the final min that decides field +0x8 are all locked against the bytes,
including one point where the scout note's shorthand understates the rule
(see below).

## Reproduce

Working directory: repository root. The checker and tests use Python's
standard library only. GNU objdump was used for the retained disassembly
(`objdump -d` for the window/callers, `objdump --dwarf=frames` for FDE
records); no LLVM, Ghidra, or Java tooling is needed to reproduce the
retained results.

```sh
make doctor
python3 tools/foundation_multi_field_store.py --check research/work-items/foundation-multi-field-store-94/evidence.json
python3 -m unittest tests.test_foundation_multi_field_store -v
make verify test catalogue-check
```

No target binary, captured service, networked node, chain operation or
model-backed program was executed.

## Observations

- Window: [0x55c6be0, 0x55c6c3a), 90 bytes (`.eh_frame+0x2d3af0`, CIE at
  offset 0, `zR` pcrel sdata4: field VA 0xfb1010 + 0x04611bd0 = 0x55c6be0,
  range 0x5a). 6 int3 padding bytes to the 96-byte stride ending at
  0x55c6c40 — stride is not the FDE extent; the checker locks body and
  padding separately. Next FDE starts exactly at 0x55c6c40
  ([0x55c6c40, 0x55c6c77), field VA 0xfb1024 + 0x04611c1c).
- Decoded behavior, verified from bytes, zero calls, three forward
  branches, all targets inside the FDE:
  `endbr64` → `mov 0x8(%rdi),%eax` (field A) →
  `mov $0x3,%edx` → `mov (%rsi),%esi` (source S, 32-bit) →
  `test %eax,%eax` → `mov %esi,0x14(%rdi)` (unconditional store) →
  `cmove %edx,%eax` (A' = A == 0 ? 3 : A) →
  `mov 0xc(%rdi),%edx` (field C) → `test %edx,%edx` →
  `jne 0x55c6c04` → `movl $0x40,0xc(%rdi)` (C' = C == 0 ? 0x40 : C) →
  `mov 0x4(%rdi),%edx` (field D) → `test %edx,%edx` →
  `jne 0x55c6c1b` → `lea -0x7(%rsi),%edx` → `mov $0x6,%ecx` →
  `cmp %ecx,%edx` → `cmovb %ecx,%edx`
  (D' = D == 0 ? min_u((S − 7) mod 2^32, 6) : D) →
  `mov %edx,0x4(%rdi)` → `mov 0x10(%rdi),%ecx` (field E) →
  `test %ecx,%ecx` → `jne 0x55c6c31` → `mov %esi,%r8d` →
  `sub %edx,%r8d` → `cmp %edx,%esi` → `cmovae %r8d,%ecx`
  (E' = E == 0 ? (S >= D' ? S − D' : 0) : E) →
  `mov %ecx,0x10(%rdi)` → `cmp %edx,%eax` → `cmova %edx,%eax`
  (A'' = min_u(A', D')) → `mov %eax,0x8(%rdi)` → `ret`.
- Rule, in its literal form: all values are 32-bit, all comparisons
  unsigned. Let S be the word at [rsi] and A/C/D/E the words at
  [rdi+0x8]/[rdi+0xc]/[rdi+0x4]/[rdi+0x10] on entry. Then:
  [rdi+0x14] = S always; [rdi+0xc] = C == 0 ? 0x40 : C;
  [rdi+0x4] = D == 0 ? min_u((S − 7) mod 2^32, 6) : D;
  [rdi+0x10] = E == 0 ? (S >= D_final ? S − D_final : 0) : E;
  [rdi+0x8] = min_u(A == 0 ? 3 : A, D_final); eax at ret equals the
  value stored to [rdi+0x8]. The D_final used by the last two steps is
  the possibly-defaulted D, not the entry D.
- Scout note, expanded: the round-9 scout shorthand said "[rdi+0x14] =
  [rsi], [rdi+8] defaulted to 3 when zero, further field clamps with
  cmov". The first two clauses are true as intermediate steps, but the
  final [rdi+0x8] is min(defaulted A, D_final), not just the default;
  and the note did not mention the 0x40 default for field +0xc, the
  min((S − 7) mod 2^32, 6) default for field +0x4, or the saturating
  difference for field +0x10. The checker, tests, and rule above lock
  the full decoded behavior, not the shorthand.
- Wrap-around edge, stated exactly: because (S − 7) wraps mod 2^32, a
  source below 7 defaults field +0x4 to 6 (the wrapped difference is
  huge, so the unsigned min picks 6), while source 7 defaults it to 0
  and source 13 to 6 via min(6, 6). For sources 8..12 the default is
  S − 7; for sources 14 and above it is 6.
- Locked edges: all zero → (store 0, +0x8 = 3, +0xc = 0x40, +0x4 = 6,
  +0x10 = 0); source 10 with A = 5, C = 1, D = 0, E = 0 → (+0x4 = 3,
  +0x10 = 7, +0x8 = 3); source 20 with A = 0, C = 0, D = 4, E = 9 →
  (+0x8 = 3, others pass through); source 5 with A = 7, C = 2, D = 0,
  E = 0 → (+0x4 = 6, +0x10 = 0, +0x8 = 6); source 14 with A = 9, C = 3,
  D = 0, E = 0 → (+0x4 = 6, +0x10 = 8, +0x8 = 6); source 13 with A = 2,
  C = 0, D = 0, E = 0 → (+0x4 = 6, +0x10 = 7, +0x8 = 2); source 7 with
  A = 0, C = 0, D = 0, E = 0 → (+0x4 = 0, +0x10 = 7, +0x8 = 0);
  source 0xffffffff with A = 1, C = 1, D = 0, E = 0 → (+0x4 = 6,
  +0x10 = 0xfffffff9, +0x8 = 1); all nonzero (100, 10, 5, 4, 3) →
  only +0x8 changes, to min(10, 4) = 4.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  exactly one direct `e8` site — 0x555deab (bytes e8 30 8d 06 00),
  confirmed as an instruction start by linear disassembly from its
  caller FDE start (0x555d1f0..0x555e60f) — explicitly not a complete
  xref census. The caller sets rsi from r14 and rdi from r15 immediately
  before the call; caller purpose beyond that is not claimed.
- Data edge: no relocation record of any type in any `.rela.*` section
  names this window as addend (full-section scan: 80,022 `.rela.dyn` +
  278 `.rela.plt` entries).
- Scout precision note (not a behavior correction): the scout listed the
  caller FDE end as 0x555e610; the exact end from `--dwarf=frames` is
  0x555e60f (the scout end is the following FDE start, the same pattern
  seen in packets #50/#51/#53/#55). The checker locks the exact end.
- Nearest claimed window: stack-arg shift sum 0x55c6c40 (packet #54),
  0x5a60 away; the caller FDE ends exactly at packet #50's window
  0x555e610, which is a caller-range fact, not a claim about that window.

## Inferences

- The "multi-field default/store" label is an inference from the five
  field effects; it is not a source-level name.
- The return register mirroring the stored +0x8 value is an observation
  about eax at `ret`, not a claim that callers use it.

## Unknowns

- What the source value and the five fields mean, and what calls this
  window for (beyond the single boundary-confirmed call site).
- Whether the +0xc default (0x40) and the +0x4 cap (6) carry any unit
  or domain meaning; the bytes give constants only.
- The provenance of the window: the absence of a naming relocation does
  not identify it.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose
  is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence
  of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and
  generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation
  was copied, and every claim is grounded in target bytes for node #94
  (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
