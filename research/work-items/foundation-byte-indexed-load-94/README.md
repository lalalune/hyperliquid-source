# foundation-byte-indexed-load-94: what does the byte-indexed-load window compute?

- Component: `foundation`, a bounded part of its first time/quantity mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985` (main).
- Reference pin: can1357/hl was a search lead only. No inferred implementation
  was copied, and every claim below is grounded in target bytes.
- Claim: observations about one target instruction window and its call/data
  edges; its source-level name and types remain inferences.
- Included: the 22-byte window, its stride padding, its FDE record plus the
  next FDE, the single incoming direct call (boundary-confirmed), and the
  full relocation scan showing no naming relocation.
- Excluded: other windows, all #115 addresses, target execution, Rust
  reconstruction, complete caller behavior, a caller census, and any meaning
  for the count byte, the index, or the loaded byte.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet binds one small, previously unclaimed
window whose rule reads directly from its own bytes: an unsigned
count-versus-index gate selecting between zero and a scaled byte load. Its
small size is not its content; the exactness of the gate — unsigned,
full-width, zero-extended on both paths — is.

## Reproduce

Working directory: repository root. The checker and tests use Python's
standard library only. GNU objdump was used for the retained disassembly
(`objdump -d` for the window/callers, `objdump --dwarf=frames` for FDE
records); no LLVM, Ghidra, or Java tooling is needed to reproduce the
retained results.

```sh
make doctor
python3 tools/foundation_byte_indexed_load.py --check research/work-items/foundation-byte-indexed-load-94/evidence.json
python3 -m unittest tests.test_foundation_byte_indexed_load -v
make verify test catalogue-check
```

No target binary, captured service, networked node, chain operation or
model-backed program was executed.

## Observations

- Window: [0x556bfe0, 0x556bff6), 22 bytes (`.eh_frame+0x2d0d78`, CIE at
  offset 0, `zR` pcrel sdata4: field VA 0xfb2298 + 0x045b9d48 = 0x556bfe0,
  range 0x16). 10 int3 padding bytes to the 32-byte stride ending at
  0x556c000 — stride is not the FDE extent; the checker locks body and
  padding separately. Next FDE starts exactly at 0x556c000
  ([0x556c000, 0x556cb06), field VA 0xfb22ac + 0x045b9d54).
- Decoded behavior, verified from bytes, zero calls, one forward branch:
  `endbr64` → `movzbl 0x1(%rdi),%edx` → `xor %eax,%eax` →
  `cmp %esi,%edx` → `jb 0x556bff5` (the `ret` itself) →
  `mov %esi,%esi` → `movzbl 0x8(%rdi,%rsi,8),%eax` → `ret`.
- Rule, in its literal form: let b be the byte at [rdi+1] (0..255) and
  i be the full 32-bit esi. If b < i (unsigned — the branch is `jb`
  after a compare of the zero-extended byte against esi) → return 0;
  else return the byte at [rdi + 8*i + 8]. The `mov %esi,%esi`
  zero-extends the index, so the scaled load uses the full 32-bit index,
  and every return is a full-register move into eax, so the result is
  always 0..255 — no low-byte-only caveat (unlike packets #27/#32).
- Locked edges: (b=3, i=5) → 0; (b=10, i=10) → indexed byte; (b=5, i=3)
  → indexed byte; (b=255, i=256) → 0, because the compare is full-width
  and unsigned, not limited to a byte; (b=0, i=0) → indexed byte, since
  the early return requires a strict below, not below-or-equal.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  exactly one direct `e8` site — 0x55c8f0b (bytes `e8 d0 30 fa ff`),
  confirmed as an instruction start by linear disassembly from its caller
  FDE start (0x55c8d70..0x55c9754) — explicitly not a complete xref
  census. The caller sets esi from r12d immediately before the call;
  caller purpose beyond that is not claimed.
- Data edge: no relocation record of any type in any `.rela.*` section
  names this window as addend (full-section scan of `.rela.dyn` and
  `.rela.plt`).
- Nearest claimed window: multiply-mix 0x5553fe0 (packet #43), 0x18000
  away. No census claimed.
- No scout correction needed: every scouted element verified exactly
  (FDE range, 22-byte body, all instructions, one caller, no naming
  relocation).

## Inferences

- The "byte-indexed byte load" label is an inference from the observed
  gate-plus-scaled-load shape. It is kept separate from the rule above.
- The window's shape (a count byte at +1, then 8-byte-strided slots from
  +8) suggests a length-prefixed table, but no table meaning, element
  type, or caller contract is claimed: the bytes alone do not say what
  the slots hold or why the gate exists.

## Unknowns

- The source-level function, the struct layout behind rdi, and the meaning
  of the count byte, the index, and the loaded byte.
- Whether other call paths reach this window indirectly (the scan counts
  direct `e8` sites only).
- The caller FDE's purpose beyond the single call site retained here.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose
  is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of
  a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and
  generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation
  was copied, and every claim is grounded in target bytes for node #94
  (SHA-256 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).

## Scout precision note

The scout listed the caller FDE end as 0x55c9760; the exact end from
`--dwarf=frames` is 0x55c9754 (the scout end appears to be the following
FDE start, the same pattern seen in packets #50/#51). The call site,
call bytes, and window rule all verified exactly as scouted; the checker
locks the exact end.
