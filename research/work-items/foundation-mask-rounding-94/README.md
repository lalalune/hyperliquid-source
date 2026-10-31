# foundation-mask-rounding-94: what does the mask/rounding window compute?

- Component: `foundation`, a bounded part of its first time/quantity mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985` (main).
- Reference pin: can1357/hl was a search lead only. No inferred implementation
  was copied, and every claim below is grounded in target bytes.
- Claim: observations about one target instruction window and its call/data
  edges; its source-level name and types remain inferences.
- Included: the 75-byte window, its stride padding, its FDE record plus the
  next FDE, three incoming direct calls (each boundary-confirmed), and the
  full relocation scan showing no naming relocation.
- Excluded: other windows, all #115 addresses, target execution, Rust
  reconstruction, complete caller behavior, and any meaning for the mask
  constant or the -72 sentinel.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet binds one small, previously unclaimed
window whose rule reads directly from its own bytes: a mask comparison, a
shift-and-add with a small-input rounding term, and a zero branch that turns
out to be unreachable on the stated inputs.

## Reproduce

Working directory: repository root. The checker and tests use Python's
standard library only. GNU objdump was used for the retained disassembly
(`objdump -d` for the window/callers, `objdump --dwarf=frames` for FDE
records); no LLVM, Ghidra, or Java tooling is needed to reproduce the
retained results.

```sh
make doctor
python3 tools/foundation_mask_rounding.py --check research/work-items/foundation-mask-rounding-94/evidence.json
python3 -m unittest tests.test_foundation_mask_rounding -v
make verify test catalogue-check
```

No target binary, captured service, networked node, chain operation or
model-backed program was executed.

## Observations

- Window: [0x555e610, 0x555e65b), 75 bytes (`.eh_frame+0x2cfd9c`, CIE at
  offset 0, `zR` pcrel sdata4: field VA 0xfb12bc + 0x045ad354 = 0x555e610,
  range 0x4b). 5 int3 padding bytes to the 80-byte stride ending at
  0x555e660 — stride is not the FDE extent; the checker locks body and
  padding separately. Next FDE starts exactly at 0x555e660
  ([0x555e660, 0x555e66c), field VA 0xfb12d0 + 0x045ad390).
- Decoded behavior, verified from bytes, zero calls, two forward branches,
  both targets inside the FDE:
  `endbr64` → `movabs $0xff00ff00ff00feff,%rdx` →
  `mov $0xffffffffffffffb8,%rax` (-72) → `cmp %rdi,%rdx` →
  `jb 0x555e65a` (the `ret` itself) → `mov %rdi,%rax` →
  `shr $0x8,%rax` → `add %rdi,%rax` → `cmp $0x1ffff,%rdi` →
  `ja 0x555e64c` (the `test`) → `mov $0x20000,%edx` →
  `sub %rdi,%rdx` → `shr $0xb,%rdx` → `add %rdx,%rax` →
  `test %rax,%rax` → `mov $0xffffffffffffffb8,%rdx` →
  `cmove %rdx,%rax` → `ret`.
- Rule, as an unsigned 64-bit rax value: if `rdi > 0xff00ff00ff00feff`
  (unsigned) → `0xffffffffffffffb8` (-72); else `v = rdi + (rdi>>8) +
  (rdi ≤ 0x1ffff ? (0x20000-rdi)>>11 : 0)` mod 2^64; if `v == 0` →
  `0xffffffffffffffb8`, else `v`. All arithmetic is 64-bit wrapping; the
  `shr`/`add` sequence has no 32-bit truncation.
- Locked edges: 0 → 64; 1 → 64; 0x1ffff → 131582 (0x201fe); 0x20000 →
  131584 (0x20200); mask → 0xfffffffffffffffd (signed -3: the mask itself
  does not return the sentinel, only inputs strictly above it do); mask+1
  → sentinel; 2^64-1 → sentinel.
- The `v == 0` branch is unreachable on the stated inputs, and is reported
  as literal bytes, not a live edge: on the small path (`rdi ≤ 0x1ffff`)
  the value is at least 64 (exhaustively checked over the whole small
  domain: the minimum is 64 at `rdi = 0`, and each unit step of `rdi`
  raises the `rdi` term by 1 while the rounding term falls by at most 1,
  so the sum never decreases); on the large path (`0x1ffff < rdi ≤ mask`)
  the value is `rdi + (rdi>>8) > 0`. The `cmove` therefore never fires
  for any input that reaches it.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  exactly three direct `e8` sites, each confirmed as an instruction start
  by linear disassembly from its caller FDE start — 0x5081df3 (bytes
  `e8 18 c8 4d 00`, caller FDE 0x50814d0..0x5081fe5), 0x5343b8a (bytes
  `e8 81 aa 21 00`, caller FDE 0x5343ab0..0x53440f8), 0x55fa67b (bytes
  `e8 90 3f f6 ff`, caller FDE 0x55fa5e0..0x55fa7e8). This is explicitly
  not a complete xref census.
- Data edge: no relocation record of any type in any `.rela.*` section
  names this window as addend (full-section scan of `.rela.dyn` and
  `.rela.plt`).
- Nearest claimed window: multiply-mix 0x5553fe0 (packet #43), 0xa630
  away; nothing in 0x555e6xx is claimed.

## Scout precision note (not a behavior correction)

The round-9 scout listed the three caller FDE ends as 0x5081ff0,
0x5344100, and 0x55fa7f0. The exact FDE ends from `objdump
--dwarf=frames` are 0x5081fe5, 0x53440f8, and 0x55fa7e8 (the scout ends
appear to be the following FDE starts). The call sites, call bytes, and
the window rule all verified exactly as scouted; only the caller FDE end
values are corrected here, and the checker locks the exact ends.

## Inferences

- The "mask/rounding arithmetic" label is an inference from the observed
  shape (a mask comparison, a shift-and-add, a small-input rounding term).
  No source-level function, argument meaning, or purpose is claimed.
- The -72 value is reported as a sentinel only because both return paths
  load it explicitly; no meaning (error code, tag, or otherwise) is
  claimed for it, and none is claimed for the mask constant.

## Unknowns

- What the window's callers pass as `rdi`, and what the returned value
  means to them, beyond the three call sites listed above.
- Whether any caller ever depends on the unreachable `v == 0` branch.
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
