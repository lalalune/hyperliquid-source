# foundation-stack-shift-sum-94: what does the stack-arg shift-sum window compute?

- Component: `foundation`, a bounded part of its first time/quantity mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985` (main).
- Reference pin: can1357/hl was a search lead only. No inferred implementation
  was copied, and every claim below is grounded in target bytes.
- Claim: observations about one target instruction window and its call/data
  edges; its source-level name and types remain inferences.
- Included: the 55-byte window, its stride padding, its FDE record plus the
  next FDE, the single incoming direct call (boundary-confirmed), and the
  full relocation scan showing no naming relocation.
- Excluded: other windows, all #115 addresses, target execution, Rust
  reconstruction, complete caller behavior, a caller census, and any meaning
  for the flag or the two arguments.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet binds one small, previously unclaimed
window whose rule reads directly from its own bytes: a flag-gated sum of two
shifted terms, where the shift counts are derived from two stack-passed
32-bit words. Its interest is not its size but its exactness — the gate
polarity, the unsigned min, and the mod-64 shift counts are all locked
against the bytes, including one point where the scout note had them
backwards (see below).

## Reproduce

Working directory: repository root. The checker and tests use Python's
standard library only. GNU objdump was used for the retained disassembly
(`objdump -d` for the window/callers, `objdump --dwarf=frames` for FDE
records); no LLVM, Ghidra, or Java tooling is needed to reproduce the
retained results.

```sh
make doctor
python3 tools/foundation_stack_shift_sum.py --check research/work-items/foundation-stack-shift-sum-94/evidence.json
python3 -m unittest tests.test_foundation_stack_shift_sum -v
make verify test catalogue-check
```

No target binary, captured service, networked node, chain operation or
model-backed program was executed.

## Observations

- Window: [0x55c6c40, 0x55c6c77), 55 bytes (`.eh_frame+0x2d3b04`, CIE at
  offset 0, `zR` pcrel sdata4: field VA 0xfb5024 + 0x04611c1c = 0x55c6c40,
  range 0x37). 9 int3 padding bytes to the 64-byte stride ending at
  0x55c6c80 — stride is not the FDE extent; the checker locks body and
  padding separately. Next FDE starts exactly at 0x55c6c80
  ([0x55c6c80, 0x55c6c9d), field VA 0xfb5038 + 0x04611c48).
- Decoded behavior, verified from bytes, zero calls, one forward branch:
  `endbr64` → `xor %eax,%eax` → `cmpl $0x1, 0x8(%rsp)` →
  `je 0x55c6c50` (the compute path) → `ret` (flag != 1, eax still 0) →
  2-byte `xchg %ax,%ax` nop → `mov 0xc(%rsp),%edx` (arg1) →
  `mov 0x10(%rsp),%eax` (arg2) → `mov $0x8,%esi` →
  `cmp %eax,%edx` → `mov %edx,%ecx` → `cmovbe %edx,%eax`
  (eax = unsigned min of arg1 and arg2) → `sub %eax,%ecx`
  (ecx = arg1 − min) → `mov $0x1,%eax` → `shl %cl,%rax` →
  `mov %edx,%ecx` → `shl %cl,%rsi` → `add %rsi,%rax` → `ret`.
- Rule, in its literal form: let flag be the 32-bit word at [rsp+8], arg1
  the 32-bit word at [rsp+0xc], arg2 the 32-bit word at [rsp+0x10], all
  read in the window's own frame (rsp points at the return address on
  entry, so these are the caller's stack-passed words — no register
  argument is read). If flag != 1 → return 0. Else return
  (1 << ((arg1 − min(arg1, arg2)) mod 64)) + (8 << (arg1 mod 64)),
  mod 2^64. The min is unsigned (`cmovbe`); both shift counts are the
  low 6 bits of their 32-bit counts (x86 `shl %cl` semantics), so
  large arguments wrap rather than saturate or trap.
- Locked edges: flag 0 or 2 → 0 regardless of arguments; flag 1 with
  arg1 = arg2 = 0 → 9; flag 1 with arg1 = 5, arg2 = 3 → 260; flag 1
  with arg1 = 3, arg2 = 5 → 65; flag 1 with arg1 = 64, arg2 = 0 → 9
  (both counts mod 64 are 0); flag 1 with arg1 = 65, arg2 = 65 → 17;
  flag 1 with arg1 = 70, arg2 = 0 → 576; flag 1 with arg1 = 0xffffffff,
  arg2 = 0 → 2^63 (difference mod 64 is 63, and 8 << 63 wraps to 0
  mod 2^64).

## Scout correction (stated prominently)

The round-9 scout note described this window as "if [rsp+8] == 1 →
return 0, else ...". The bytes say the opposite: `cmpl $0x1, 0x8(%rsp)`
followed by `je` to the compute path and a fall-through `ret` with eax
already zeroed. So flag == 1 is the computing case and flag != 1 is the
zero case. The checker, tests, and rule above lock the verified polarity,
not the scout summary. The rest of the scout note (FDE range, 55-byte
body, both shifts, one caller, no naming relocation) verified exactly.

## Incoming call and data edge

- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  exactly one direct `e8` site — 0x555ba70 (bytes `e8 cb b1 06 00`),
  confirmed as an instruction start by linear disassembly from its caller
  FDE start (0x555b930..0x555bbf8) — explicitly not a complete xref
  census. The caller stores to its own frame before the call; caller
  purpose beyond that is not claimed.
- Data edge: no relocation record of any type in any `.rela.*` section
  names this window as addend (full-section scan of `.rela.dyn` and
  `.rela.plt`).
- Scout precision note (not a behavior correction): the scout listed the
  caller FDE end as 0x555bc00; the exact end from `--dwarf=frames` is
  0x555bbf8 (the scout end appears to be the following FDE start, the
  same pattern seen in packets #50/#51/#53). Call site, call bytes, and
  the window rule all verified exactly as scouted apart from the gate
  polarity above; the checker locks the exact end.
- Nearest claimed window: byte-indexed byte load 0x556bfe0 (packet #53),
  0x5a60 away.

## Inferences (kept separate from observations)

- The "stack-arg shift sum" label is an inference from the shape of the
  rule; no source-level function name is claimed.
- The flag and the two arguments have no assigned meaning; the window
  reads no register argument, which is unusual for this run's packets
  and is stated as a property of the bytes, not as an ABI claim about
  the caller.

## Unknowns

- Why the caller passes these three words on the stack, and what the
  flag gates, is unknown from this window alone.
- Whether any other caller reaches this window by an indirect branch is
  unknown; the scan counts direct `e8` sites only.

## Limits

- No stdlib type, source-level function, argument meaning, or caller
  purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence
  of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and
  generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation
  was copied, and every claim is grounded in target bytes for node #94.
