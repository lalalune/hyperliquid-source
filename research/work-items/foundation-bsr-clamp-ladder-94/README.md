# Foundation bsr clamp ladder — node #94 window 0x556e980

## Question

Can one small, previously unclaimed window in node #94 be bound to a precise
rule from its own bytes alone, without a reference label, a matching string,
or a family census?

## Target

- Release: node #94 (Linux x86-64 baseline).
- Captured binary: `artifacts/node/94/hl-node`, 91,774,280 bytes.
- SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Window: FDE `[0x556e980, 0x556e9d8)`, 88 bytes, body SHA-256
  `5414e6009ee48d94319af3e60af05eec0ec123c3b2d8e8c74992e64df4e40fba`.
- Coordinate system: ELF virtual addresses, no runtime rebase.
- Static analysis only. The captured binary was never executed; no network,
  chain action, or signing was involved.

## Scope

Included: this window alone, its FDE record, its stride padding, and the
relocation scan for a naming record.

Excluded: the immediately following FDE `0x556e9e0` (same ladder shape,
different inputs — bound only with an explicit parent decision, never as
part of this packet), any census of similar windows, any stdlib type or
source-level function, and any progress gate. No progress files are touched
and no gate is claimed.

## Reproduce

```sh
python3 tools/foundation_bsr_clamp_ladder.py \
  --check research/work-items/foundation-bsr-clamp-ladder-94/evidence.json
python3 -m unittest tests.test_foundation_bsr_clamp_ladder
make verify test catalogue-check
```

GNU `objdump` was used for the retained disassembly and frames
(`--dwarf=frames` for the FDE extents). The reference tree was a search lead
only; no inferred implementation was copied, and every claim below is
grounded in target bytes.

## Observations

- FDE record at `.eh_frame` section offset `0x2d110c`, CIE at offset `0x0`
  (`zR`, pcrel sdata4), range 88 bytes. The 88-byte body ends at `0x556e9d8`;
  8 `int3` padding bytes run to the 96-byte stride ending at `0x556e9e0`,
  where the next FDE starts (`[0x556e9e0, 0x556ea27)`, section offset
  `0x2d1120`, same CIE). Stride is not the FDE extent; the checker locks
  body and padding separately.
- Decoded instructions, in order, all verified from bytes (all operands are
  32-bit; bsr reads the low 32 bits of its source, rcx enters only as r8d,
  v enters as edi and the result leaves in eax):
  - `endbr64`; `mov %edi,%eax` (v); `mov %edx,%edi` (third argument into
    the bsr slot); `lea -0x1(%rsi),%edx`; `mov %ecx,%r8d`.
  - `bsr %edx,%edx` (bsr of low32(rsi-1)); `mov $0x1f,%ecx`;
    `bsr %edi,%edi` (bsr of low32(rdx)); `bsr %esi,%esi` (bsr of low32(rsi)).
  - `xor $0x1f,%edx`: since a 32-bit bsr result lies in 0..31,
    `31 ^ bsr == 31 - bsr`; then `sub %r8d,%ecx` (31 - rcx) and
    `sub %edx,%ecx` give `hi = bsr(rsi-1) - rcx` (mod 2^32).
  - `add $0x1,%esi` (bsr(rsi)+1); `lea 0x2(%rdi),%edx` (bsr(rdx)+2);
    `cmp %edx,%esi; cmova %edx,%esi` gives `lo = min(bsr(rsi)+1,
    bsr(rdx)+2)`: cmova moves edx into esi exactly when esi is above
    edx, so the result is the smaller of the two.
  - `test %eax,%eax`; `mov $0xb,%edx`; `cmove %edx,%eax` gives
    `v0 = (v == 0 ? 11 : v)`.
  - `mov $0xc,%edx`; `cmp %ecx,%eax; cmova %ecx,%eax` (min with hi);
    `cmp %esi,%eax; cmovb %esi,%eax` (max with lo);
    `cmp %edx,%eax; cmova %edx,%eax` (min with 12);
    `mov $0x5,%edx`; `cmp %edx,%eax; cmovb %edx,%eax` (max with 5); `ret`.
- Rule, stated literally (all comparisons unsigned 32-bit):
  `v0 = (v == 0 ? 11 : v)`; `v = min(v0, hi)`; `v = max(v, lo)`;
  `v = min(v, 12)`; `v = max(v, 5)`; return v, where
  `hi = bsr(low32(rsi)-1) - low32(rcx)` (mod 2^32) and
  `lo = min(bsr(low32(rsi))+1, bsr(low32(rdx))+2)`.
  The chain is not a true clamp: when lo > hi the min-then-max order
  matters (for example v=7, rsi=8, rdx=8, rcx=0 gives 5, not a clamped 7).
- bsr-undefined caveat, stated exactly: bsr of zero is architecturally
  undefined, and the bytes contain no zero guards, so the rule is defined
  only when the low 32 bits of rsi, rdx, and (rsi-1) are all nonzero —
  equivalently low32(rsi) not in {0, 1} and low32(rdx) != 0. No behavior
  is claimed for those inputs.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  zero direct `e8` sites. This is explicitly not a complete xref census.
- Data edge: a full-section scan of every `.rela.*` section finds no
  relocation record of any type naming this window as addend.
- No scout correction was needed: every scouted element verified exactly
  (FDE range, 88-byte body, all instructions, the hi derivation, zero
  callers, no naming relocation).

## Inferences

- The "bsr clamp ladder" label is an inference from the observed rule
  (bsr-derived bounds applied as a min/max ladder), kept separate from
  the rule itself.
- The window's position, `0x556e980`, sits far from every previously
  claimed window (nearest claimed: the multiply-mix divide-by-61 store
  `0x5553fe0`, `0x1a9a0` away), so no overlap is claimed or implied.

## Unknowns

- The meaning of the four arguments, the constants 11/12/5, and the
  bsr-derived bounds is unknown and not claimed.
- Whether any indirect or non-`e8` caller exists is unknown; the scan above
  is a byte pattern, not a census.

## Limits

- No stdlib type, source-level function, argument meaning, or caller
  purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a
  naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and
  generated progress files are unchanged.
