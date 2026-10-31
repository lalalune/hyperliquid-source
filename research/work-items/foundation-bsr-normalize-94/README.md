# foundation-bsr-normalize-94

## Question

Bind one small, previously unclaimed window in node #94 whose rule reads
directly from its own bytes: a bsr/normalize helper with two paths — a
flag path returning 0 or 0x100, and a main path that derives a base from
bsr([rdi]+1) and returns esi minus that base. No family census, no
shared-primitive decode, no component map is claimed.

## Target

- Node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (`artifacts/node/94/hl-node`).
- Window: `[0x55c9800, 0x55c9830)`, 48 bytes, `.eh_frame+0x2d3cec`,
  CIE at section offset 0, zR pcrel sdata4
  (field VA `0xfb520c` + `0x46145f4` = `0x55c9800`, range `0x30`),
  confirmed with GNU `objdump --dwarf=frames`.
- Padding: 0 bytes — the next FDE starts immediately at `0x55c9830`.
  The checker locks the next FDE's decoded start at exactly `END`;
  there is no int3 stride to lock. Next FDE is
  `[0x55c9830, 0x55c9989)`.

## Scope

Included: the window's bytes, its FDE record, the next FDE record, the
four retained direct callers and their shared FDE record, the full
`.rela.*` scan, and the two-path rule below.

Excluded: the meaning of the loaded word, the flag arguments, or the
returned value; caller purpose beyond the calls themselves; any stdlib
type or source-level function; any provenance for the window; and any
other window in `0x55c9xxx`.

## Reproduce

```sh
objdump -d --start-address=0x55c9800 --stop-address=0x55c9830 \
  artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node | grep -A 4 '55c9800'
python3 tools/foundation_bsr_normalize.py \
  --check research/work-items/foundation-bsr-normalize-94/evidence.json
python3 -m unittest tests.test_foundation_bsr_normalize -v
make verify test catalogue-check
```

## Observations

Decoded behavior, verified from bytes, zero calls, two forward branches:

```text
endbr64
mov    %ecx,%eax              # save original ecx for the later test
cmp    $0x1,%edx
je     0x55c9824              # low32(edx) == 1 -> flag path
mov    (%rdi),%edx            # 32-bit load
add    $0x1,%edx              # w = word + 1 (mod 2^32)
bsr    %edx,%ecx              # t = bsr(w); undefined iff w == 0
mov    %ecx,%edi
shl    $0x8,%edi              # base = t << 8
test   %eax,%eax              # original ecx
je     0x55c981f              # original ecx == 0 -> skip the add
shl    $0x8,%edx              # w << 8 (32-bit)
shr    %cl,%edx               # (w << 8) >> t
add    %edx,%edi              # base += (w << 8) >> t
mov    %esi,%eax
sub    %edi,%eax              # return low32(esi) - base (mod 2^32)
ret
# flag path:
test   %ecx,%ecx              # original ecx (untouched on this path)
setne  %al
movzbl %al,%eax
shl    $0x8,%eax              # return 0x100 if ecx != 0, else 0
ret
```

Rule, all arithmetic 32-bit: if low32(edx) == 1, return
(low32(ecx) != 0 ? 0x100 : 0). Otherwise let w = (u32 [rdi] + 1) mod
2^32 and t = bsr(w); base = t << 8, plus ((w << 8) >> t) when low32(ecx)
!= 0 (the ecx tested here is the entry value, saved into eax by the
first instruction before bsr overwrites ecx); return
(low32(esi) − base) mod 2^32.

The window opens directly with the first move — no `endbr64` is present
at this window's start (the retained bytes begin with `89 c8`); this is
an observation, not a scout deviation.

bsr-undefined caveat, stated exactly: bsr of zero is architecturally
undefined and the bytes contain no zero guard, so the main-path rule is
defined only when w != 0, i.e. when u32 [rdi] != 0xffffffff. No behavior
is claimed for that input; the model returns None for it and the tests
assert only the exclusion.

Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
exactly four direct `e8` sites, each confirmed as an instruction start
by linear disassembly from the caller FDE start
(`0x55caf70..0x55cc408`), all in that single caller FDE:
`0x55cb6fb` (bytes `e8 00 e1 ff ff`), `0x55cb7f0` (bytes
`e8 0b e0 ff ff`), `0x55cbde5` (bytes `e8 16 da ff ff`),
`0x55cc00a` (bytes `e8 f1 d7 ff ff`). This scan is explicitly not a
complete xref census. Caller purpose beyond the calls themselves is not
claimed.

Data edge: no relocation record of any type in any `.rela.*` section
names this window as addend (full-section scan of `.rela.dyn` and
`.rela.plt`: 80,022 + 278 entries).

## Scout precision note

Not a behavior correction: the scout listed the caller FDE end as
`0x55cc410`; the exact end from `--dwarf=frames` is `0x55cc408` (the
scout end is the following FDE start, the same pattern seen in packets
#50/#51/#53/#55). Call sites, call bytes, and the window rule all
verified exactly as scouted; the checker locks the exact end. No other
scout element needed correction.

## Inferences

The "bsr/normalize" label is an inference from the bsr-derived base and
the esi-minus-base return. The flag path (0 or 0x100) and the
(w << 8) >> t refinement suggest a normalization step, but no quantity,
type, or meaning is claimed.

## Unknowns

- What the loaded word, the flags, or the returned value means.
- The caller's purpose and the meaning of its arguments.
- Whether any indirect or PLT path reaches this window (the scan covers
  direct `e8` sites only).

## Limits

- The byte-pattern scan is not a complete xref census, and the absence
  of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and
  generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation
  was copied, and every claim is grounded in target bytes for node #94.
- Static analysis only. The captured binary was never executed; no
  network, chain action, or signing was involved.
