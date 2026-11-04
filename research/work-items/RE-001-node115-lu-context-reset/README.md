# RE-001-node115-lu-context-reset: the node #115 lu context reset

## Summary

Packet #247's next question: what sits next to the per-slot list insert
in the call graph — the neighbour FDE `0x63d8a00..0x63d8b15`, immediately
after the insert FDE, which ends exactly at `0x63d8a00`.

It is the lu context **reset**: a single FDE, `0x63d8a00..0x63d8b15`
(277 bytes, `endbr64` entry, one `ret` site at `0x63d8b14`, eight
static call sites to one helper). It zeroes the whole lu context object
from `+0x0` through `+0x14a0` (5280 bytes): first a loop that calls the
16-byte zero helper `0x63b9660` (cited only) on 64 consecutive slots at
`+0x0..+0x400`, then two `rep stos` regions with explicit head/tail
stores covering `+0x400..+0x14a0` contiguously. That span is exactly the
structures the recent packets decoded: the global triple (`+0x408`/
`+0x410`/`+0x418`), the `+0x420`-based counter region, the slot-pointer
table (`+0x1088` base), the `+0x1488` bitmap, and the `+0x1498` anchor.
It reads no block field, writes no block key, and calls nothing but the
zero helper. Its only known caller is site `0x63b9080` (cited only).

## Entry contract

- `rdi` = first-argument object (saved in `rbp` and `rbx`, kept live).
- No other argument is used: the loop limit is `first-arg + 0x400`,
  and every store address derives from `first-arg`.
- No return value is established by these bytes: the single `ret` path
  returns through the pops epilogue; `rax` still holds the `rep stos`
  fill value 0, incidentally, not as a set result.
- The function reads no block field: it never loads `[block+0x68]`,
  `[block+0x10]`, or any flag byte. It only writes zeros.

## Entry

1. `endbr64`; `push %r12`; `lea 0x400(%rdi),%r12` (loop limit);
   `push %rbp`; `rbp := rdi`; `push %rbx`; `rbx := rdi`;
   `nopl (%rax)` (alignment padding, 3 bytes).
2. Control falls into the loop at `0x63d8a18`.

## The helper loop: 64 slots at +0x0..+0x400

Each iteration issues 8 calls to the helper `0x63b9660` (cited only —
20-byte FDE `0x63b9660..0x63b9674`: `endbr64`, `movq $0,(%rdi)`,
`movq $0,0x8(%rdi)`, `ret`), on 8 consecutive 16-byte slots:

- Loop-head call on `rbx` itself, then `lea` calls on `rbx+0x10`
  through `rbx+0x70` — except the last call of the iteration, which
  uses the `rbx+0x70` address computed just before the stride update.
- `sub $0xffffffffffffff80,%rbx` adds `0x80` to `rbx` (the immediate
  is −128, so subtracting it advances by 128 bytes).
- `cmp %r12,%rbx; jne 0x63d8a18` exits when `rbx` reaches
  `first-arg + 0x400`.

So 8 iterations × 8 slots = 64 slots × 16 bytes = 1024 bytes
(`+0x0..+0x400`) zeroed, two qwords at a time, through the helper.
The loop body is fully unrolled per iteration (8 static sites, one
dynamic helper call per slot), not a per-slot loop.

## First zero region: +0x400..+0x1080

1. `lea 0x428(%rbp),%rdi`; `mov %ebp,%ecx` (low 32 bits of
   first-arg); `pxor %xmm0,%xmm0`; `xor %eax,%eax` (fill value 0);
   `and $-8,%rdi` (8-align the destination).
2. Explicit stores: `[first-arg+0x400] := 0` (8 bytes),
   `movups %xmm0,0x408(%rbp)` (16 bytes: `+0x408` and `+0x410`),
   `[first-arg+0x418] := 0`, `[first-arg+0x420] := 0`.
3. `sub %edi,%ecx; add $0x1080,%ecx; shr $0x3,%ecx` — with the
   8-alignment the guard establishes, the count is
   `(0x1080 − 0x428) / 8 = 395` qwords.
4. `[first-arg+0x1078] := 0` (the last qword of the `rep stos`
   range, stored explicitly as well), then
   `rep stos %rax,%es:(%rdi)` writes 395 zero qwords from
   `first-arg+0x428` through `first-arg+0x1080`.

Net: `+0x400..+0x1080` contiguously zeroed. This covers the global
triple (`+0x408`/`+0x410`/`+0x418`, the same triple #243 decrements
and #246 increments) and the `+0x420`-based region
(`+0x420..+0x1080` = 1632 bytes = 34 48-byte strides).

## Second zero region: +0x1080..+0x14a0

1. `lea 0x1090(%rbp),%rdi`; explicit `[first-arg+0x1080] := 0`
   and `[first-arg+0x1088] := 0` (the slot-pointer table head);
   `and $-8,%rdi`.
2. `sub %rdi,%rdx` (where `rdx = first-arg+0x1088`, set in the
   first region); `lea 0x400(%rdx),%ecx; shr $0x3,%ecx` — with
   8-alignment, `(0x400 − 8) / 8 = 127` qwords.
3. `rep stos` writes 127 zero qwords from `first-arg+0x1090`
   through `first-arg+0x1488`; `[first-arg+0x1480] := 0` (again
   the last qword of the range, stored explicitly as well).
4. `movups %xmm0,0x1488(%rbp)` (16 bytes: bitmap qwords
   `+0x1488` and `+0x1490`); `[first-arg+0x1498] := 0` (anchor).

Net: `+0x1080..+0x14a0` contiguously zeroed. This covers the
slot-pointer table (`+0x1088` base, the table #244/#247 use), the
`+0x1488` bitmap (set side #247, clear side #244), and the
`+0x1498` anchor (the #237 register list anchor #246 reconciles).

## What this decides

- The insert's preconditions are established here: after this reset,
  every slot pointer is 0 (so #247's empty path is the first-insert
  path), every bitmap bit is clear (so #247's empty-only set is
  well-defined), and the anchor is 0 (so #247's anchor splice starts
  from an empty list).
- The counter preconditions are established here: the global triple
  starts at zero, matching the decrement/increment bookkeeping of
  #243/#246, which assume a zero start rather than setting it.
- The reset is a whole-object zero, not a per-structure init: the
  `+0x0..+0x400` helper region and the `+0x400..+0x14a0` direct
  region are contiguous with no gaps, so the object footprint is at
  least `0x14a0` bytes.
- The single caller site (see Census) means this reset runs from one
  call graph position, not from every user of the structures — but
  the caller FDE itself is not decoded here.

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63d8a00..0x63d8b15`, 277 bytes); `endbr64` entry; no
  padding before (the #247 insert FDE ends exactly at `0x63d8a00`);
  `int3` padding `0x63d8b15..0x63d8b20` (11 bytes, before the next
  FDE at `0x63d8b20`, cited only). Static analysis only; the binary
  was never executed.
- 4 exhibits, 277 bytes (the whole FDE), 57 strict instructions
  (strict = mnemonic-line count: address + bytes field + tab +
  mnemonic; objdump byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `rs_entry` | `0x63d8a00..0x63d8a18` | 24 | 8 | Entry, loop limit, arg saves |
| `rs_loop` | `0x63d8a18..0x63d8a68` | 80 | 19 | Helper loop, +0x80 stride, exit test |
| `rs_zero1` | `0x63d8a68..0x63d8ac3` | 91 | 15 | First zero region, rep stos |
| `rs_zero2` | `0x63d8ac3..0x63d8b15` | 82 | 15 | Second zero region, bitmap, anchor, ret |

- Census: direct `E8` call sites to `0x63d8a00`: 1 — `0x63b9080`
  (inside FDE `0x63b8fe0..0x63b9180`, cited only; the `lea`
  immediately before the site computes first-arg as `r15+0x140`).
  Direct `E9` jump sites: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63d8a00`: 0 of 60,723 entries.
  Internal calls within the FDE: 8 static sites, all to `0x63b9660`
  (one helper, cited only). Internal jump targets: the loop-back
  `jne 0x63d8a18` only. One `ret` site: `0x63d8b14`.
- Disjointness: this FDE overlaps no claimed range from packets
  #183–#247 (16,177 exhibit/FDE ranges checked across the merged
  tree and the prior worktree records, 0 overlaps) and no other
  contributor's topic, addresses, or tables. The insert, the
  register, the re-register, the size mapper, the handoff, the
  post-remove unlink, the give-back, the removal entry, the class
  remove, the entry probe, the gate, the driver, and the allocator
  thunk are cited by address, not claimed here.

## Corrections to earlier packets

- **#247 confirmed and completed.** Its insert's preconditions —
  slot 0, bitmap bit clear, anchor 0 — are exactly what this reset
  establishes, on the same table base (`+0x1088`), bitmap
  (`+0x1488`), and anchor (`+0x1498`).
- **#246 confirmed.** Its global triple (`+0x408`/`+0x410`/
  `+0x418`) is zeroed here; its `+0x420`-based counter region is
  zeroed here through `+0x1080` (see the unresolved stride bound
  below for indices past 33).
- **#244 confirmed.** Its slot-pointer table, bitmap, and anchor
  are zeroed here, on the same addresses and with the same
  empty-path semantics.
- **#243 confirmed.** Its global triple is zeroed here; the
  give-back's decrements assume this zero start.
- **#242, #241, #240, #239, #238, #236, #235, #234, #233, #232,
  #216 confirmed.** Nothing of theirs is re-claimed here; the
  reset touches no queue, chain, class, gate, driver, or allocator
  structure beyond the zero writes above.

## Unresolved

- Whether the `+0x420`-based counter table extends beyond `+0x1080`:
  #246's size-arm index can reach 199, which would address
  `+0x420 + 48*199 = +0x2970`, past this reset's bound — whether
  those high slots are reset elsewhere or the index is bounded in
  practice is not decided here.
- What the `+0x0..+0x400` helper-zeroed region is: 64 16-byte slots
  are proved, but their domain role (lock array, pair table, or
  other) is not claimed — the helper only proves zero pairs.
- The caller FDE `0x63b8fe0..0x63b9180` is not decoded: why the
  reset runs from that one site, and whether the object is ever
  re-reset after first init, are open.
- Whether the first-arg object is 8-aligned in practice: the
  `rep stos` counts above assume the alignment the `and $-8`
  guards establish; an unaligned object would shift the first
  region's start down by up to 7 bytes, which the code tolerates
  but is not observed.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#249)

Decode the neighbour FDE `0x63d8b20..0x63d8e67` end to end: what it
does with its arguments, what it calls, and how it relates to this
reset — deciding what sits next to the reset in the call graph.

## Verification

- `tools/node115_lu_context_reset.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, entry bytes, one `ret` site, eight call rel32s, key
  bytes, jump targets internal, full census, neighbour
  disjointness, MANIFEST coverage (13 entries).
- `tests/test_node115_lu_context_reset.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7167 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout (verified for #242; base unchanged
  since), so this is pre-existing upstream staleness from
  the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone. Note: the worktree's `AGENTS.md`
  says to run `make verify test catalogue-check`, but the
  parent task's explicit no-full-`make test` rule outranks
  it; the deviation is disclosed here, as in #245/#246/#247.

## Files (14)

- `research/work-items/RE-001-node115-lu-context-reset/README.md`
- `research/work-items/RE-001-node115-lu-context-reset/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-context-reset/records.json`
- `research/work-items/RE-001-node115-lu-context-reset/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-context-reset/rs_entry.hex`
- `research/work-items/RE-001-node115-lu-context-reset/rs_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-context-reset/rs_loop.hex`
- `research/work-items/RE-001-node115-lu-context-reset/rs_loop.objdump.txt`
- `research/work-items/RE-001-node115-lu-context-reset/rs_zero1.hex`
- `research/work-items/RE-001-node115-lu-context-reset/rs_zero1.objdump.txt`
- `research/work-items/RE-001-node115-lu-context-reset/rs_zero2.hex`
- `research/work-items/RE-001-node115-lu-context-reset/rs_zero2.objdump.txt`
- `tools/node115_lu_context_reset.py`
- `tests/test_node115_lu_context_reset.py`
