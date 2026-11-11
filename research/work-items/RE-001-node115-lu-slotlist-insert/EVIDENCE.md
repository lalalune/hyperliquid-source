# RE-001-node115-lu-slotlist-insert: the per-slot list insert

- Component ID: RE-001-node115-lu-slotlist-insert
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30` (confirmed
  before analysis by fetch; worktree HEAD `05bc2de30`)
- Claim status: observation (disassembly-backed) for the insert, the slot
  computation, the bitmap set, and the no-flag-read negative; inference
  for the "append" reading of the splice (stated against the circular
  invariant) and for slot-number ranges; unresolved for the bitmap/slot
  overlap, the register tail's `+0x13` provenance, and the neighbour FDE
- Scope included and excluded: included is FDE `0x63d88d0..0x63d8a00`
  only. Excluded (cited by address only): #246's re-register, #237's
  register (including its tail call site `0x63d967f`), the size mapper
  `0x63e8bf0`, the handoff, the post-remove unlink (#244), the merged
  `0x63ac0d0` slot-insert helper (different function, different list),
  and the neighbour FDE `0x63d8a00..0x63d8b15`.

## Reproduce

Working directory: the worktree at upstream main `05bc2de30`.
Tool versions: GNU objdump 2.42, GNU readelf 2.42, Python 3.12.3.
Static analysis only; the binary was never executed. No network, no
build, no side effects beyond writing this packet's files.

- `objdump -d --start-address=0x63d88d0 --stop-address=0x63d8a00
  artifacts/node/115/hl-node` — the full FDE disassembly.
- `readelf --debug-dump=frames-interp artifacts/node/115/hl-node` —
  FDE `pc=0x63d88d0..0x63d8a00` (this section uses PC-relative
  sdata4 FDE encoding, CIE augmentation `zR`, encoding byte `0x1b`;
  a naive absolute parse returns garbage, per #246).
- `python3 tools/node115_lu_slotlist_insert.py` — static verifier,
  exit 0.
- `python3 -m unittest tests.test_node115_lu_slotlist_insert` — 10/10.
- Coordinate system: `.text` file offset = VA − 0x1000 (program-header
  verified: PT_LOAD off `0x1418300` ↔ vaddr `0x1419300`);
  `.rodata` = VA as-is (no `.rodata` constant is claimed here);
  `.rela.dyn` addends used for the GOT census (file slots are
  zero-filled for RELATIVE entries).

## Evidence

- FDE bounds: `.eh_frame` `pc=0x63d88d0..0x63d8a00`, 304 bytes.
  Entry `55 48 89 fd` (`push %rbp; mov %rdi,%rbp`), no `endbr64`.
  `int3` padding 12 bytes before (`0x63d88c4..0x63d88d0`, after
  #238's handoff which ends at `0x63d88c4`); no trailing padding
  (next FDE starts at `0x63d8a00` with `endbr64`).
- Entry/dispatch: `rax = [block+0x68]`; `jne 0x63d8940` (size arm)
  when nonzero, else the zero arm.
- Zero arm: `rcx = byte[block+0x10] + 0x7e`;
  `rdx = rcx + 0x210`; slot load `mov 0x8(%rbp,%rdx,8),%rax`
  = `first-arg + 0x1478 + 8*byte` = `first-arg + 0x1088 + 8*rcx`;
  `je 0x63d89c0` when the slot is `0`.
- Size arm: `rdi = ([block+0xb0] - [block+0x68]) << 12`;
  `call 0x63e8bf0` at `0x63d894e` (rel32-verified); overflow
  (`> 0x7000000000000000`) stub `r10d = 0x18e = 2*199`,
  `jmp 0x63d89a5`; otherwise the #242 index scheme
  (`bsr`, `+1` unless a power of two via `cmp`/`sbb`, clamped
  to a minimum of 14, shift = `clamped - 3` except `12` when
  `clamped == 14`, index = `((result - 1) >> shift) & 3 +
  4 * (clamped - 14)`), then slot number
  `rcx = ([block+0x10] ^ 1) + 2*index`, `jmp 0x63d88ed`
  (shared slot load).
- Splice (`0x63d8902..0x63d893a`, 16 strict): with
  `H := [slot]`, `T := [H+0x48]`, the stores are
  `[block+0x48] := block`; `[block+0x40] := T`;
  `[H+0x48] := block`; `[block+0x48] := T`;
  `[block+0x40] := H`; `[T+0x40] := block`;
  `[slot] := H` (unchanged); pops; `ret` at `0x63d8939`.
  Net effect against the circular invariant: block inserted
  between tail and head, slot head unchanged.
- Empty case (`0x63d89c0..0x63d89f1`, 13 strict):
  `r10 = rcx >> 6`; `r11 = 1 << cl`;
  `or %r11, 0x1488(%rbp,%r10,8)` (bit `rcx mod 64` of
  qword `rcx / 64` at `first-arg+0x1488`);
  `movups %xmm0, 0x40(%rbx)` with `xmm0 = (block, block)`
  (self-link); `[slot] := block`; pops; `ret` at `0x63d89f0`.
- Flag negative: the FDE's disassembly contains no
  `0x11(`, `0x12(`, `0x13(`, `0x14(`, `0x20(`, or `0x23(`
  displacement (verified by the static verifier's scan of
  every mnemonic line; `0x1488`/`0x210`/`0x120`-style longer
  displacements do not match those patterns).
- Callers (cited only): `0x63d9247` in #246's re-register
  (after its `cmpb $0, 0x13(%rbx)` gate) and `0x63d967f`
  in #237's register tail (after its own `cmpb $0,
  0x13(%rbx)` gate, following its handoff call at
  `0x63d966a`). Both objdump- and rel32-confirmed.
- Census: E8 exactly [`0x63d9247`, `0x63d967f`]; E9 0;
  rip-relative LEA 0 (all `48`/`4c`/`49`/`4d 8d` forms);
  `.rela.dyn` addends equal to `0x63d88d0`: 0 of 60,723.
- Jump targets: every direct jump inside the FDE lands
  inside `0x63d88d0..0x63d8a00` (`jne 0x63d8940`,
  `je 0x63d89c0`, `jb 0x63d89f8`, `jmp 0x63d88ed`,
  `jmp 0x63d89a5`).
- Disjointness: 0 overlaps against the merged tree and
  prior worktree records (merged `0x63ac0d0` helper ranges
  included — different address, different function).
- Slug collision note (honest record): the first draft of
  this packet reused the directory name
  `RE-001-node115-lu-slotinsert`, which the merged base
  already contains for the unrelated `0x63ac0d0` helper.
  Those draft files were deleted before any packet text
  was finalised, and the packet was rebuilt under
  `RE-001-node115-lu-slotlist-insert`; the worktree's git
  status shows only the new directory as untracked, and
  the merged packet's files are untouched.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction is claimed for
this function; the packet is evidence only (exhibits + verifier +
tests), as in packets #183–#246.

## Results and limitations

- 6 exhibits, 285 bytes, 74 strict instructions; verifier exit 0;
  own unit tests 10/10; `make verify` exit 0; `make
  catalogue-check` exit 2 (`Stale catalogue: README.md`,
  pre-existing on pristine `05bc2de30`, not a packet
  regression); full `make test` not attempted (584 files on
  the new base; hours-long, VM-restart liable per #234).
- No gate is requested beyond the packet's own checks.
- What remains unknown: the bitmap/slot overlap resolution;
  the register tail's `+0x13` provenance; one-table vs
  two-uses for the slot numbers; the `[block+0x10]` byte's
  domain meaning beyond slot selection.
- Next question (#248): decode the neighbour FDE
  `0x63d8a00..0x63d8b15` end to end — its arguments, its
  calls, and its relation to this per-slot insert.
