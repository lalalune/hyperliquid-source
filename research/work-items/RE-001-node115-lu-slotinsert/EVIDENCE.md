# RE-001: the node #115 lu slot-insert helper — evidence

- Component ID: RE-001-node115-lu-slotinsert
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), artifact `artifacts/node/115/hl-node`
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all byte claims below; inference only
  where marked; unresolved items listed at the end
- Scope included and excluded: the insert FDE `0x63ac0d0..0x63ac472`
  only. Caller FDEs, the slot-claim FDE, and the remainder FDE are
  cited by address only. No execution of the node binary at any point.

## Reproduce

Worktree `~/workspace/hl-wt-calls219-115`, branch
`codex/re-004-calls219-115`, from origin/main of
`~/workspace/hyperliquid-source` (main clone HEAD untouched at
`2993e46`). Tools: GNU objdump 2.42, readelf 2.42, python3 3.12.3.
`make doctor` exit 0, `analysis_ready: true` (after restoring git-lfs
3.4.1 from `~/workspace/scratch-git-lfs/git-lfs-3.4.1/git-lfs`, the
22nd observed loss, and the standard fresh-worktree submodule init).
Coordinate system: `.text` file offset = VA − 0x1000.

## Evidence

- FDE bounds from `objdump --dwarf=frames`:
  `pc=00000000063ac0d0..00000000063ac472` (930 bytes). Two `ret`
  sites: shared exit `0x63ac16e`, insert-before exit `0x63ac443`.
  Zero `call` instructions in the FDE (grep over the full
  disassembly); the helper is pure inline splice code.
- Entry (`si_entry`, 47B/14 strict): `endbr64` at `0x63ac0d0`;
  `movups %xmm0,0x28(%rsi)` at `0x63ac0e7` zeroes the node's `+0x28`
  pair; `movq $0,0x10(%rcx)` at `0x63ac0ee` zeroes `+0x38`
  (`rcx = node+0x28`); `mov (%rdi),%rsi` at `0x63ac0eb` loads the
  head; `je 0x63ac3e0` at `0x63ac0f9` on a NULL head.
- Key comparison (`si_cmp`, 48B/16 strict): `+0x20` words, then
  `+0x8` words on a tie, via the `setb`/`sbb` signum idiom
  (e.g. `0x63ac111`–`0x63ac11d` for `+0x20`, `0x63ac123`–`0x63ac12c`
  for `+0x8`). Result -1 means the node key is smaller.
- After-head splice (`si_splice`, 36B/10 strict): `[slot+8]++`
  (`0x63ac13c`–`0x63ac144`), `node+0x30 = old head+0x30`
  (`0x63ac14c`), successor backlink (`0x63ac155`, guarded by NULL),
  `node+0x28 = head` (`0x63ac159`), `head+0x30 = node`
  (`0x63ac15c`), then `cmp $0x1,%rbp; ja 0x63ac170`
  (`0x63ac160`) on the new second word.
- Merge walk (`si_merge`, 28B/9 strict): `sub $0x1,%rbp`
  (`0x63ac170`), `tzcnt %rbp,%r12` (`0x63ac177`), budget in `r10d`
  (`0x63ac17c`), zero-budget and NULL-node early returns
  (`0x63ac182`, `0x63ac187`), parity test `test $0x1,%r12b`
  (`0x63ac191`) selecting the starting block. Step counter `r9d`
  (set to 1 at `0x63ac227`, incremented at `0x63ac2e1`/`0x63ac376`)
  is compared against the budget at `0x63ac238` and `0x63ac385`.
  Merge splices use `movups` pair stores into `+0x28` slots plus
  backlink writes (e.g. `0x63ac205`, `0x63ac213`, `0x63ac21a`,
  `0x63ac22d`–`0x63ac235`); passed-over nodes get `+0x28` pairs
  zeroed from `xmm8` (e.g. `0x63ac26b`, `0x63ac277`).
- Insert-before (`si_before`, 28B/10 strict): `node+0x38 = head`
  (`0x63ac428`), `head+0x28 = node` (`0x63ac42c`),
  `[slot] = node` (`0x63ac430`), `[slot+8] = 0`
  (`0x63ac433`), pops + `ret` at `0x63ac443`.
- Empty slot (`0x63ac3e0`, cited): `[slot] = node`, then the shared
  exit check on the old second word.
- Census: whole-`.text` E8 scan with rel32-target filter, each hit
  confirmed by objdump as `call 63ac0d0`: 6 sites (`0x635f3f7`,
  `0x635f497`, `0x636370d`, `0x63637c7`, `0x636a035`, `0x63b0675`);
  0 E9, 0 LEA (rip-relative scan), 0 GOT (60,723 `.rela.dyn`
  addends, no hit for `0x63ac0d0`; file-content scan would miss
  zero-filled RELATIVE slots).
- No-drop argument: every control path stores the node — empty slot
  to head, smaller key to new head, greater-or-equal key spliced
  after the head before any walk exit — and no path frees memory or
  returns a status. Equal keys take the after-head path.

## Implementation and comparison

Not yet implemented/measured. Static verifier
`tools/node115_lu_slotinsert.py` and unit tests
`tests/test_node115_lu_slotinsert.py` only (byte regeneration,
tamper control, strict counts, key bytes, FDE bounds, census spot,
MANIFEST coverage).

## Results and limitations

- Static verifier: exit 0 (5 excerpts, 187 bytes, 59 strict,
  census 6 E8 sites, MANIFEST 15/15).
- Unit tests: 9/9 (see suite run for the in-suite count).
- `make verify`, `make catalogue-check`, `make test`: verify exit 0
  (29 manifests, 471 entries), catalogue-check exit 0, test wrapper
  exit 2 read directly from make's own exit status — 77 files
  attempted, single failure is the pre-existing
  `test_node115_catalogue` Errno 18 cross-device-link error,
  identical on pristine checkouts; own file [36/77] passes 9/9.
- Unresolved: chain invariant (tree vs list); the slot second
  word's semantic identity and the `tzcnt` bound's rationale;
  purposes of the five non-remainder callers; fresh-slot chain
  population.
- Next question: decode FDE `0x6363660..0x63637e2` end to end
  (two slot-insert calls at `0x636370d` and `0x63637c7`).
