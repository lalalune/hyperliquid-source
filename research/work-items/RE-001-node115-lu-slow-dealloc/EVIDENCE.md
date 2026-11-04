# RE-001-node115-lu-slow-dealloc: deallocator slow path sinks

- Component ID: RE-001-node115-lu-slow-dealloc
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes)
- Source commit / reference commit:
  8fd8db680ec4bfef40996e5616bce3d5156d0b86 (upstream main, confirmed
  unmoved by fetch before analysis)
- Claim status: observation (all claims are byte-backed; the shared
  central structure's layout and the `.bss` selector byte's live value
  are explicitly unresolved, not inferred)
- Scope included and excluded: included — slow-path FDE
  0x635c6d0..0x635de25 only, its dispatch, its TLS push, its
  list-full and page paths, its census, and first-level helper
  outlines (mutex/atomic evidence only). Excluded — the drain helper
  0x51e8720, field-drop callees 0x5a50a10 / 0x5a4d200, #200's
  delegates 0x51f3e20 / 0x57ec1b0 and unwind callee 0x1680cab,
  and full decodes of 0x63ead50 / 0x63eb870 / 0x63637f0 /
  0x63bd6c0 / 0x63be4d0 / 0x63c3330 / 0x6363260 / 0x63eec80.

## Reproduce

Working directory: repository root (worktree at upstream main
8fd8db6). Static analysis only; the node binary was never
executed. Commands (objdump from GNU binutils as shipped in the
environment):

- `objdump -d --start-address=0x635c6d0 --stop-address=0x635de25
  artifacts/node/115/hl-node` — slow-path FDE disassembly
  (5973 bytes, 1220 strict mnemonic lines).
- `readelf --debug-dump=frames artifacts/node/115/hl-node` —
  FDE extents: slow path `pc=0x635c6d0..0x635de25`, fast path
  `pc=0x635de30..0x635ded5`, helpers as cited in README.
- `readelf -r artifacts/node/115/hl-node` — RELATIVE entries:
  `0x64df4a0 -> 0x635de30`, `0x64ffb30 -> 0x6349380`.
- Whole-`.text` byte scan (`.text` VA 0x1419300, file offset
  0x1418300, size 0x4fd7700): E8/E9 rel32 targets, REX+8D
  rip-relative LEA targets, `.rela.dyn` addends. No execution,
  no side effects.

## Evidence

Coordinate system: `.text` file offset = VA - 0x1000,
`.data.rel.ro`/`.got` file offset = VA - 0x2000, `.rodata` VA
as-is. `rbx` in the slow path is `TLS base - 0x10a8`; all
`rbx`-relative offsets below use that base.

- Entry: `0x635c6d0` endbr64, prologue, `fs:0x28` canary saved
  at `rsp+0x78`, thread-state flag `fs:0x330(%rbx)`.
- Dispatch branches (all inside the dispatch exhibit):
  align test `0x635c730 -> 0x635c890`; oversized
  `0x635c73d -> 0x635cc58`; flags `0x635c765 -> 0x635ca40`;
  flag recheck `0x635c774 -> 0x635d128`; page-aligned
  `0x635c78d -> 0x635cce8`; class-size oversized
  `0x635c7a1 -> 0x635cd88`; flag-clear `0x635c7b9 ->
  0x635c900`; class `> 0x23` `0x635c7d6 -> 0x635d080`;
  null slot base `0x635c7df -> 0x635d010`; list-full
  `0x635c7fd -> 0x635cdf8`; budget `0x635c85b -> 0x635ccd0`.
- TLS push: `0x635c7e5..0x635c886` (slot `rbx+0x358 +
  class*24`, head `[slot+0x8]`, bound `[slot+0x1a]` low-16,
  budget store `rbx+0x348`, canary check, ret at `0x635c886`).
- List-full drain: `0x635cdf8..0x635ce47` (call `0x63ead50`
  at `0x635ce27`, re-check, push at `0x635ce3b` or
  budget-return at `0x635c80f`). Large-class drain: calls
  `0x63eb870` at `0x635c97e` / `0x635cc2d`. Mutex evidence:
  `pthread_mutex_trylock` call at `0x63eaf51` (inside
  `0x63ead50`), `lock add` at `0x63eba30` and `lock addq` at
  `0x63eba3b` (inside `0x63eb870`), `memmove` in both helpers.
- Page path: `0x635cce8..0x635cd7f` (segment slot
  `(ptr >> 0x1a) & 0xf0` at `rbx+0x1b0`, key check, page
  `(ptr >> 9) & 0x1ffff8` at segment `+0x1b8`, call
  `0x63bd6c0` at `0x635cd7a`, jump to budget-return).
  Segment cache: `rbx+0x2b0` key / `rbx+0x2b8` page base,
  8-slot scan loops (compare against 8, e.g. `0x635db55`),
  miss registers via `0x63d9700`.
- Page pair: calls `0x63be4d0` at `0x635d0dd` and `0x63c3330`
  at `0x635d0f4`, gated on out-word `[rsp+0x38] > 1`.
  Page-owning free: call `0x63637f0` at `0x635ce56`;
  `0x63637f0` contains `pthread_mutex_trylock` /
  `pthread_mutex_unlock` and no `munmap`/`madvise`.
- Poison: guard `cmpb $0, 0x6511749` at `0x635cba0`,
  taken branch to `0x635ce78`; GOT call `ff 15 a8 2c 1a 00`
  at `0x635ce82` through slot `0x64ffb30`; stub
  `0x6349380`: `mov %rsi,%rdx; mov $0x5a,%esi;
  jmp memset@plt`; re-dispatch `jmp 0x635cbad`.
- No-OS evidence: byte scan of the 5973 slow-path FDE bytes
  finds zero `0f 05` pairs; the FDE's direct-call list contains
  no PLT call except `abort@plt` and `__stack_chk_fail@plt`;
  scans of all 15 first-level helper FDEs
  (`0x63637f0`, `0x63bd6c0`, `0x63be4d0`, `0x63c3330`,
  `0x6363260`, `0x63ead50`, `0x63eb870`, `0x63eec80`,
  `0x63ef8e0`, `0x63b73a0`, `0x63ed8b0`, `0x63495b0`,
  `0x6349510`, `0x63d9700`, `0x63bf5b6`) find no `munmap`,
  `madvise`, or `syscall` edge.
- Census: whole-`.text` raw scan — 0 E8 targets equal
  `0x635c6d0`, 1 E9 target (`0x635ded0`, bytes
  `e9 fb e7 ff ff`, verified by disassembly), 0 rip-relative
  LEA targets, 0 `.rela.dyn` RELATIVE addends equal
  `0x635c6d0`. Fast path guard exits to `0x635ded0`:
  `0x635de3b` (ja), `0x635de43` (jne), `0x635de4f` (je),
  `0x635de87` (jae), `0x635deac` (je).
- Huge class: `mov $0xe8` at `0x635d3e0` /
  `0x635d6dc` / `0x635d99f` / `0x635dade`; threshold
  `0x7000000000000000` (`movabs` at `0x635cc58`,
  `0x635c9a0`, `0x635cd88`, `0x635cfa1`, `0x635d1e6`,
  `0x635d330`, `0x635d591`).
- Analysis completeness: the slow-path FDE was read in full
  (1220 strict lines); helper FDEs were outlined by call,
  lock, and PLT evidence only, not fully decoded.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction, no
build, no equivalence claim. This packet is evidence only.

## Results and limitations

- Passed: verifier exit 0; unit tests 8/8; MANIFEST 11/11;
  `make verify` exit 0; `make catalogue-check` exit 0;
  `make test` 77 files with only the pre-existing
  test_node115_catalogue Errno 18 failure.
- Unknown: the central pool's exact layout; the live value of
  the `.bss` selector byte `0x6713606` and poison byte
  `0x6511749`; whether emptied pages ever reach the OS at
  deeper call levels (no edge within one level).
- Next question: decode the central-flush helpers
  `0x63ead50` / `0x63eb870` — the shared structure they move
  full class lists into, its layout, locking, and per-entry
  pushes (`0x63612b0` / `0x63bd640`).
