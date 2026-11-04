# RE-001-node115-lu-alloc: the lu allocator (thunk + worker)

- Component ID: RE-001-node115-lu-alloc
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (105,896,032 bytes)
- Source commit / reference commit: upstream main `8fd8db6` (fetch-confirmed unmoved before analysis)
- Claim status: observation for all decoded paths; inference flagged as unresolved where noted
- Scope included and excluded: included — thunk `0x636b370`, worker `0x636a680` lock protocol, alignment math, size-class selection, slot scan, fresh path, carve, mode store, return contract, census. Excluded — internals of `0x63ac480`, `0x636a140`, `0x6369fe0`, `0x63bf680`; the `.bss` table population; counter-flag semantics.

## Reproduce

Working directory: worktree `~/workspace/hl-wt-calls216-115`, branch
`codex/re-004-calls216-115`. Static analysis only; the node binary
was never executed. Commands:

- `objdump -d --start-address=0x636b370 --stop-address=0x636b37c artifacts/node/115/hl-node` (thunk)
- `objdump -d --start-address=0x636a680 --stop-address=0x636aad8 artifacts/node/115/hl-node` (worker)
- `objdump --dwarf=frames artifacts/node/115/hl-node` (FDE bounds)
- `python3 tools/node115_lu_alloc.py` (static verifier, exit 0)
- `python3 tests/test_node115_lu_alloc.py` (unit tests)
- `make verify`, `make catalogue-check`, `make test`

Tool versions: objdump/readelf GNU Binutils 2.42, Python 3.12.3,
git-lfs 3.4.1. Coordinate system: `.text` file offset = VA − 0x1000.

## Evidence

FDE bounds (from `.eh_frame`): thunk `0x636b370..0x636b37c`
(12B, single `jmp`, no `ret` — tail jump); worker
`0x636a680..0x636aad8` (1112B, single `ret` at `0x636aa0b`).

Thunk bytes (12B, exhibit `al_thunk`): `f3 0f 1e fa` (endbr64),
`45 31 c0` (xor r8d,r8d), `e9 04 f3 ff ff` (jmp rel32 to
`0x636a680`: `0x636b37c - 0xcfc = 0x636a680`).

Worker prologue (exhibit `al_head`, 53B/18 strict): `r15 =
pool+0x60` (mutex), `r14 = thread`, `r12 = (align-arg + 0xf) &
~0xf`, `r13 = (r12 + size - 1) & -r12`, `rbp = r12 + r13`
(total). Stack saves: mode pointer at `[rsp+0x10]`, mask
`-align` at `[rsp+0x8]`, `total-0x10` at `[rsp]`,
`pool+0x20` at `[rsp+0x18]` (contention-helper argument).

Lock: `pthread_mutex_trylock(pool+0x60)` at `0x636a6d0`; failure
goes to `0x636aa10` (`0x63bf680(pool+0x20)`, set `[pool+0x88] =
1`, rejoin at `0x636a6dd`). Hold accounting: `[pool+0x58]++`,
thread-change check against `[pool+0x50]` with `[pool+0x48]++`
and store. Second lock site `0x636a8ef` (fresh path re-lock)
with failure block `0x636aab0` uses the same shape.

Size class: small path reads `.bss` table `0x67277c0` at index
`(total-9) >> 3` (`0x636a706..0x636a70e`); large path at
`0x636aa50` computes `edx = masked + 4*bsr - 23` (bsr on
`2*(total-16) - 1`). Index `> 0xe7` jumps to the fresh path
(`0x636a8b4`). Miss-handler call arithmetic: align `0x40`,
rounded `0x200000`, total `0x200040`, `total-16 = 0x200030 >
0x1000` (large), bsr(`0x40005f`) = 22, masked bits 0, index
`0 + 88 - 23 = 65`, scan `pool+0x4b8..pool+0xf28`.

Scan (exhibit `al_scan`, 38B/8 strict): start
`pool+0xa8 + index*16`, end `pool+0xf28`, remainder dispatch
`((end - start - 0x10) >> 4) + 1) & 7`, unrolled `0x63ac480`
calls stepping `0x10`, nonzero return = found block.

Fresh path (exhibit `al_fresh`, 48B/11 strict): clear
`[pool+0x88]`, unlock `pool+0x60`, call `0x636a140(thread,
pool, pool+0x10, pool+0x94, pool+0x98, rounded, align)` — six
register args plus pushed align. NULL return (`0x636a912..0x636a915`
test-and-jump) leads to clear/unlock/return-NULL at `0x636a9eb`.
Non-NULL links via `+0x8` into `pool+0xa0`, adds `[chunk]` into
`pool+0xf38`, updates `pool+0xf28` from `.rodata 0x450770`,
flag-gated `pool+0xf40` counter.

Carve (exhibit `al_found`, 82B/21 strict): at the block pointer
(`rax`, from `0x63ac480`'s return on the scan path or
`chunk+0x10` on the fresh path): stamp `[block]` low bits to
`0xe80afff`, set `[block+0x8] = requested-rounded + aligned`,
set `[block+0x10]` to the computed remainder, call
`0x6369fe0(pool, block, aligned, aligned, requested)`. Mode
store at `0x636a9d5..0x636a9e7`: if `[rsp+0x10]` (mode) != 0,
`[mode] = [block+0x20]`. Exit at `0x636a9fa..0x636aa0b`:
unlock, `rax = aligned value`, pops, `ret`.

Census: whole-`.text` E8 byte scan with rel32-target filter.
Thunk `0x636b370`: 19 E8 sites (listed in records.json).
Worker `0x636a680`: 1 E8 site (`0x636b3a5`) plus the thunk's
E9 tail jump (`0x636b377`). `.rela.dyn` addend scan (60,723
entries): 0 GOT hits for either target. No LEA sites.

Callers/callees: callers of the thunk include the miss handler
(`0x63d9803`, inside FDE `0x63d9700..0x63d987b`) and the
`0x80`/`0x80` stack-out-pointer wrapper (`0x636b3a5` calls the
worker directly). Callees characterised only: `0x63ac480`
(slot claim), `0x636a140` (fresh chunk), `0x6369fe0`
(remainder re-insert), `0x63bf680` (contention),
`pthread_mutex_trylock/unlock@plt`.

## Implementation and comparison

Not yet implemented/measured. This packet is evidence only; no
reconstructed implementation is claimed.

## Results and limitations

Static verifier exit 0 (5 excerpts, 233 bytes, 61 strict
mnemonics, census 19/1 E8 sites, MANIFEST 15/15). Unit tests 8/8.
`make verify` exit 0 (29 manifests, 471 entries).
`make catalogue-check` exit 0. `make test`: 77 files attempted,
1 failed — the pre-existing `test_node115_catalogue` Errno 18
cross-device-link error, identical on pristine checkouts, not a
packet regression; this packet's file passes 8/8.

Limitations: block `+0x8` word semantics (why aligning it yields
the returned pointer), block `+0x20` mode-out word semantics,
`.bss` table population, and counter-flag semantics are stated
as unresolved, not inferred.
