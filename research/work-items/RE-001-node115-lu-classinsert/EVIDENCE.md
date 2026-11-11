# RE-001-node115-lu-classinsert: the node #115 lu class insert — key, count, spine rotation

- Component ID: lu size-class entry insertion (tail-jump target of the #238 handoff's size path)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30` (confirmed by fetch before analysis; unmoved)
- Claim status: observation for all byte-level claims (entry zeroing, key compare, insert, min displacement, count update, tzcnt budget, per-step rewiring, census); inference for the "larger stays on the spine" reading of each step (it is the exact pointer-write pattern, but the name "spine" is descriptive); unresolved for the global invariant, the count word's domain meaning, the `+0x38` link's domain meaning, the chain's drain path, and the `0x63b9680` entry probe
- Scope included and excluded: included — the single FDE `0x63b99d0..0x63b9d0c` (828 bytes), its entry contract, its three paths (empty head, min displacement, insert + rotation pass), and its census. Excluded — the handoff, register, gate, driver, allocator thunk, and entry probe (cited by address only); any reader/drain of the entry chains; any Rust implementation.

## Reproduce

Working directory: a fresh worktree of upstream main `05bc2de30`
(`~/workspace/hl-wt-calls239-115`, local branch
`codex/re-004-calls239-115`; the main clone's HEAD was left untouched
at `2993e46`). Tools: system `objdump`/`readelf`, `python3`.
Static analysis only; the binary was never executed.

- FDE bounds: `readelf --debug-dump=frames artifacts/node/115/hl-node`
  shows `FDE pc=0x63b99d0..0x63b9d0c`.
- Disassembly: `objdump -d --start-address=0x63b99d0
  --stop-address=0x63b9d0c artifacts/node/115/hl-node`.
- Coordinate system: `.text` file offset = VA − 0x1000, confirmed
  against the program headers (`PT_LOAD` file offset `0x1418300`
  ↔ vaddr `0x1419300`); `.rodata` = VA as-is;
  `.data.rel.ro`/`.got` = VA − 0x2000. RELATIVE `.got` slots are
  zero-filled in the file, so the GOT census uses `.rela.dyn`
  addends (60,723 entries).
- Census: byte scan of `.text` for `E8`/`E9` rel32 targets and
  `48`/`4C 8D` rip-relative `LEA` targets equal to `0x63b99d0`,
  plus a `.rela.dyn` addend scan — implemented in
  `tools/node115_lu_classinsert.py` and re-checked independently
  during analysis (0 E8, 1 E9 at `0x63d88a3`, 0 LEA, 0 GOT).
- Disjointness: the full FDE range was checked against 824 exhibit
  ranges from the merged tree and the #235–#238 worktree records —
  zero overlaps, and no record mentions `0x63b99d0`.

## Evidence

Original addresses and coordinate system (VA; file offset = VA −
0x1000 for `.text`):

- Entry `0x63b99d0`: `endbr64`, `pxor %xmm0,%xmm0`, pushes,
  `[block+0x28] := 0` and `[block+0x30] := 0` (`movups`),
  `[block+0x38] := 0` (`movq $0`), head load `[entry]`, empty
  test. Exhibit `tl_entry` (37 bytes, 11 strict).
- Key compare `0x63b99f5..0x63b9a1e`: `edx` = sign of
  `[block+8] − [head+8]` via `setb`/`sbb`; `edx == -1` jumps to
  the min path. Exhibit `tl_cmp` (41 bytes, 11 strict).
- Insert `0x63b9a1e..0x63b9a4d`: `[entry+8] += 1`, block spliced
  after the head (`+0x28`/`+0x30` rewiring, old successor's
  `+0x28` updated when present), count `<= 1` returns through
  the shared epilogue (`ret` at `0x63b9a4c`). Exhibit `tl_insert`
  (47 bytes, 16 strict).
- Min path `0x63b9cc0..0x63b9cd8`: `[block+0x38] := head`,
  `[head+0x28] := block`, `[entry] := block`,
  `[entry+8] := 0`, epilogue (`ret` at `0x63b9cd7`). Exhibit
  `tl_min` (24 bytes, 8 strict).
- Loop head `0x63b9a50..0x63b9a7a`: `count − 1`, `tzcnt`,
  budget in `ebx`, odd/even first-step select. Exhibit `tl_loop`
  (42 bytes, 12 strict).
- Even-path step `0x63b9b10..0x63b9b8a`: pair load, both nodes'
  `+0x28`/`+0x30` cleared, key compare, non-swap relink
  (`[cur+0x28] := next`, `[cur+0x30] := [next+0x38]`,
  `[next+0x38] := cur`, `[next+0x30] := next-next`,
  `[next+0x28] := head`, `[head+0x30] := next`). Exhibit
  `tl_step` (122 bytes, 30 strict).
- Swap forms at `0x63b9c30`, `0x63b9c90`, `0x63b9ce0` and the
  second step of each two-step iteration are covered by the
  verifier's whole-FDE check (every direct jump target lies
  inside the FDE; zero `call` instructions), not exhibited, to
  keep the packet at 18 files.
- Padding: `int3` at `0x63b99c8..0x63b99d0` and
  `0x63b9d0c..0x63b9d10`; the previous FDE ends at `0x63b99c8`
  (the #231 consumer), the next function starts with `endbr64`
  at `0x63b9d10`.
- Analysis was complete for this FDE: the full 828-byte range was
  disassembled and every jump target, call site (none), and ret
  site was enumerated. No execution, no timing, no `.bss`
  dependence.

## Implementation and comparison

Not yet implemented/measured. No Rust code is claimed from this
packet; the packet is evidence only. A future implementation must
reproduce, at minimum: the three entry paths, the count-word
update rules (including the no-increment empty path and the reset
on min displacement), and the exact per-step rewiring for both
rotation directions, with the step budget `tzcnt(count before
insert)` and early exit on chain end.

## Results and limitations

- Static verifier `tools/node115_lu_classinsert.py`: exit 0
  (6 excerpts, 313 bytes, 88 strict, census 1 E9 site, MANIFEST
  17 entries).
- Unit tests `tests/test_node115_lu_classinsert.py`: 10/10, exit 0
  (standalone; regeneration comparison + tamper control).
- `make doctor`: exit 0 (run in the worktree; see run log).
- `make verify`: exit 0 (run in the worktree; see run log).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout per #234–#238, so this is pre-existing
  upstream staleness from the merge wave, not a packet
  regression. Packet files are untracked and the check reads
  tracked files only.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). No suite tally of any kind
  is claimed. This packet's own file passes 10/10 standalone.
- Limitations, stated not smoothed: the global invariant of the
  rotation pass is unresolved (a `tzcnt(count)`-bounded pass
  cannot reorder an arbitrarily long spine); the count word's
  domain meaning is unresolved; the `+0x38` link's domain meaning
  is unresolved; no drain/reader of these chains is decoded;
  the `0x63b9680` entry probe is unresolved. If requesting no
  gate, say so: no progress gate is requested by this packet.
- Next question (#240): decode `0x63b9680` end to end — what it
  checks in the size-class entry, what a nonzero return means
  (it gates the bitmap bit at `first-arg+0x400` in #238), and
  whether it reads the chains built here.
