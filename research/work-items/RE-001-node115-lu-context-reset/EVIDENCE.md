# RE-001-node115-lu-context-reset: the lu context reset

- Component ID: RE-001-node115-lu-context-reset
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30` (confirmed
  before analysis by fetch; worktree HEAD `05bc2de30`)
- Claim status: observation (disassembly-backed) for the helper loop, the
  two zero regions, the census, and the FDE bounds; inference for the
  "reset" reading (stated against the zero writes and the structures
  #243/#244/#246/#247 decode) and for the rep stos counts (stated under
  the 8-alignment the `and $-8` guards establish); unresolved for the
  `+0x420` stride bound, the `+0x0..+0x400` region's domain role, the
  caller FDE's role, and the neighbour FDE
- Scope included and excluded: included is FDE `0x63d8a00..0x63d8b15`
  only. Excluded (cited by address only): the zero helper `0x63b9660`
  (including its FDE `0x63b9660..0x63b9674`), the caller site `0x63b9080`
  and its FDE `0x63b8fe0..0x63b9180`, the #247 insert
  (`0x63d88d0..0x63d8a00`), the neighbour FDE `0x63d8b20..0x63d8e67`,
  and every structure address from #237/#238/#242/#243/#244/#246/#247.

## Reproduce

Working directory: the worktree at upstream main `05bc2de30`.
Tool versions: GNU objdump 2.42, GNU readelf 2.42, Python 3.12.3.
Static analysis only; the binary was never executed. No network, no
build, no side effects beyond writing this packet's files.

- `objdump -d --start-address=0x63d8a00 --stop-address=0x63d8b15
  artifacts/node/115/hl-node` — the full FDE disassembly.
- `.eh_frame` parsed directly (this section uses PC-relative sdata4
  FDE encoding, CIE augmentation `zR`, encoding byte `0x1b`; a naive
  absolute parse returns garbage, per #246) — FDE
  `pc=0x63d8a00..0x63d8b15`, 277 bytes; neighbours `0x63d88d0..0x63d8a00`
  (#247) and `0x63d8b20..0x63d8e67`.
- `python3 tools/node115_lu_context_reset.py` — static verifier,
  exit 0.
- `python3 -m unittest tests.test_node115_lu_context_reset` — 10/10.
- Coordinate system: `.text` file offset = VA − 0x1000 (program-header
  verified: PT_LOAD off `0x1418300` ↔ vaddr `0x1419300`);
  `.rodata` = VA as-is (no `.rodata` constant is claimed here);
  `.rela.dyn` addends used for the GOT census (file slots are
  zero-filled for RELATIVE entries).

## Evidence

- FDE bounds: `.eh_frame` `pc=0x63d8a00..0x63d8b15`, 277 bytes.
  Entry `f3 0f 1e fa 41 54` (`endbr64; push %r12`); no padding before
  (#247's insert ends at `0x63d8a00`); `int3` padding 11 bytes after
  (`0x63d8b15..0x63d8b20`); next FDE starts `0x63d8b20` with
  `endbr64`.
- Entry: `lea 0x400(%rdi),%r12` (loop limit); `rbp := rdi`;
  `rbx := rdi`; `nopl (%rax)` alignment padding.
- Loop: 8 static `E8` sites (`0x63d8a1b`, `0x63d8a24`, `0x63d8a2d`,
  `0x63d8a36`, `0x63d8a3f`, `0x63d8a48`, `0x63d8a51`, `0x63d8a5e`),
  all rel32-verified to `0x63b9660`; stride `sub $-128` = +`0x80`;
  exit `cmp %r12,%rbx; jne 0x63d8a18` at `rbx == first-arg+0x400`.
  8 iterations × 8 slots × 16 bytes = `+0x0..+0x400`.
- Helper (cited only): `0x63b9660..0x63b9674`, 20 bytes:
  `endbr64`, `movq $0,(%rdi)`, `movq $0,0x8(%rdi)`, `ret`.
- First zero region: explicit `+0x400`, `movups` at `+0x408`
  (covers `+0x408`/`+0x410`), `+0x418`, `+0x420`; count
  `(0x1080 − 0x428) / 8 = 395` qwords; `rep stos` from `+0x428`;
  explicit `+0x1078` (last qword of the range). Net `+0x400..+0x1080`.
- Second zero region: explicit `+0x1080`, `+0x1088`; count
  `(0x400 − 8) / 8 = 127` qwords; `rep stos` from `+0x1090`;
  explicit `+0x1480` (last qword of the range); `movups` at `+0x1488`
  (covers `+0x1488`/`+0x1490`); `+0x1498`. Net `+0x1080..+0x14a0`.
- Census: `E8` to `0x63d8a00`: 1 site (`0x63b9080`, objdump- and
  rel32-confirmed; preceding `lea 0x140(%r15),%rdi` computes
  first-arg); `E9`: 0; rip-relative `LEA` (all `48`/`4c`/`49`/`4d 8d`
  forms): 0; `.rela.dyn` addends: 0 of 60,723.
- Disjointness: 16,177 ranges from the merged tree and prior
  worktree records checked recursively (exhibit `range` entries plus
  top-level `fde` ranges), 0 overlaps with this FDE or its exhibits.
- Slug check: `RE-001-node115-lu-context-reset` does not collide
  with any merged-tree packet directory (unlike #247's draft slug,
  which collided with the merged `lu-slotinsert` helper).

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed here.
The packet is evidence only — the reset's byte behaviour is fully
specified above for a future implementation to test against.

## Results and limitations

- 4 exhibits, 277 bytes (whole FDE), 57 strict instructions.
- Verifier exit 0; unit tests 10/10; `make verify` exit 0
  (559 manifests, 7167 entries); `make catalogue-check` exit 2
  (`Stale catalogue: README.md`, pre-existing on the `05bc2de30`
  base, not a packet regression); full `make test` not attempted
  (584 files on the new base; hours-long, VM-restart liable per
  #234 — deviation from the worktree `AGENTS.md` disclosed in the
  README and body, as in #245/#246/#247).
- Open: the `+0x420` stride bound past `+0x1080`, the domain role
  of the `+0x0..+0x400` region, the caller FDE's role, and the
  neighbour FDE `0x63d8b20..0x63d8e67`.
- Next question (#249): decode the neighbour FDE
  `0x63d8b20..0x63d8e67` end to end — its arguments, its calls,
  and its relation to this reset.
