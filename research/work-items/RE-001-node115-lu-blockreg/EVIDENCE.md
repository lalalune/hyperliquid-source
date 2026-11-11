# RE-001-node115-lu-blockreg: the node #115 lu block register

- Component ID: lu block register (`0x63d94b0`), anchor getter
  (`0x63d94a0`)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30`
  (confirmed by fetch before analysis; unmoved during analysis)
- Claim status: observation for all byte claims; inference only where
  marked (sentinel reading of the anchor, size-class reading of the
  main-path index computation, domain meaning of the table/totals)
- Scope included and excluded: included — the `0x63d94b0` FDE
  (555 bytes) and the adjacent `0x63d94a0` anchor-getter FDE
  (12 bytes), their census, and the fresh-consume-stamped-block
  specialization. Excluded — the callees `0x63e8bf0`,
  `0x63d8790`, `0x63d88d0` (cited only), the driver and
  single-shot caller FDEs (cited only), and all other packets'
  claimed ranges.

## Reproduce

Working directory: a worktree of upstream main `05bc2de30`.
Static analysis only; the binary was never executed.

- `sha256sum artifacts/node/115/hl-node` →
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- `objdump --dwarf=frames artifacts/node/115/hl-node` → FDE
  `pc=0x63d94a0..0x63d94ac` and `pc=0x63d94b0..0x63d96db`
- `objdump -d --start-address=0x63d94a0 --stop-address=0x63d96e0
  artifacts/node/115/hl-node` → full disassembly used here
- `python3 tools/node115_lu_blockreg.py` → static verifier, exit 0
- `python3 -m unittest tests.test_node115_lu_blockreg` → 10/10
- Coordinate system: `.text` file offset = VA − 0x1000
  (re-derived from program headers: PT_LOAD file offset
  `0x1418300` ↔ vaddr `0x1419300`); `.rodata` file offset = VA
  as-is. RELATIVE `.got` slots are zero-filled in the file, so
  the GOT census uses `.rela.dyn` addends (60,723 entries).

## Evidence

- FDE bounds confirmed by `.eh_frame` (see above); entry
  `endbr64` at `0x63d94b0`, single `ret` at `0x63d95fe`,
  `int3` padding `0x63d96db..0x63d96e0`; anchor getter entry
  `endbr64` at `0x63d94a0`, `ret` at `0x63d94ab`, `int3`
  padding `0x63d94ac..0x63d94b0`.
- 6 exhibits, 502 bytes, 112 strict instructions (see README
  table and `records.json`); raw bytes in `cm_*.hex`, raw
  disassembly lines in `cm_*.objdump.txt`.
- Callers (direct `E8`, each confirmed by objdump/rel32):
  `0x63b8c1d` (single-shot caller FDE) and `0x63b8f1a`
  (driver FDE). No `E9`, no rip-relative `LEA`, no `.rela.dyn`
  addend equal to `0x63d94b0`.
- Anchor getter callers (direct `E8`, each confirmed by
  objdump/rel32): 9 sites (`0x63b76f9`, `0x63b77da`,
  `0x63b79b1`, `0x63b7a13`, `0x63b7d47`, `0x63b80e0`,
  `0x63b8488`, `0x63b8a99`, `0x63b8b0c`). No `E9`, no `LEA`,
  no `.rela.dyn` addend equal to `0x63d94a0`.
- Callees (cited only, verified by rel32, not decoded here):
  `0x63e8bf0` (size mapping, arg `[block+0x60] << 12`),
  `0x63d8790` (flag-gated handoff, args first-arg and block),
  `0x63d88d0` (second flag-gated handoff, same args).
- `.rodata` constant at `0x450b10`: qwords `1` and `2`
  (bytes `0100000000000000 0002000000000000`), added by the
  `0x200` path to the table entry and to the totals pair.
- Overflow stub `0x63d96d0..0x63d96db` (`mov $0x2970,%r11d`;
  `jmp 0x63d9548`) verified by rel32, not exhibited.
- Helper-call sites `0x63d966a` (→ `0x63d8790`) and
  `0x63d967f` (→ `0x63d88d0`) verified by rel32, not exhibited.
- Branch targets: every conditional/unconditional jump inside
  the FDE targets an address inside `0x63d94b0..0x63d96db`.
- Disjointness: no overlap with any claimed exhibit range in
  the worktree's `research/work-items/*/records.json`
  (checked across all packets #183–#236 present in the tree).
- Analysis was complete for the two FDEs; the callees and
  callers were not decoded beyond their call sites.

## Implementation and comparison

Not yet implemented/measured: this packet is static evidence
only. No Rust reconstruction, no execution, no binary
equivalence claim. The verifier and unit tests check byte
regeneration, strict counts, rel32 targets, census, and
MANIFEST coverage, with a tamper control (a flipped exhibit
byte must mismatch the binary).

## Results and limitations

- Proven: the three-way dispatch on `[block+0x68]`; the
  per-path table/totals arithmetic; the entry flag
  `[block+0x24] := 1`; the flag-gated helper calls; the
  splice pointer writes; the anchor getter's body and its
  relationship (separate FDE, not an alternate entry); the
  fresh-consume-stamped-block specialization (zero path,
  `0x63d8790` called, no splice, no `0x63d88d0`).
- Not proven: the domain meaning of the table entries and
  totals; the identities of the three callees; which writers
  set `[block+0x68] = 0x200`, `[block+0x13]`, or
  `[block+0x14]`; the sentinel-vs-head reading of the anchor.
- No return value is established by these bytes.
- `.bss` contents are runtime-filled and not readable from
  the file; nothing here depends on them.
- Full `make test` was not attempted on the new base (584
  files; hours-long; VM-restart risk shown in #234). This
  packet's own file passes 10/10 standalone.
- Next question (#238): decode `0x63d8790` end to end — what
  it does with the (first-arg, block) pair it receives
  whenever `[block+0x11]` is nonzero.
