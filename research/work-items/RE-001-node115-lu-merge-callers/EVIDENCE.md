# RE-001-node115-lu-merge-callers: lu merge callers

- Component ID: RE-001-node115-lu-merge-callers
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30` (confirmed
  by fetch before analysis)
- Claim status: observation (bytes, counts, census) / inference (the
  "locked merge" reading of caller B, the counter/last-tag pattern) /
  unresolved (see README)
- Scope included and excluded: included — caller FDEs
  `0x63b9180..0x63b91d2` and `0x63b91e0..0x63b930c` end to end, their
  census, and the merge call sites (cited target, no merge bytes
  claimed). Excluded — the merge FDE itself (#249), the give-back FDE
  (#243, the originally assigned #250 topic, not re-claimed), the wait
  helper `0x63bf680`, the PLT stubs, the enclosing caller FDEs at
  `0x63a734e`/`0x63c0ad3`, and any runtime behaviour (static analysis
  only).

## Reproduce

Worktree `~/workspace/hl-wt-calls250-115`, branch
`codex/re-004-calls250-115`, base `05bc2de30`. Static disassembly with
system objdump on the target ELF; no execution, no side effects.

- `objdump -d --start-address=0x63b9180 --stop-address=0x63b91d2
  artifacts/node/115/hl-node` reproduces caller A.
- `objdump -d --start-address=0x63b91e0 --stop-address=0x63b930c
  artifacts/node/115/hl-node` reproduces caller B.
- `objdump --dwarf=frames artifacts/node/115/hl-node` confirms
  `pc=0x63b9180..0x63b91d2` and `pc=0x63b91e0..0x63b930c`.
- `python3 tools/node115_lu_merge_callers.py` — static verifier, exit 0.
- `python3 -m unittest tests.test_node115_lu_merge_callers` — 10/10.

## Evidence

Coordinate system: VA to file offset is VA − 0x1000, re-derived from
the executable PT_LOAD (offset `0x1418300` ↔ vaddr `0x1419300`); the
`.rodata` rule (VA as-is) is not needed here (no `.rodata` constant is
claimed). `.eh_frame` in this section uses PC-relative sdata4 FDE
encoding (CIE augmentation `zR`, encoding byte `0x1b`).

- Caller A entry bytes `f3 0f 1e fa` (`endbr64`) at `0x63b9180`;
  merge call site `0x63b9190` (`e8 8b f9 01 00`, rel32 to
  `0x63d8b20`); tail `paddq`/`movups` at `0x63b91b5..0x63b91cb`;
  `ret` (`c3`) at `0x63b91d1`; `int3` padding `0x63b91d2..0x63b91e0`
  (14 bytes).
- Caller B entry bytes `f3 0f 1e fa` at `0x63b91e0`; trylock calls
  at `0x63b920c` and `0x63b9247` (rel32 to `0x63f17b0`); wait calls
  at `0x63b92e3` and `0x63b92fb` (rel32 to `0x63bf680`); merge call
  at `0x63b9272` (rel32 to `0x63d8b20`); unlock call at `0x63b92b7`
  and tail jump at `0x63b92d4` (rel32 to `0x63f0b70`); `int3`
  padding `0x63b930c..0x63b9310` (4 bytes); next FDE at `0x63b9310`
  starts with `endbr64`.
- Census sites: `0x63a734e` (caller A, preceded by
  `lea 0x8700(%r14),%rsi`) and `0x63c0ad3` (caller B, preceded by
  `lea 0xf3b0(%rdi),%rsi` and `mov %r15,%rdi`), both objdump- and
  rel32-confirmed. An earlier raw-byte scan candidate for caller A
  was re-checked from a proper instruction boundary and confirmed
  real; no immediate-byte false positive survived.
- Caller B's wait paths jump back to the counting steps
  (`0x63b9219`, `0x63b9254`), not to the trylocks — after the wait
  helper returns, the lock is treated as held. The waited flags
  (`+0x118`, `+0xa8`) are set to 1 only on the wait paths and
  cleared to 0 on the success exit.
- Disjointness method: the verifier collects every `range`/`fde`
  value from the merged tree and prior worktree `records.json`
  files, deduplicates paths by string and ranges as a set, and
  excludes this packet's own slug; the resulting unique-range count
  is printed by the verifier run (it drifts only when genuinely new
  ranges appear, unlike raw path-count tallies).

## Implementation and comparison

Not yet implemented/measured. No Rust code is claimed from this
packet; the packet is observation plus the merge-caller reading, for
use by later reconstruction work.

## Results and limitations

- Machine-readable metrics: 2 FDEs, 382 exhibit bytes (the whole of
  both FDEs), 86 strict instructions, 2 census E8 sites (one per
  caller), 0 E9, 0 LEA, 0/60,723 `.rela.dyn` addend hits, 0 overlaps.
- What passed: static verifier exit 0, unit tests 10/10,
  `make verify` exit 0 (559 manifests, 7169 entries).
- What failed (pre-existing, not a packet regression):
  `make catalogue-check` exit 2, `Stale catalogue: README.md`, on the
  `05bc2de30` base.
- What remains unknown: the wait helper's behaviour, the tail source
  region's identity, the locks' domain roles, the tag value's
  meaning, and the enclosing callers' FDEs (see README).
- Next question (#251): decode the wait helper FDE `0x63bf680` end
  to end — what it waits on, what it returns, and how its two
  argument objects relate to the two locks.
