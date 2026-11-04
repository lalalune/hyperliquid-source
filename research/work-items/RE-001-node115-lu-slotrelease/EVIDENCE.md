# RE-001-node115-lu-slotrelease: the node #115 lu slot-release helper

- Component ID: RE-001-node115-lu-slotrelease
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all byte claims; inference only where
  marked (circular-list reading of the rewiring block); unresolved
  items listed at the end
- Scope included and excluded: included — the single FDE
  `0x63b0780..0x63b097f` (512 bytes) and its four direct call sites
  plus the four callees' entry behaviour (empty-test fully,
  others by address only). Excluded — the internals of
  `0x63acb40` (#223), `0x63abd00`, `0x63e8bf0`, and all caller FDEs.

## Reproduce

Working directory: the worktree root. Commands (static only; the node
binary is never executed):

- `objdump -d --start-address=0x63b0780 --stop-address=0x63b0980
  artifacts/node/115/hl-node` — full FDE disassembly (139 lines
  including header/padding).
- `python3 tools/node115_lu_slotrelease.py` — static verifier, exit 0.
- `python3 -m unittest tests.test_node115_lu_slotrelease -v` — 9/9.
- `make verify`, `make catalogue-check`, `make test` — see README.
- Census: whole executable-segment byte scan for E8/E9 opcodes with
  rel32 resolving to `0x63b0780`, rip-relative LEA scan, and
  `.rela.dyn` addend scan (60,723 entries, file offset `0x6be8`).
- Coordinate system: `.text` file offset = VA − 0x1000;
  `.data.rel.ro` / `.got` = VA − 0x2000; `.rodata` = VA as-is.
  RELATIVE `.got` slots are zero-filled in the file, hence the
  `.rela.dyn` census.
- Tool versions: system `objdump`, `readelf`, Python 3.12, git-lfs
  3.4.1. No side effects; no execution.

## Evidence

Original addresses (VA) and validated boundaries:

- FDE `0x63b0780..0x63b097f` (512 bytes, next function at
  `0x63b0980`): `endbr64` at entry, single `ret` at `0x63b08cf`,
  `int3` padding at `0x63b097f`. Four internal calls, verified by
  rel32: `0x63b07a6 -> 0x63e8bf0` (size helper),
  `0x63b0847 -> 0x63acb40` (slot-remove, #223),
  `0x63b084f -> 0x63abcf0` (empty-test),
  `0x63b0912 -> 0x63abd00` (refresh callee).
- Entry exhibit `sr_entry` (`0x63b0780..0x63b07ae`, 46 bytes):
  `r12 = [node+0x10] & ~0xfff`, `call 0x63e8bf0`.
- Index exhibit `sr_index` (`0x63b07c1..0x63b07f7`, 54 bytes):
  `bsr` / `sbb` / clamp-14 idiom, `index = (edi - 14) * 4 +
  (((v - 1) >> shift) & 3)`. Huge path at `0x63b0950` hardcodes
  `0xc7` (199) with `S = P + 0x2590`, `T = P + 0x1900`.
- Accounting exhibit `sr_acct` (`0x63b0811..0x63b0854`, 67 bytes):
  `[S] -= 1`, `[S+8] -= r12`, key save, `call 0x63acb40`,
  `call 0x63abcf0`.
- Clear exhibit `sr_clear` (`0x63b0854..0x63b087c`, 40 bytes):
  `test %al,%al`, bitmap clear `rol` / `and`, cursor compare.
- Cache exhibit `sr_cache` (`0x63b08d0..0x63b092b`, 91 bytes):
  two-sided `setb` key-equality gates, `call 0x63abd00`,
  `movq` / `movhps` / `movups` key copy to `[C+0x30]`.
- Empty-test `0x63abcf0` (12 bytes, fully read):
  `cmpq $0,(%rdi); sete %al; ret` — returns 1 iff `[slot] == 0`.
- Callers (per-site disassembly confirmed, `call 63b0780` at each):
  `0x63b1bc4`, `0x63b1c91` (#213 chain FDE),
  `0x63b26f1` (#210 selector FDE from `0x63b2630`),
  `0x63b47ca` (FDE from `0x63b4630`, undecoded).
  All four callers ignore the return value.
- Record layout arithmetic: bitmap `P+0x00..0x20`,
  slots `P+0x20 + i*32`, accounting `P+0x1920 + i*16`,
  cursor `P+0x25a0`, page counter `P+0x25a8`;
  `0x20 + 200*32 = 0x1920`, `0x1920 + 200*16 = 0x25a0`.
- Analysis is complete for this FDE (all paths traced to the single
  `ret`); no timeout, no range limit.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed by
this packet. No Cargo graph, no build comparison. The packet is
evidence only: raw bytes, disassembly excerpts, and a static
verifier with a tamper control (corrupting one exhibit hex byte
makes the verifier fail).

## Results and limitations

Metrics with denominators:

- Exhibits: 5 excerpts, 298 bytes, 81 strict mnemonic lines,
  all byte-matched against the binary.
- Internal calls: 4/4 rel32 targets confirmed.
- Census: 4 direct E8, 0 E9, 0 LEA, 0 GOT out of 60,723
  `.rela.dyn` entries.
- MANIFEST: 15/15 entries verified.
- Unit tests: 9/9. Full suite: 77 files, single pre-existing
  catalogue Errno 18 failure (see README).
- What remains unknown: `0x63abd00`'s contract; the size helper's
  `.bss` base/table contents; `[T+8]`'s identity; the global
  purpose of the `+0x40` / `+0x48` list and of `P+0x25a0`;
  the four callers' purposes.
- No gate is requested by this packet.

Next question: decode `0x63abd00` end to end — what node it returns
for a slot, and whether it mutates the chain — this decides whether
the cache refresh in this packet is read-only.
