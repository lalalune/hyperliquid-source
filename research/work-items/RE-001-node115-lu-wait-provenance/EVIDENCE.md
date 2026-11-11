# RE-001-node115-lu-wait-provenance: mov-shape wait-helper arguments in the largest caller FDE

- Component ID: lu lock-wait callers, largest caller FDE
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390` (confirmed before analysis)
- Claim status: observation (bytes, rel32s, offsets proved); inference
  (record-type reading, group counting); unresolved (see below)
- Scope included and excluded: included — the whole FDE
  `0x63a5bf0..0x63a6470` read end to end, all 18 helper sites traced to
  their record sources, 6 exhibits (113 bytes, 26 strict). Excluded —
  the work function `0x63bf7f0`, the `.bss` table contents, the other
  384 caller FDEs, any domain identity of the objects/locks.

## Reproduce

Working directory: the worktree root (`~/workspace/hl-wt-calls253-115`).
No execution of the node binary at any point; all checks are byte reads
and `objdump -d` disassembly of the file.

- `python3 tools/node115_lu_wait_provenance.py` — static verifier, exit 0.
- `python3 -m unittest tests.test_node115_lu_wait_provenance` — 10/10.
- `make verify` — exit 0 (559 manifests, 7171 entries).
- `make catalogue-check` — exit 2, `Stale catalogue: README.md`
  (pre-existing on the new base, verified for #242 on a pristine
  checkout; base unchanged since).
- Full `make test` — not attempted (584 files on the new base; a full
  run takes hours and was already shown in #234 to be liable to
  VM-restart termination). The deviation from the worktree `AGENTS.md`
  (`make verify test catalogue-check`) follows the parent task's
  explicit no-full-`make test` rule and is disclosed in the README
  and the PR body, as in #245–#252.
- `objdump -d --start-address=0x63a5bf0 --stop-address=0x63a6470
  artifacts/node/115/hl-node` reproduces the FDE disassembly used here.

## Evidence

- Coordinate system: virtual addresses as shown by objdump; `.text`
  file offset = VA − 0x1000 (program-header derived: PT_LOAD
  off=0x1418300 ↔ vaddr=0x1419300, re-checked for this packet).
  `.data.rel.ro`/`.got` = VA − 0x2000, `.rodata` = VA as-is.
- FDE bounds confirmed by `.eh_frame` (PC-relative sdata4 encoding,
  CIE augmentation zR, encoding byte 0x1b): `pc=0x63a5bf0..0x63a6470`,
  2176 bytes. Entry `endbr64`; 1 byte `int3` padding before
  (`0x63a5bef..0x63a5bf0`); no padding after (next FDE at `0x63a6470`).
  Single `ret` at `0x63a615b`.
- All 18 `E8` sites to `0x63bf680` rel32-verified (see records.json
  `census.sites` and the verifier). No `E9` or rip-relative `LEA` to
  the helper occurs in this FDE.
- Raw disassembly of the FDE is the basis for the site table in the
  README; the 6 exhibits are byte-exact slices of it (see
  `*.hex` + `*.objdump.txt` beside this record).
- The object table (`0x65096c0`), group dword array (`0x6511780`),
  and group descriptors (`0x6711b40`) all lie in `.bss`
  (`0x64ffe40..0x6728924`); their contents are runtime-filled and
  were not read from the file. Only the walk structure (strides,
  bounds, null-skip) is claimed.
- Analysis was complete for this FDE (every instruction read); it was
  not a sampled or timed-out pass.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is included in
this packet. The packet is evidence only (README, records, exhibits,
static verifier, unit tests), following the light-style packet pattern
of #245–#252. No helper/data/relocation closure beyond the verifier's
checks is claimed.

## Results and limitations

- Metrics with explicit denominators: 18/18 helper sites traced to a
  record source; 18/18 sites show mutex = record `+0x40`, flag =
  record `+0x68`, triple = record `+0x28`/`+0x30`/`+0x38`; 6 exhibits,
  113 bytes, 26 strict; disjointness 0 overlaps over the merged tree
  + prior worktree records (count printed by the verifier).
- Passed: verifier exit 0, unit tests 10/10, `make verify` exit 0.
  Failed (pre-existing, not a regression): `make catalogue-check`
  exit 2, `Stale catalogue: README.md`.
- Unknown: `.bss` table contents; the work function `0x63bf7f0`;
  provenance in the other 384 caller FDEs; domain identity of the
  objects/locks; whether statistic fields (`+0x00..+0x24`) are read
  after a wait.
- No gate is requested by this packet beyond the checks above.
- Next question (#254): decode the work function `0x63bf7f0` end to
  end — what it does with `(tag, record)` after each successful
  trylock, deciding what this largest caller FDE accomplishes once
  it holds each lock.
