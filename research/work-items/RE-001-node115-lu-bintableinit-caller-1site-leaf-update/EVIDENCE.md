# RE-001: lu bin_table_init 1-site leaf update caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-leaf-update
- Target release and full SHA-256: node #115 only,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- Source commit / reference commit: upstream main `05bc2de30`.
- Claim status: observation (disassembly + byte census); no execution.
- Scope included and excluded: FDE `0x63637f0..0x6363d50` only.
  Cited, not claimed: bin_table_init body `0x63d9880..0x63d9a64`
  (#262), lu-miss handler `0x63d9700..0x63d987b` (#215), tail-jump
  target `0x6360ed0`, helpers `0x63f17b0`, `0x63f0b70`,
  `0x63bf680`, `0x635f3a0`, `0x63acb40`, `0x63c0340`, `0x6360610`,
  `0x635f340`, tables/globals `0x65096c0`, `0x6511780`, `0x6511820`,
  `0x6711b40`, `0x650969c`, `0x6511a00`.

## Reproduce

Worktree `~/workspace/hl-wt-calls300-115` (branch
`codex/re-004-calls300-115`, from origin/main `05bc2de30`).
Static analysis only; the binary is never executed.

- `objdump -d --start-address=0x63637f0 --stop-address=0x6363d50 artifacts/node/115/hl-node`
- `python3 tools/node115_lu_bintableinit_caller_leaf_update_1site.py`
  (exit 0, 63 checks, 0 failures)
- `python3 tests/test_node115_lu_bintableinit_caller_leaf_update_1site.py`
  (exit 0, 12 checks, 0 failures)
- `make verify` (exit 0, 559 manifests, 7159 entries)
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md`, also on a pristine checkout)
- `sha256sum -c MANIFEST.sha256` (5/5 OK, from inside the packet dir)
- Full `make test` not run (584 files; declared deviation).

## Evidence

Coordinate system: VA; `.text` file offset = VA − 0x1000.
`.eh_frame` bounds from own parse (135,313 FDEs, sorted before
bisect): FDE `0x63637f0..0x6363d50` (1376 bytes), prev FDE
`0x6363660..0x63637e2` (gap 14, all `0xcc`), next FDE
`0x6363d50..0x6364270` (padding 0 — adjacent, the #301 candidate).
`.hex` exhibit is raw binary bytes, not hex text.

Census from the objdump exhibit (strict mnemonic lines
`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`): 291 strict, 12 calls
(trylock `0x63f17b0`, unlock `0x63f0b70` x2, lock-wait helper
`0x63bf680`, helpers `0x635f3a0` / `0x63acb40` / `0x63c0340` /
`0x6360610` / `0x635f340`, bin_table_init `0x63d9880`, lu-miss
`0x63d9700`, `__stack_chk_fail`), 1 ret (`0x63639a6`),
1 bin_table_init site (`0x6363b30`, `lea 0x20(%rsp)` in-block via
`rbx`, entered only by null-context `je` from `0x6363828`),
1 lu-miss site (`0x6363d29`), 0 bsr, 0 lock sub, 0 lock add,
44 jump instructions, exactly 1 outside-window target (tail jump
`0x6363b8a` → `0x6360ed0`).
Raw `0xe8` census (own parse): total 108, tiers 10x1, 8x1, 6x2,
5x1, 4x8, 2x12, 1x17; this FDE holds 1 raw site.
`.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
entries, counted separately (readelf `-W`).

## Implementation and comparison

Not yet implemented/measured — evidence packet only; no Rust
reconstruction in this packet.

## Results and limitations

- Static verifier exit 0, 63 checks, 0 failures;
  disjointness NONE over 57,174 priors, 0 skipped (deduplicated
  56,446 after removing 728 exhibits carrying both a `range` key
  and a `start`/`end` pair). The raw-e8 census uses bytes.find
  over 0xe8 occurrences (same 108 total / same tiers as a
  byte-by-byte scan, ~50x faster); the test harness shares one
  fingerprint-validated priors cache (HL_PRIORS_CACHE) across its
  temp runs and asserts the priors count, so a stale/empty cache
  cannot pass vacuously. A default verifier run (no env var)
  always collects priors fresh. The cache fingerprint uses
  normalized paths so the same corpus maps to the same key from
  the real worktree and from test temp dirs (glob preserves the
  `..` segment, so #299's un-normalized fingerprint never hit
  across temp dirs).
- Own unit tests exit 0, 12 checks, 0 failures (tamper
  controls first; clean temp copy passes).
- `make verify` exit 0; `make catalogue-check` exit 2
  (pre-existing failure, not a packet regression).
- Limitations: helper/tail-jump-target bodies not decoded; no
  execution; `.bss` values never claimed; entry `rdx` has no
  callee-saved copy in the head, so its entry role is not
  established.
- Next question: packet #301 decodes `0x6363d50..0x6364270`
  (1312 bytes, 1 bin_table_init site, 1 lu-miss site, 1 ret,
  4 bsr).
