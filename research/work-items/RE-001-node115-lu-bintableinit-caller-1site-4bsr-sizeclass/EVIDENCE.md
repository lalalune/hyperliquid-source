# RE-001: lu bin_table_init 1-site 4bsr sizeclass caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-4bsr-sizeclass
- Target release and full SHA-256: node #115 only,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- Source commit / reference commit: upstream main `05bc2de30`.
- Claim status: observation (disassembly + byte census); no execution.
- Scope included and excluded: FDE `0x6363d50..0x6364270` only.
  Cited, not claimed: bin_table_init body `0x63d9880..0x63d9a64`
  (#262), lu-miss handler `0x63d9700..0x63d987b` (#215), helpers
  `0x635f340`, `0x63bd2e0`, `0x6360ed0`, tables/globals `0x67277c0`,
  `0x6727a00`, `0x65096c0`, `0x6511a00`, prev FDE
  `0x63637f0..0x6363d50` (#300), next FDE `0x6364270..0x6364280`.

## Reproduce

Worktree `~/workspace/hl-wt-calls301-115` (branch
`codex/re-004-calls301-115`, from origin/main `05bc2de30`).
Static analysis only; the binary is never executed.

- `objdump -d --start-address=0x6363d50 --stop-address=0x6364270 artifacts/node/115/hl-node`
- `python3 tools/node115_lu_bintableinit_caller_4bsr_sizeclass_1site.py`
  (exit 0, 71 checks, 0 failures)
- `python3 tests/test_node115_lu_bintableinit_caller_4bsr_sizeclass_1site.py`
  (exit 0, 12 checks, 0 failures)
- `make verify` (exit 0, 559 manifests, 7159 entries)
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md`, also on a pristine checkout)
- `sha256sum -c MANIFEST.sha256` (5/5 OK, from inside the packet dir)
- Full `make test` not run (584 files; declared deviation).

## Evidence

Coordinate system: VA; `.text` file offset = VA − 0x1000.
`.eh_frame` bounds from own parse (135,313 FDEs, sorted before
bisect): FDE `0x6363d50..0x6364270` (1312 bytes), prev FDE
`0x63637f0..0x6363d50` (gap 0 — adjacent, the #300 window), next
FDE `0x6364270..0x6364280` (padding 0 — adjacent, a 16-byte FDE).
`.hex` exhibit is raw binary bytes, not hex text.

Census from the objdump exhibit (strict mnemonic lines
`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`): 289 strict, 6 calls
(refcount helper `0x635f340`, bin_table_init `0x63d9880`,
large-size helper `0x63bd2e0`, context-release helper
`0x6360ed0`, lu-miss `0x63d9700`, `__stack_chk_fail`), 1 ret
(`0x6363ef7`), 1 bin_table_init site (`0x6364009`,
`lea 0x10(%rsp)` in-block in `rsi`, entered only by null-context
`je` from `0x6363d9c`; `r9d` saved to `0xc(%rsp)` and `rsi` to
`(%rsp)` before the call, `r11`/`r10d` restored after; rejoin
`jmp 0x6363da2`), 1 lu-miss site (`0x636425d`, `r8d` = 1,
`r9d` = 0, `r10d` on the stack), 4 bsr (`0x6364042`,
`0x6364080`, `0x636410d`, `0x6364150`), 0 lock sub, 0 lock add,
43 jump instructions, 0 outside-window targets.
Raw `0xe8` census (own parse): total 108, tiers 10x1, 8x1, 6x2,
5x1, 4x8, 2x12, 1x17; this FDE holds 1 raw site.
`.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
entries, counted separately (readelf `-W`).

## Implementation and comparison

Not yet implemented/measured — evidence packet only; no Rust
reconstruction in this packet.

## Results and limitations

- Static verifier exit 0, 71 checks, 0 failures;
  disjointness NONE over 58,016 priors, 0 skipped (deduplicated
  figure 57,278 after removing 738 exhibits carrying both a `range` key
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
- Limitations: helper bodies not decoded; no execution;
  `.bss` values never claimed; the `eax` 0/1 flag's caller-side
  meaning is not established beyond the arms that set it.
- Next question: packet #302 decodes `0x6387420..0x6387878`
  (1112 bytes, 1 bin_table_init site, 1 lu-miss site, 1 ret,
  0 bsr).
