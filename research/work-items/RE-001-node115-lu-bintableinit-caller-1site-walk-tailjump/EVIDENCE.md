# RE-001: lu bin_table_init 1-site walk tail-jump caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-walk-tailjump
- Target release and full SHA-256: node #115 only,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- Source commit / reference commit: upstream main `05bc2de30`.
- Claim status: observation (disassembly + byte census); no execution.
- Scope included and excluded: FDE `0x6363260..0x6363552` only.
  Cited, not claimed: bin_table_init body `0x63d9880..0x63d9a64`
  (#262), lu-miss handler `0x63d9700..0x63d987b` (#215), call target
  FDE `0x63aefe0..0x63af45f` (1-raw candidate #12), helper
  `0x63eb870`, tail-jump target `0x63bd6c0`, tables/globals
  `0x6728848`, `0x6728868`, `0x6511a00`, `0x64ffdc8`.

## Reproduce

Worktree `~/workspace/hl-wt-calls299-115` (branch
`codex/re-004-calls299-115`, from origin/main `05bc2de30`).
Static analysis only; the binary is never executed.

- `objdump -d --start-address=0x6363260 --stop-address=0x6363552 artifacts/node/115/hl-node`
- `python3 tools/node115_lu_bintableinit_caller_walk_tailjump_1site.py`
  (exit 0, 60 checks, 0 failures)
- `python3 tests/test_node115_lu_bintableinit_caller_walk_tailjump_1site.py`
  (exit 0, 12 checks, 0 failures)
- `make verify` (exit 0, 559 manifests, 7159 entries)
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md`, also on a pristine checkout)
- `sha256sum -c MANIFEST.sha256` (5/5 OK, from inside the packet dir)
- Full `make test` not run (584 files; declared deviation).

## Evidence

Coordinate system: VA; `.text` file offset = VA − 0x1000.
`.eh_frame` bounds from own parse (135,313 FDEs, sorted before
bisect): FDE `0x6363260..0x6363552` (754 bytes), prev FDE
`0x6362f90..0x6363258` (gap 8, all `0xcc`), next FDE
`0x6363560..0x636365a` (padding 14, all `0xcc`).
`.hex` exhibit is raw binary bytes, not hex text.

Census from the objdump exhibit (strict mnemonic lines
`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`): 161 strict, 5 calls
(`0x63aefe0`, bin_table_init `0x63d9880`, helper `0x63eb870`,
lu-miss `0x63d9700`, `__stack_chk_fail`), 1 ret (`0x636336e`),
1 bin_table_init site (`0x63633f8`, `lea 0x10(%rsp)` in-block via
`rbx`, entered only by null-context `je` from `0x6363297`),
1 lu-miss site (`0x636353e`), 0 bsr, 0 lock sub, 0 lock add,
23 jump instructions, exactly 1 outside-window target (tail jump
`0x636339a` → `0x63bd6c0`).
Raw `0xe8` census (own parse): total 108, tiers 10x1, 8x1, 6x2,
5x1, 4x8, 2x12, 1x17; this FDE holds 1 raw site.
`.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
entries, counted separately (readelf `-W`).

## Implementation and comparison

Not yet implemented/measured — evidence packet only; no Rust
reconstruction in this packet.

## Results and limitations

- Static verifier exit 0, 60 checks, 0 failures;
  disjointness NONE over 56,332 priors, 0 skipped. The raw-e8
  census uses bytes.find over 0xe8 occurrences (same 108 total /
  same tiers as a byte-by-byte scan, ~50x faster); the test
  harness shares one fingerprint-validated priors cache
  (HL_PRIORS_CACHE) across its temp runs and asserts the priors
  count, so a stale/empty cache cannot pass vacuously. A default
  verifier run (no env var) always collects priors fresh.
- Own unit tests exit 0, 12 checks, 0 failures (tamper
  controls first; clean temp copy passes).
- `make verify` exit 0; `make catalogue-check` exit 2
  (pre-existing failure, not a packet regression).
- Limitations: helper/tail-jump-target bodies not decoded; no
  execution; `.bss` values never claimed.
- Next question: packet #300 decodes `0x63637f0..0x6363d50`
  (1376 bytes, 1 bin_table_init site, 1 lu-miss site, 1 ret,
  0 bsr).
