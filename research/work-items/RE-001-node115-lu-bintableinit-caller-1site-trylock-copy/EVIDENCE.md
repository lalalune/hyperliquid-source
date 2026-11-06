# RE-001: lu bin_table_init 1-site trylock copy caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-trylock-copy
- Target release and full SHA-256: node #115 only,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- Source commit / reference commit: upstream main `05bc2de30`.
- Claim status: observation (disassembly + byte census); no execution.
- Scope included and excluded: FDE `0x6387420..0x6387878` only.
  Cited, not claimed: bin_table_init body `0x63d9880..0x63d9a64`
  (#262), lu-miss handler `0x63d9700..0x63d987b` (#215), lock-wait
  helper `0x63bf680` (#251), `pthread_mutex_trylock`/`unlock`,
  mutex `0x67121a0` and globals `0x6712188`, `0x6712190`,
  `0x6712198`, `0x67121c8`, tables `0x65096c0`, `0x6511a00`, prev
  FDE `0x6386eb0..0x6387420`, next FDE `0x6387880..0x6387fec`.

## Reproduce

Worktree `~/workspace/hl-wt-calls302-115` (branch
`codex/re-004-calls302-115`, from origin/main `05bc2de30`).
Static analysis only; the binary is never executed.

- `objdump -d --start-address=0x6387420 --stop-address=0x6387878 artifacts/node/115/hl-node`
- `python3 tools/node115_lu_bintableinit_caller_trylock_copy_1site.py`
  (exit 0, 84 checks, 0 failures)
- `python3 tests/test_node115_lu_bintableinit_caller_trylock_copy_1site.py`
  (exit 0, 12 checks, 0 failures)
- `make verify` (exit 0, 559 manifests, 7159 entries)
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md`, also on a pristine checkout)
- `sha256sum -c MANIFEST.sha256` (5/5 OK, from inside the packet dir)
- Full `make test` not run (584 files; declared deviation).

## Evidence

Coordinate system: VA; `.text` file offset = VA − 0x1000.
`.eh_frame` bounds from own parse (135,313 FDEs, sorted before
bisect): FDE `0x6387420..0x6387878` (1112 bytes), prev FDE
`0x6386eb0..0x6387420` (gap 0 — adjacent), next FDE
`0x6387880..0x6387fec` (padding 8 bytes, all `0xcc`).
`.hex` exhibit is raw binary bytes, not hex text.

Census from the objdump exhibit (strict mnemonic lines
`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`): 254 strict, 6 calls
(`pthread_mutex_trylock` `0x63f17b0`,
`pthread_mutex_unlock` `0x63f0b70`, lock-wait helper
`0x63bf680`, bin_table_init `0x63d9880`, lu-miss `0x63d9700`,
`__stack_chk_fail`), 1 ret (`0x6387595`), 1 bin_table_init site
(`0x6387629`, `lea 0x20(%rsp)` in-block in `rsi`, entered only by
null-context `je` from `0x63874c6`; `rcx` saved to `0x8(%rsp)`
and `rsi` to `(%rsp)` before the call, `r10`/`rcx` restored
after; rejoin `jmp 0x63874cc`), 1 lu-miss site (`0x6387869`,
`r8d` = 1, `r9d` = 0, `rdi` = context in `r14`, `rdx` = scan
table in `r10`, `rcx` = key in `r15`, `rsi` = `lea 0x6511a00`;
rejoin `jmp 0x63874f2`), 0 bsr, 0 lock sub, 0 lock add, 39 jump
instructions, 0 outside-window targets.
Raw `0xe8` census (own parse): total 108, tiers 10x1, 8x1, 6x2,
5x1, 4x8, 2x12, 1x17; this FDE holds 1 raw site.
`.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
entries, counted separately (readelf `-W`).

## Implementation and comparison

Not yet implemented/measured — evidence packet only; no Rust
reconstruction in this packet.

## Results and limitations

- Static verifier exit 0, 84 checks, 0 failures;
  disjointness NONE over 58,858 priors, 0 skipped
  (deduplicated figure 58,110 after removing 748
  exhibits carrying both a `range` key and a `start`/`end` pair).
  The raw-e8 census uses bytes.find over 0xe8 occurrences (same
  108 total / same tiers as a byte-by-byte scan, ~50x faster);
  the test harness shares one fingerprint-validated priors cache
  (HL_PRIORS_CACHE) across its temp runs and asserts the priors
  count, so a stale/empty cache cannot pass vacuously. A default
  verifier run (no env var) always collects priors fresh. The
  cache fingerprint uses normalized paths so the same corpus maps
  to the same key from the real worktree and from test temp dirs
  (glob preserves the `..` segment, so #299's un-normalized
  fingerprint never hit across temp dirs).
- Own unit tests exit 0, 12 checks, 0 failures (tamper
  controls first; clean temp copy passes).
- `make verify` exit 0; `make catalogue-check` exit 2
  (pre-existing failure, not a packet regression).
- Limitations: helper bodies not decoded; no execution;
  `.bss` values never claimed; the mutex owner-tracking globals'
  caller-side meaning is described from the reads/writes in this
  FDE only; the `0x16` return code's caller-side meaning is not
  established beyond the arms that set it.
- Next question: packet #303 decodes `0x63adb50..0x63adf34`
  (996 bytes, 1 bin_table_init site, 2 lu-miss sites, 1 ret,
  0 bsr — verified by program against all prior exhibits).
