# RE-001: lu bin_table_init 1-site 2-scan field-set caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-2scan-fieldset
- Target release and full SHA-256: node #115 only,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- Source commit / reference commit: upstream main `05bc2de30`.
- Claim status: observation (disassembly + byte census); no execution.
- Scope included and excluded: FDE `0x63adb50..0x63adf34` only.
  Cited, not claimed: bin_table_init body `0x63d9880..0x63d9a64`
  (#262), lu-miss handler `0x63d9700..0x63d987b` (#215), prev
  FDE `0x63adb40..0x63adb4c`, next FDE `0x63adf40..0x63ae252`
  (excluded whole FDE for #214 overlap). No node-resolution
  tables (`0x65096c0`, `0x6511780`) or size tables (`0x6727a00`,
  `0x67277c0`) are read in this FDE.

## Reproduce

Worktree `~/workspace/hl-wt-calls303-115` (branch
`codex/re-004-calls303-115`, from origin/main `05bc2de30`).
Static analysis only; the binary is never executed.

- `objdump -d --start-address=0x63adb50 --stop-address=0x63adf34 artifacts/node/115/hl-node`
- `python3 tools/node115_lu_bintableinit_caller_2scan_fieldset_1site.py`
  (exit 0, 92 checks, 0 failures)
- `python3 tests/test_node115_lu_bintableinit_caller_2scan_fieldset_1site.py`
  (exit 0, 12 checks, 0 failures)
- `make verify` (exit 0, 559 manifests, 7159 entries)
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md`, also on a pristine checkout)
- `sha256sum -c MANIFEST.sha256` (5/5 OK, from inside the packet dir)
- Full `make test` not run (584 files; declared deviation).

## Evidence

Coordinate system: VA; `.text` file offset = VA − 0x1000.
`.eh_frame` bounds from own parse (135,313 FDEs, sorted before
bisect): FDE `0x63adb50..0x63adf34` (996 bytes), prev FDE
`0x63adb40..0x63adb4c` (gap 4 bytes, all `0xcc`), next FDE
`0x63adf40..0x63ae252` (padding 12 bytes, all `0xcc`).
`.hex` exhibit is raw binary bytes, not hex text.

Census from the objdump exhibit (strict mnemonic lines
`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`): 209 strict, 4 calls
(bin_table_init `0x63d9880`, lu-miss `0x63d9700` x2,
`__stack_chk_fail`), 1 ret (`0x63adc8b`), 1 bin_table_init site
(`0x63adce6`, plain `%rsp` in-block via `r15`, entered only by
null-context `je` from `0x63adba1`; no save/restore — `r15`
itself becomes the stack-temp table; rejoin `jmp 0x63adba7`),
2 lu-miss sites (`0x63ade8d`, scan A exhaustion, `r8d` = 1,
`r9d` = 0, `rdi` = context in `rbp`, `rdx` = scan table in
`r15`, `rcx` = second-level pointer in `r14`, `rsi` = key in
`r13`, return to `r14`, rejoin `jmp 0x63adbe8`; `0x63adf22`,
scan B exhaustion, `rcx` = derived key in `rdx`, return to
`rdx`, rejoin `jmp 0x63adc4e`), 0 bsr, 0 lock sub, 0 lock add,
32 jump instructions, 0 outside-window targets.
Raw `0xe8` census (own parse): total 108, tiers 10x1, 8x1, 6x2,
5x1, 4x8, 2x12, 1x17; this FDE holds 1 raw site.
`.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
entries, counted separately (readelf `-W`).

## Implementation and comparison

Not yet implemented/measured — evidence packet only; no Rust
reconstruction in this packet.

## Results and limitations

- Static verifier exit 0, 92 checks, 0 failures;
  disjointness NONE over 59,700 priors, 0 skipped
  (deduplicated figure 58,942 after removing 758
  within-file duplicate ranges).
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
  `.bss` values never claimed; the 3-bit field's caller-side
  meaning (beyond the two write sites) is not established; no
  return register is set on the `ret` path, so no return value
  is claimed. The next FDE `0x63adf40..0x63ae252` is excluded
  as a whole FDE for #214 overlap and is not decoded here.
- Next question: packet #304 decodes `0x63ae2b0..0x63ae6d1`
  (1057 bytes, 1 bin_table_init site, 2 lu-miss sites, 1 ret,
  0 bsr — verified by program against all prior exhibits).
