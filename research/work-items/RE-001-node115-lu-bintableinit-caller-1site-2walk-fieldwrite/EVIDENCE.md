# RE-001: lu bin_table_init 1-site 2-walk field-write caller

- Component ID: RE-001-node115-lu-bintableinit-caller-1site-2walk-fieldwrite
- Target release and full SHA-256: node #115 only,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- Source commit / reference commit: upstream main `05bc2de30`.
- Claim status: observation (disassembly + byte census); no execution.
- Scope included and excluded: FDE `0x63ae2b0..0x63ae6d1` only.
  Cited, not claimed: bin_table_init body `0x63d9880..0x63d9a64`
  (#262), lu-miss handler `0x63d9700..0x63d987b` (#215), prev
  FDE `0x63ae2a0..0x63ae2a9`, next FDE `0x63ae6e0..0x63ae974`.
  No node-resolution tables (`0x65096c0`, `0x6511780`) or size
  tables (`0x6727a00`, `0x67277c0`) are read in this FDE.

## Reproduce

Worktree `~/workspace/hl-wt-calls304-115` (branch
`codex/re-004-calls304-115`, from origin/main `05bc2de30`).
Static analysis only; the binary is never executed.

- `objdump -d --start-address=0x63ae2b0 --stop-address=0x63ae6d1 artifacts/node/115/hl-node`
- `python3 tools/node115_lu_bintableinit_caller_2walk_fieldwrite_1site.py`
  (exit 0, 98 checks, 0 failures)
- `python3 tests/test_node115_lu_bintableinit_caller_2walk_fieldwrite_1site.py`
  (exit 0, 12 checks, 0 failures)
- `make verify` (exit 0, 559 manifests, 7159 entries)
- `make catalogue-check` (exit 2, pre-existing `Stale catalogue:
  README.md`, also on a pristine checkout)
- `sha256sum -c MANIFEST.sha256` (5/5 OK, from inside the packet dir)
- Full `make test` not run (584 files; declared deviation).

## Evidence

Coordinate system: VA; `.text` file offset = VA − 0x1000.
`.eh_frame` bounds from own parse (135,313 FDEs, sorted before
bisect): FDE `0x63ae2b0..0x63ae6d1` (1057 bytes), prev FDE
`0x63ae2a0..0x63ae2a9` (gap 7 bytes, all `0xcc`), next FDE
`0x63ae6e0..0x63ae974` (padding 15 bytes, all `0xcc`).
`.hex` exhibit is raw binary bytes, not hex text.

Census from the objdump exhibit (strict mnemonic lines
`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`): 222 strict, 4 calls
(bin_table_init `0x63d9880`, lu-miss `0x63d9700` x2,
`__stack_chk_fail`), 1 ret (`0x63ae3fc`), 1 bin_table_init site
(`0x63ae45d`, block `0x63ae450`, `lea 0x10(%rsp)` in `r15`,
`mov %r15,%rdi`; `rsi` saved to `0x8(%rsp)` before the call
and restored after it; rejoin `jmp 0x63ae2f3`; entered only by
a null-context `je` from `0x63ae2ed`), 2 lu-miss sites
(`0x63ae627`, scan A exhaustion, `r8d` = 0, `r9d` = 1, `rdi` =
context in `r14`, `rdx` = scan table in `r15`, `rcx` =
second-level pointer in `rbp`, `rsi` = entry `rsi`, return to
`rbp`, rejoin `jmp 0x63ae332`; `0x63ae6bf`, scan B exhaustion,
`r8d` = 0, `r9d` = 1, `rcx` = second-level value, return to
`rcx`, rejoin `jmp 0x63ae38e`), 0 bsr, 0 lock sub, 0 lock add,
32 jump instructions, 0 outside-window targets.
Raw `0xe8` census (own parse): total 108, tiers 10x1, 8x1, 6x2,
5x1, 4x8, 2x12, 1x17; this FDE holds 1 raw site.
`.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
entries, counted separately (readelf `-W`).

## Implementation and comparison

Not yet implemented/measured — evidence packet only; no Rust
reconstruction in this packet.

## Results and limitations

- Static verifier exit 0, 98 checks, 0 failures;
  disjointness NONE over 60,542 priors, 0 skipped
  (deduplicated figure 59,774 after removing 768
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
  `.bss` values never claimed; the entry `rsi` value's
  caller-side meaning is not established (it is preserved
  across the bti call and lu-miss A and passed to the lu-miss
  handler, but what the caller means by it is unknown). The
  composed field value's semantics (beyond the two write
  sites) are not established.
- Next question: packet #305 decodes `0x63ae6e0..0x63ae974`
  (660 bytes, 1 bin_table_init site, 1 lu-miss site, 1 ret,
  0 bsr — verified by program against all prior exhibits).
