# RE-001-node115-lu-bintableinit-caller-1site-leaf-update

Third 1-raw bin_table_init caller packet (after #298, #299). The window
is a single-site leaf-update routine: one bin_table_init site
(`lea 0x20(%rsp)` in-block via `rbx`, entered only by a null-context
`je`), a two-phase context-table walk that DOES read node-resolution
tables (`0x65096c0` + `0x6511780` — unlike #298/#299), an 8-slot
move-to-front scan (all normal-operand compares), a trylock-guarded
in-place leaf update with a lock-wait helper and grow/rebalance arms,
and two exits — one `ret` and one tail jump to `0x6360ed0`.

## Window

- FDE `0x63637f0..0x6363d50`, 1376 bytes, 291 strict mnemonic lines.
- Previous FDE `0x6363660..0x63637e2` (gap 14 bytes, all `0xcc`).
- Next FDE `0x6363d50..0x6364270` (padding 0 bytes — adjacent, the
  packet #301 candidate, not decoded here).
- Frame: `endbr64`, pushes r15/r14/r13/r12/rbp/rbx, `sub $0x1b8,%rsp`,
  canary at `0x1a8(%rsp)`.
- Entry: `rdi` = context (kept in `r14`), `rsi` = key (kept in
  `rbp`); entry `rdx` has no callee-saved copy in the head (all
  later `rdx` uses are re-set first).
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification summary

- Phase-1 walk on the context+`0x1b0` table; on a top-level match the
  second-level value is shifted/masked and the node is resolved
  through tables `0x65096c0` / `0x6511780` — this FDE reads
  node-resolution tables, unlike the #298/#299 walkers (and no
  `0x6727a00` table read happens here either).
- Bin_table_init site: `0x6363b30` (block `0x6363b28`, via `rbx`,
  `lea 0x20(%rsp)`).
- Lu-miss site: `0x6363d29` (scan exhaustion).
- Scan: 8 slots, table+`0x100`, move-to-front on a hit; all 8 slot
  compares are normal-operand (`cmp 0x1X0(%rbx),%rcx`) — no
  reversed-operand compare in this scan, unlike #298/#299 (slot 3).
- Leaf update: `pthread_mutex_trylock` (`0x63f17b0`) at `0x63638cc`,
  lock-wait helper `0x63bf680` (#251) on failure, refcount/bit-set
  update on success, grow arm (helper `0x63acb40`) and rebalance arm
  (helper `0x635f3a0`), context-release arm (helper `0x635f340`).
- Calls: 12 (trylock, unlock x2, lock-wait helper, 5 other helpers,
  bin_table_init, lu-miss, `__stack_chk_fail`).
- Exit: single `ret` at `0x63639a6`, plus one tail jump at `0x6363b8a`
  to `0x6360ed0` (exit-ness verified per FDE).

Full site/scan tables, census, and method notes are in records.json
and EVIDENCE.md.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings, 0 skipped). The window
`0x63637f0..0x6363d50` overlaps no prior range (verifier: see the
final verifier run figure below), including packet #299's window
`0x6363260..0x6363552`, packet #298's window
`0x6362f90..0x6363258`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`.

## Prior pointer verified (no correction)

#299's survey pointer for this window (1376 bytes, 1 bin_table_init
site, 1 lu-miss site, 1 ret, 0 bsr) is verified correct by program
arithmetic and by the objdump census above.

## 1-raw tier status

Packet #298 surveyed all 17 1-raw candidates (each exactly 1
objdump-verified bin_table_init site). 16 survive; 1 is excluded as
a whole FDE (`0x63adf40..0x63ae252`, overlapping #214's claimed
sub-ranges). This packet builds on the third survivor. The next
frontier is packet #301 on `0x6363d50..0x6364270`.

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_leaf_update_1site.py`:
  exit 0 (final check count from the sealing run: see below).
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_leaf_update_1site.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (final check count from the
  sealing run: see below). The test harness uses lean temp copies
  (verifier + packet dir + symlinked binary only); a full worktree
  copy changes nothing the verifier reads.
- `make verify`: exit 0 (559 evidence-packet manifests, 7159
  entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Sealing-run figures

- Verifier: exit 0, 63 checks, 0 failures.
- Unit tests: exit 0, 12 checks, 0 failures.
- Disjointness: verifier scanned 57,174 priors, 0 skipped,
  NONE (deduplicated figure 56,446 after removing 728 exhibits
  carrying both a `range` key and a `start`/`end` pair).

## Review correction: reproducible prior comparison

The submitted comparison scanned private `hl-wt-calls*` directories. Those
inputs were not committed, so its large prior-count result was not independently
reproducible. The original observations remain in this packet and Git history.

The reviewed checker instead authenticates the 1,210 public `records.json`
inputs listed in `RE-review-open-20261106/prior-source-manifest.json`, using
`tools/node115_prior_corpus.py`. Every input path and SHA-256 is checked; a
missing or changed input fails before the comparison. The frozen source commit
and target digest are recorded in that manifest. All 72 incoming static
packets are included, so their mutual comparisons are also covered.

The original exhibit/range extraction and target-byte controls are retained.
The arbitrary count of duplicated private-worktree ranges is replaced by
complete authentication of the public input set. Range counts are reported
without coverage credit. This is a comparison against a frozen, documented
input set, not proof of global function ownership or reconstruction completion.
The common helper and its corruption tests are pinned by the review packet's
manifest. Temporary tests use their source checkout as the explicit reference
root and keep mutations in temporary copies.

A historical next-work suggestion may already have a complete exhibit in
the pinned input set. That case is validated as already documented and earns
no new coverage; actual current-window overlap remains a failure.
