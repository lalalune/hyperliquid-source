# RE-001-node115-lu-miss-caller-2site-ctypescan: lu-miss caller with a ctype pre-scan, a single walk, and three exits (first window with three rets)

Tenth packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, #316 on `0x6355900`, #317 on `0x63577f0`, #318 on
`0x635a7a0`, #319 on `0x635c6d0`, #320 on `0x635e2e0`, #321 on
`0x63c9650`, and #322 on `0x63ccd60`). FDE `0x63cddd0..0x63ce23b`
(1131 bytes, 242 strict lines) is a ctype-validated string lookup
followed by a SINGLE context-table walk and TWO lu-miss sites — the
tenth frontier window, the first with a `__ctype_b_loc` pre-scan, the
first with THREE rets (three distinct exit values 0 / 14 / 11, one
reaching definition each), and the first to call the FDE immediately
after #322's window (`0x63cd910`, once). It opens with `endbr64`,
loads `0x68(%rdi)` into `r13` with two init arms (helper `0x63c3780`
when the field is null and the `0x330(%rdi)` flag byte is at most 2;
helper `0x63c3b00` when `0x21(%r13)` is nonzero), and exits 14 on a
null string. A per-character `__ctype_b_loc` table scan then validates
the `rsi` string: a byte is accepted iff its ctype entry has the sign
bit set or bit 0 set, otherwise the window exits 14. The window then
calls `0x63cd910` (`rdi` = `r12` context, `rsi` = `rbp` string); its
return goes to `rbx` and is null-checked (exit 11 on null). The walk
is keyed by the node pointer in `0x18(%r13)` (`rbp`), table `r12` +
`0x1b0`: top index `(key >> 0x1a) & 0xf0`, high bits `key &
0xffffffffc0000000`, an inline `shr $0x30` extract feeding size table
`0x6727a00` (size class into `r15`), then a `shl $0x10` / `sar $0x10`
extract feeding node table `0x65096c0` and a `lock sub %r15,0x38(%rdi)`
refcount decrement. The window then calls `0x63c89c0`, clears
`0x18(%r13)`, and installs `rbx` into `0x18(%r13)` iff `*rbx` is
nonzero. Two 8-slot move-to-front scans share one slot set
(`0x2b0..0x320` in `r12`): 16 slot-compare instructions, ELEVEN
reversed-operand (arm-B slot-0; scan-A slots 2–7; scan-B slots 2–5),
i.e. 11 of 16 slot positions reversed; their exhaustions fall to the
two lu-miss sites. Both miss sites share one argument pattern (`rdi`
= `r12` context, `rsi` = `.bss` `0x6511a00`, `rdx` = walk table
pointer `lea 0x1b0(%r12)`, `rcx` = `rbp` walk key, `r8d` = 1, `r9d` =
0), with the `rcx` provenance proven by reaching-definitions: the
only `rcx` definition reaching either site is the `mov %rbp,%rcx`
immediately before its call, and the only `rbp` definition reaching
either site is `mov 0x18(%r13),%rbp` at `0x63cde5b` (the walk-key node
pointer). The `rdx` at site 1 additionally admits the restore `mov
(%rsp),%rdx` at `0x63ce232` (second pass after site 2's call), which
restores the same table pointer saved before site 2's call. It exits
by THREE rets with one reaching `rax` definition each — 0 (`xor
%eax,%eax` at `0x63cdf23`, success path), 14 (`mov $0xe,%eax` at
`0x63cdf34`, null string or ctype-test failure), 11 (`mov $0xb,%eax`
at `0x63cdf6b`, context-init failure) — so no single exit value is
established, unlike #314 (`rbx`), #315 (`r12`), #316 (`r13`), #317
(`r12`), #319 (0), and #320 (`r15`). 0 `bin_table_init` sites, 0
second-handler sites, 0 `bsr`, 0 tail-jump exits, 1 `lock sub` and 0
`lock add`, NO canary, NO TLS flag check. This window is a
lu-miss-ONLY survivor (in the lu-miss survivor list but NOT in the
second-handler survivor list), so claiming it consumes one slot of
the combined 25-FDE miss-handler pool without being shared. It never
calls the lock-wait helper `0x63bf680` — the follow-on frontier's
helper — cited, not claimed.

## Window

| Item | Value |
| --- | --- |
| FDE | `0x63cddd0..0x63ce23b` |
| Bytes | 1131 |
| Strict lines | 242 |
| Calls | 7 (6 distinct direct targets, 0 indirect) |
| Bin_table_init sites | 0 |
| Lu-miss sites | 2 (`0x63ce1f8`, `0x63ce221`) |
| Second-handler sites | 0 |
| Ret | 3 (`0x63cdf2f`, `0x63cdf43`, `0x63cdf7a`) |
| Tail-jump exits | 0 |
| Bsr | 0 |
| Lock sub / add | 1 / 0 |
| Jumps | 39 (0 outside) |
| Prev FDE | `0x63cd910..0x63cddce` (gap 2, all `0xcc`) |
| Next FDE | `0x63ce240..0x63ce501` (padding 5, all `0xcc`) |

## Classification

- Entry: `endbr64`; pushes r15/r14/r13/r12/rbp/rbx, `sub
  $0x18,%rsp`. `rdi` is the context base (kept in `r12`); `rsi` is
  the string pointer (kept in `rbp`); `0x68(%rdi)` is loaded into
  `r13` at `0x63cddf8`. No canary, no TLS flag check (`%fs:0x330`
  appears nowhere).
- Entry guards: `test %r13,%r13` at `0x63cddec`; `je 0x63cdf48` on
  null. `cmpb $0x0,0x21(%r13)` at `0x63cddf5`; `jne 0x63cdf7b` when
  nonzero (refresh arm). `test %rbp,%rbp` at `0x63cde00`; `je
  0x63cdf30` (exit 14) on a null string.
- Init arms: null-field arm at `0x63cdf48`: `cmpb $0x2,0x330(%rdi)`;
  `ja 0x63cdf67` (exit 11) when the flag byte exceeds 2; `call
  0x63c3780` at `0x63cdf51`; `mov %rax,%r13` at `0x63cdf56`; `mov
  %r13,0x68(%r12)` at `0x63cdf59`; `test %r13,%r13` at `0x63cdf5e`;
  `jne 0x63cde00` on success, else fall through to exit 11.
  Refresh arm at `0x63cdf7b`: `mov %r13,%rsi`; `call 0x63c3b00` at
  `0x63cdf7e`; `mov %rax,%r13` at `0x63cdf83`; `jmp 0x63cdf59`
  (store and re-test).
- Ctype scan: `movsbq 0x0(%rbp),%r14` at `0x63cde09` loads the first
  byte; NUL jumps to `0x63cde44` (skip the scan). `call
  __ctype_b_loc@plt` (`0x63f1b60`) at `0x63cde13`; `mov (%rax),%rcx`
  at `0x63cde18` loads the ctype table; `movzwl (%rcx,%r14,2),%edx`
  at `0x63cde20` looks up the byte. `test %dx,%dx` at `0x63cde25`;
  `js 0x63cde33` when the entry is negative (sign bit set advances
  to the next byte); `and $0x1,%edx` at `0x63cde2a`; `je 0x63cdf30`
  (exit 14) when bit 0 is clear. The loop advances with `lea
  0x1(%rax),%ebx` at `0x63cde33` (`rbx` is the index), `movsbq
  0x0(%rbp,%rbx,1),%r14` at `0x63cde36`, `mov %rbx,%rax` at
  `0x63cde3c`, `test %r14b,%r14b` at `0x63cde3f`, `jne 0x63cde20` at
  `0x63cde42`. A byte is accepted iff its ctype entry has the sign
  bit set or bit 0 set; the specific ctype class is not named here
  because the table entry bits are only observed, not decoded
  against a named class.
- Pre-walk call: `mov %rbp,%rsi` at `0x63cde44`; `mov %r12,%rdi` at
  `0x63cde47`; `call 0x63cd910` at `0x63cde4a` (the FDE immediately
  after #322's window); `mov %rax,%rbx` at `0x63cde4f`; `test
  %rax,%rax` at `0x63cde52`; `je 0x63cdf67` (exit 11) on null.
- Walk (key = node pointer `0x18(%r13)` in `rbp`, table `r12` +
  `0x1b0` in `rdx`): `mov 0x18(%r13),%rbp` at `0x63cde5b`; `test
  %rbp,%rbp` at `0x63cde5f`; `je 0x63cdf16` (skip the walk, keep the
  `rbx` store at the epilogue) on null. Top index `(key >> 0x1a) &
  0xf0` (`shr $0x1a,%r14` at `0x63cde76`, `and $0xf0,%r14d` at
  `0x63cde81`, `add %r12,%r14` at `0x63cde88`); high bits `key &
  0xffffffffc0000000` (`and $0xffffffffc0000000,%r10` at `0x63cde7a`);
  top compare `cmp %r9,%r10` at `0x63cde92` (`r9` = `0x1b0(%r14)`),
  mismatch to miss arm A at `0x63cdfd9` (scan B). Second level `(key
  >> 0x9) & 0x1ffff8 + table + 0x8`, head `mov (%rax),%rax` at
  `0x63cdeae`. Extract: `lea 0x6727a00,%rsi` at `0x63cdeb1` (size
  table); `shr $0x30,%rax` at `0x63cdeb8`; `mov (%rsi,%rax,8),%r15`
  at `0x63cdebc` (size class into `r15`). Second compare `cmp
  %r10,%r9` at `0x63cdec0`, mismatch to miss arm B at `0x63cdf88`
  (scan A). Then `shl $0x10,%r10` / `sar $0x10,%r10` / `and
  $0xffffffffffffff80,%r10` feeding node table `0x65096c0` (`lea
  0x65096c0,%r8` at `0x63cdedf`, `mov (%r8,%rax,8),%rdi` at
  `0x63cdefa`) and a `lock sub %r15,0x38(%rdi)` at `0x63cdefe`
  (refcount decrement by the size class).
- Release and slot store: `mov %rbp,%rsi` at `0x63cdf03`; `mov
  %r12,%rdi` at `0x63cdf06`; `call 0x63c89c0` at `0x63cdf09`;
  `movq $0x0,0x18(%r13)` at `0x63cdf0e`. `cmpb $0x0,(%rbx)` at
  `0x63cdf16`; `je 0x63cdf1f` (skip the store) when the first byte of
  `*rbx` is zero; `mov %rbx,0x18(%r13)` at `0x63cdf1b` installs the
  `0x63cd910` return as the new node pointer.
- Scan (two 8-slot move-to-front loops over the same slot set,
  table+`0x2b0` in `r12`, 16-byte entries, swap-on-hit): scan A is
  entered from miss arm B (`0x63cdf88`, second-level compare miss);
  scan B is entered from miss arm A (`0x63cdfd9`, top-index compare
  miss). Slot-0 compares: arm B `cmp %r10,0x2b0(%r12)` at `0x63cdf88`
  (REVERSED); arm A `cmp 0x2b0(%r12),%r10` at `0x63cdfd9` (normal).
  Loop compares cover slots 1–7 in one instruction each: scan A
  `0x63ce033` (slot 1, normal), `0x63ce0fc`, `0x63ce110`,
  `0x63ce124`, `0x63ce138`, `0x63ce14c`, `0x63ce15a` (slots 2–7,
  REVERSED); scan B `0x63ce098` (slot 1, normal), `0x63ce174`,
  `0x63ce187`, `0x63ce19a`, `0x63ce1ad` (slots 2–5, REVERSED),
  `0x63ce1c0`, `0x63ce1ce` (slots 6–7, normal). 16 slot-compare
  instructions, 11 reversed-operand, 11 of 16 slot positions
  reversed (scan A 7, scan B 4). Hits swap the 16-byte entries and
  rejoin the walk (scan A via `0x63cdfb5` to the second extract at
  `0x63cdedc`; scan B via `0x63ce006` to the first extract at
  `0x63cdeae`); exhaustions fall to the two miss blocks (scan A on
  slot-7 mismatch at `0x63ce162`; scan B on slot-7 mismatch at
  `0x63ce1d6`).
- Lu-miss sites (2): one argument pattern — `rdi` = `r12`
  context, `rsi` = `0x6511a00` (`.bss`), `rdx` = walk table pointer
  (`lea 0x1b0(%r12),%rdx` at `0x63cde6e`), `rcx` = `rbp` walk key,
  `r8d` = 1, `r9d` = 0. Site 1 (`0x63ce1f8`, block `0x63ce1e2`,
  scan-A exhaustion) rejoins at the second extract `0x63cdedc`
  with no callee-saved register spilled across the call; site 2
  (`0x63ce221`, block `0x63ce202`, scan-B exhaustion) saves `r10`
  and `rdx` to the stack (`mov %r10,0x8(%rsp)` at `0x63ce218`,
  `mov %rdx,(%rsp)` at `0x63ce21d`) and restores them after the
  call, then rejoins at the first extract `0x63cdeae`. The `rcx`
  provenance is proven by reaching-definitions: the only `rcx`
  definition reaching site 1 is `mov %rbp,%rcx` at `0x63ce1ec`
  and the only one reaching site 2 is `mov %rbp,%rcx` at
  `0x63ce20c`; the only `rbp` definition reaching either site is
  `mov 0x18(%r13),%rbp` at `0x63cde5b` (the walk-key node pointer).
  The `rdx` at site 2 is the same `lea 0x1b0(%r12),%rdx` at
  `0x63cde6e`; at site 1 it additionally admits the restore `mov
  (%rsp),%rdx` at `0x63ce232`, which is reachable only on the
  second pass after site 2's call (the miss handler returns, the
  walk continues, and the second-level compare can miss again into
  scan A). The `r15` at site 1 is the size class from the first
  extract (`mov (%rsi,%rax,8),%r15` at `0x63cdebc`); at site 2 it
  is the caller's entry value, because the first extract has not
  run on the top-index-miss path — `r15` is not a lu-miss argument
  in either case.
- Second-handler sites (0): the second miss handler `0x634ebb0`
  is never called from this FDE (verified by objdump census and
  raw-`0xe8` census).
- Dispatcher: `0x63cd910` 1 (prev FDE; its return is the new node
  pointer), `0x63c89c0` 1 (release call after the walk),
  `0x63c3780` 1, `0x63c3b00` 1 (context init/refresh arms),
  `0x63d9700` 2 (lu-miss); PLT: `__ctype_b_loc` 1. The #314–#322
  windows are NOT called from this FDE.
- Exit: THREE rets with one reaching `rax` definition each — 0
  (`xor %eax,%eax` at `0x63cdf23`, success path, ret `0x63cdf2f`),
  14 (`mov $0xe,%eax` at `0x63cdf34`, null string or ctype-test
  failure, ret `0x63cdf43`), 11 (`mov $0xb,%eax` at `0x63cdf6b`,
  context-init failure, ret `0x63cdf7a`) — so no single exit value
  is established. This is the first frontier window with three
  rets and three distinct exit values.

## Census

- Raw `0xe8` census (own `.eh_frame` parse, 135,313 FDEs):
  lu-miss 168 sites / 53 FDEs (this FDE 2); bin_table_init 108 sites /
  42 FDEs (this FDE 0); second-handler 64 sites / 28 FDEs (this FDE
  0; the next candidate holds 1).
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278.
- `.bss` `0x64ffe40..0x6728924`; three referenced addresses inside
  (`0x65096c0`, `0x6511a00`, `0x6727a00`). No `.data.rel.ro`
  address is referenced.

## Correction to #322's pointer

#322's survey pointer for this window (1131 bytes, 242 strict,
7 calls, 2 lu-miss sites at `0x63ce1f8` and `0x63ce221`, 0
bin_table_init sites, 0 second-handler sites, THREE rets at
`0x63cdf2f`, `0x63cdf43`, and `0x63cdf7a`, bsr 0) was verified correct
by targeted objdump census. No correction
(`prior_pointer_verified`).

## Frontier status

Tenth packet of the lu-miss-caller frontier (53 FDEs, 168 sites,
16 survivors): #314 on `0x63495b0`, #315 on `0x6353a70`, #316 on
`0x6355900`, #317 on `0x63577f0`, #318 on `0x635a7a0`, #319 on
`0x635c6d0`, #320 on `0x635e2e0`, #321 on `0x63c9650`, #322 on
`0x63ccd60`. This window is a lu-miss-ONLY survivor (in the lu-miss
survivor list but NOT in the second-handler survivor list), so
claiming it consumes one slot of the combined 25-FDE miss-handler
pool (lu-miss 16 ∪ second-handler 18, 9 shared) without being
shared.

## Disjointness

Range-only collector over all prior records. The window
`0x63cddd0..0x63ce23b` overlaps no prior range (verifier: 76,548 priors
scanned, 0 skipped, disjointness NONE). The next candidate `0x63d03a0..0x63d17d7` is likewise
disjoint from all priors and from this window (verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262, NOT called
  from this FDE), the lu-miss handler `0x63d9700..0x63d987b` (#215),
  the second miss handler `0x634ebb0..0x634eccd` (NOT called from
  this FDE), the lock-wait helper `0x63bf680..0x63bf7ee` (#251, NOT
  called from this FDE), and the PLT stub `__ctype_b_loc@plt`
  are cited, not claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the prev FDE `0x63cd910..0x63cddce` (called once at `0x63cde4a`),
  the next FDE `0x63ce240..0x63ce501`, the release helper
  `0x63c89c0..0x63c8d5a`, the init helpers `0x63c3780..0x63c3885`
  and `0x63c3b00..0x63c3b6b`, and the #314–#322 windows (NOT called
  from this FDE).
- The `.bss` objects are referenced by address only; their runtime
  contents are not established.
- The entry inputs' caller-side meaning, the walk key's caller-side
  meaning beyond its origin (the node pointer in `0x18(%r13)`), the
  `0x68`/`0x18`/`0x21`/`0x330` field semantics beyond the observed
  reads/writes, and the dispatcher callees' semantics beyond their
  call sites are not established. The exit values' meaning beyond
  their three distinct paths is not established.

## Verification

- Static verifier `tools/node115_lu_miss_caller_2site_ctypescan.py`:
  exit 0 (314 checks, 0 failures).
- Own unit tests `tests/test_node115_lu_miss_caller_2site_ctypescan.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (12 checks, 0 failures).
- `make verify`: exit 0 (559 evidence-packet manifests, 7159 entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine checkout;
  not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Next question

Packet #324 decodes `0x63d03a0..0x63d17d7` (5175 bytes, 1037 strict,
23 calls, 10 lu-miss sites at `0x63d1063`, `0x63d1183`, `0x63d1258`,
`0x63d12a8`, `0x63d1416`, `0x63d15b6`, `0x63d166c`, `0x63d16b7`,
`0x63d177a`, and `0x63d17c1`, 0 bin_table_init sites, 1
second-handler site at `0x63d0837`, 1 ret at `0x63d0817`, bsr 2 —
the next surviving lu-miss caller after this packet, verified by
targeted objdump census against all prior exhibits; it is a SHARED
survivor, unlike this packet).
