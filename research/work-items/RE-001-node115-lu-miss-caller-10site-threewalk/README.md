# RE-001-node115-lu-miss-caller-10site-threewalk: lu-miss caller with three walks, an outer size-class loop, and ten miss sites (largest window so far)

Eleventh packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, #316 on `0x6355900`, #317 on `0x63577f0`, #318 on
`0x635a7a0`, #319 on `0x635c6d0`, #320 on `0x635e2e0`, #321 on
`0x63c9650`, #322 on `0x63ccd60`, and #323 on `0x63cddd0`). FDE
`0x63d03a0..0x63d17d7` (5175 bytes, 1037 strict lines) is the largest
lu-miss window so far: an outer loop that recomputes the size class
each iteration, a key-resolver call, THREE context-table walks (A, B,
C) plus a deep-resolution tail (D, D-prime), TEN lu-miss sites, and a
single ret with two possible exit values. It opens with `push %r15`
(NO `endbr64` — the first frontier window without one), keeps the
context base in `r15`, the remaining count in `r12d` (from `0x14(%rsi)`),
and the resolver input `0x88(%r15)` in `r14`. The size class is
recomputed each outer iteration from the count (`shl`, `$0x3800` /
`$0x1000` thresholds, byte table `0x67277c0`, size table `0x6727a00`,
`$0x3fff` cap, `0x6728140` fallback, `$0x4000` cap), then `cmpb
$0x0,0x1(%r15)` gates the second-handler path. Resolver `0x6365150`
(`rdi` = `r15`, `rsi` = `r14`, `rdx` = size class, `rcx` = `$0x40`,
`r8d` = 1, `r9d` = 0) returns the walk-A key in `rax` (null → exit 1).
Walk A (key `r14`, `lock add`) runs an element loop calling the prev
FDE `0x63d0080` once per element, then walk B (key `r10`, `lock sub`)
and walk C (key `r12`, `lock sub`) follow, with a deep-resolution tail
(`0x63bd6c0`, `0x63637f0`, `0x6363260`) and a loop-back to `0x63d03d4`.
Ten 8-slot move-to-front scans share one slot set (`0x2b0..0x320` in
`r15`): 74 slot-compare instructions, EIGHTEEN reversed-operand (B1
slots 1, 2, 4; B2 slots 3, 4, 5, 6; C3 slots 1, 2, 3, 4; D2 slots
1–7), i.e. 18 of 80 slot positions reversed; nine scans are unrolled
chains, D1 is a counter loop. All ten miss sites share one argument
pattern (`rdi` = `r15` context, `rsi` = `.bss` `0x6511a00`, `rdx` =
walk table pointer from `0x18(%rsp)`, `rcx` = walk key, `r8d` = 1,
`r9d` = 0), with the `rcx` provenance proven by
reaching-definitions: sites 1, 3, 5, 6 take `r10` (the walk-B key),
sites 2, 4, 7, 8 take `r12` (the walk-C key), sites 9, 10 take `r14`
(the walk-A key). It exits by a SINGLE ret with two reaching `rax`
definitions — 0 (`xor %eax,%eax` at `0x63d066f` / `0x63d0d30` /
`0x63d1316`, leaf exits) or 1 (`mov $0x1,%eax` at `0x63d07f0`,
resolver-null and size-class overflow paths) — so no single exit
value is established, unlike #314 (`rbx`), #315 (`r12`), #316
(`r13`), #317 (`r12`), #319 (0), and #320 (`r15`). 0
`bin_table_init` sites, 1 second-handler site at `0x63d0837`, 2
`bsr`, 0 tail-jump exits, 2 `lock sub` and 1 `lock add`, canary
present, NO TLS flag check. This window is a SHARED survivor (in
both the lu-miss survivor list and the second-handler survivor
list), so claiming it consumes one slot of the combined 25-FDE
miss-handler pool. It never calls the lock-wait helper `0x63bf680`
— the follow-on frontier's helper — cited, not claimed.

## Window

| Item | Value |
| --- | --- |
| FDE | `0x63d03a0..0x63d17d7` |
| Bytes | 5175 |
| Strict lines | 1037 |
| Calls | 23 (11 distinct direct targets, 0 indirect) |
| Bin_table_init sites | 0 |
| Lu-miss sites | 10 (`0x63d1063`, `0x63d1183`, `0x63d1258`, `0x63d12a8`, `0x63d1416`, `0x63d15b6`, `0x63d166c`, `0x63d16b7`, `0x63d177a`, `0x63d17c1`) |
| Second-handler sites | 1 (`0x63d0837`) |
| Ret | 1 (`0x63d0817`) |
| Tail-jump exits | 0 |
| Bsr | 2 (`0x63d07a4`, `0x63d0a80`) |
| Lock sub / add | 2 / 1 |
| Jumps | 172 (0 outside) |
| Prev FDE | `0x63d0080..0x63d0398` (gap 8, all `0xcc`) |
| Next FDE | `0x63d17e0..0x63d2a80` (padding 9, all `0xcc`) |

## Classification

- Entry: NO `endbr64`; first instruction is `push %r15` at
  `0x63d03a0`, then `mov %rdi,%r15` at `0x63d03a2`; pushes
  r14/r13/r12/rbp/rbx, `sub $0x58,%rsp`. `rdi` is the context base
  (kept in `r15`); `rsi` is the count holder (kept in `rbx`);
  `0x14(%rsi)` is the remaining count (loaded at `0x63d03b4`, kept
  in `r12d` via `lea 0x2(%rsi),%r12d` at `0x63d03d0`). Canary
  present (`mov %fs:0x28,%rax` at `0x63d03b7`, stored to
  `0x48(%rsp)`). No TLS flag check (`%fs:0x330` appears nowhere).
- Size class (outer loop head at `0x63d03d4`, recomputed each
  iteration): `lea 0x1(%r12),%edi`; `mov $0x10,%eax`; `shl
  %cl,%rax` at `0x63d03e4`; `cmp $0x3800,%rax` at `0x63d03e7`,
  `ja 0x63d0778` (first `bsr` path); `add $0x3f` / `and
  $0xffffffffffffffc0`; `cmp $0x1000,%rax` at `0x63d03fb`, `ja
  0x63d0a75` (second `bsr` path); byte table `lea 0x67277c0,%r9`
  at `0x63d0407`, `shr $0x3,%rax`, `movzbl (%r9,%rax,1),%r10d`
  at `0x63d0412`; size table `lea 0x6727a00,%rax` at `0x63d0417`,
  `mov (%rax,%r10,8),%rbp` at `0x63d041e`; `cmp $0x3fff,%rbp`
  at `0x63d0422`, `jbe 0x63d07d8`; fallback `lea 0x6728140,%r11`
  at `0x63d042f`, `mov (%r11),%rbp`, `add $0x4000,%rbp`; `cmp
  $0x3fff,%rbp` at `0x63d0440`, `jbe 0x63d07f0` (exit 1);
  `mov $0x4000,%ebp` at `0x63d044d`. Bsr paths: `bsr %rbp,%r8`
  at `0x63d07a4`; `bsr %rdi,%rdx` at `0x63d0a80`.
- Gate: `cmpb $0x0,0x1(%r15)` at `0x63d0452`; `jg 0x63d0818`
  (second-handler block) at `0x63d0457`.
- Resolver input: `mov 0x88(%r15),%r14` at `0x63d045d`; `test
  %r14,%r14` at `0x63d0464`; `je 0x63d0844` (the `0x6352fc0`
  path) at `0x63d0467` on null.
- Resolver call: `mov %r14,%rsi` at `0x63d046d`; `xor %r9d,%r9d`
  at `0x63d0470`; `mov $0x1,%r8d` at `0x63d0473`; `mov
  %rbp,%rdx` at `0x63d0479` (size class); `mov $0x40,%ecx` at
  `0x63d047c`; `mov %r15,%rdi` at `0x63d0481`; `call 0x6365150`
  at `0x63d0484`. Return: `mov %rax,%r14` at `0x63d0489`
  (walk-A key); `test %rax,%rax` at `0x63d048c`; `je
  0x63d07f0` (exit 1) at `0x63d048f` on null.
- Walk A (key = resolver return in `r14`/`r10`, table `r15` +
  `0x1b0`): `mov %rax,%rbp` at `0x63d0495`; `mov %rax,%r10` at
  `0x63d0498`; `lea 0x1b0(%r15),%rcx` at `0x63d049b`, stored to
  `0x18(%rsp)` at `0x63d04ad` (every lu-miss `rdx` is `mov
  0x18(%rsp),%rdx`). Top index `(key >> 0x1a) & 0xf0` (`shr
  $0x1a,%rbp` at `0x63d04a2`, `and $0xf0,%ebp` at `0x63d04b2`,
  `add %r15,%rbp` at `0x63d04b8`); high bits `key &
  0xffffffffc0000000` (`and $0xffffffffc0000000,%r10` at
  `0x63d04a6`); top compare `cmp %rdx,%r10` at `0x63d04c2`
  (`rdx` = `0x1b0(%rbp)`), mismatch to scan A1 at `0x63d08e4`.
  Second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`, head
  `mov (%rax),%r9` at `0x63d04db`. Extract: `lea 0x6727a00,%rax`
  at `0x63d04de` (size table); `shr $0x30,%r9` at `0x63d04e5`;
  `mov (%rax,%r9,8),%r11` at `0x63d04e9` (size class into
  `r11`). Second compare `cmp %rdx,%r10` at `0x63d04ed`,
  mismatch to scan A2 at `0x63d0895`. Then `shl $0x10,%r10` /
  `sar $0x10,%r10` / `and $0xffffffffffffff80,%r10` feeding node
  table `0x65096c0` (`lea 0x65096c0,%r9` at `0x63d050c`, `mov
  (%r9,%rax,8),%r8` at `0x63d0527`) and a `lock add
  %r11,0x38(%r8)` at `0x63d052b` (refcount increment by the size
  class).
- Element loop: `mov 0x28(%rbx),%r11` at `0x63d0530`; `mov
  %r14,0x28(%rbx)` at `0x63d0534`; `mov 0x8(%rbx),%r14` at
  `0x63d0538`; `sub $0x1,%r12d` at `0x63d053c`; `mov
  %r11,0x8(%rsp)` at `0x63d0540` (walk-B key save); `mov
  %r12d,0x14(%rbx)` at `0x63d0545`; per-element `call 0x63d0080`
  at `0x63d0582` (`rdi` = `rbx`, `rsi` = `lea 0x38(%rsp)`,
  `rdx` = `r13`); `test %al,%al` at `0x63d0587`, `jne
  0x63d0680` (walk C) at `0x63d0589` when the element call
  returns nonzero; otherwise the loop advances (`add $0x10,%rbp`
  at `0x63d0593`, `cmp %r14,%r12` at `0x63d0597`).
- Walk B (key = saved phrase `0x28(%rbx)` in `r10`/`r13`, table
  `r15` + `0x1b0`): `mov 0x8(%rsp),%r10` at `0x63d059c`; `mov
  %r10,%rbx` at `0x63d05a1`; `mov %r10,%r13` at `0x63d05a4`;
  `shr $0x1a,%rbx` at `0x63d05a7`; `and
  $0xffffffffc0000000,%r13` at `0x63d05ab`; `and $0xf0,%ebx` at
  `0x63d05b2`; `add %r15,%rbx` at `0x63d05b8`; top compare `cmp
  %rax,%r13` at `0x63d05c2` (`rax` = `0x1b0(%rbx)`), mismatch to
  scan B1 at `0x63d0dce`. Extract: `shr $0x30,%rdi` at
  `0x63d05e9` (size table `0x6727a00`), `mov
  (%rcx,%rdi,8),%r14` at `0x63d05ed`; second compare `cmp
  %rax,%r13` at `0x63d05f1`, mismatch to scan B2 at `0x63d0d83`.
  Then `shl $0x10,%r12` / `sar $0x10,%r12` / `and
  $0xffffffffffffff80,%r12` feeding node table `0x65096c0` and a
  `lock sub %r14,0x38(%r9)` at `0x63d0631` (refcount decrement
  by the size class). Leaf: `mov 0x1b0(%rbx),%r14` at `0x63d0636`;
  `cmp %r14,%r13` at `0x63d063d`, `jne 0x63d0d37` (scan B3) at
  `0x63d0640`; `test $0x1,%al` at `0x63d065c` — set calls
  `0x63637f0` at `0x63d066a` then exits 0 (`xor %eax,%eax` at
  `0x63d066f`); clear goes to the second-extract check at
  `0x63d0ce8`.
- Walk C (key = stored phrase `0x28(%rbx)` in `r12`/`r10`, table
  `r15` + `0x1b0`): `mov 0x28(%rbx),%r12` at `0x63d0680`; `mov
  %r14,0x8(%rbx)` at `0x63d0684`; `mov %r12,%rbp` at `0x63d0688`;
  `mov %r12,%r10` at `0x63d068b`; `shr $0x1a,%rbp` at
  `0x63d068e`; `and $0xffffffffc0000000,%r10` at `0x63d0692`;
  `and $0xf0,%ebp` at `0x63d0699`; `add %r15,%rbp` at
  `0x63d069f`; top compare `cmp %r14,%r10` at `0x63d06a9`
  (`r14` = `0x1b0(%rbp)`), mismatch to scan C1 at `0x63d0a22`.
  Extract: `shr $0x30,%rax` at `0x63d06cf` (size table
  `0x6727a00`), `mov (%rdx,%rax,8),%r11` at `0x63d06d3`;
  second compare `cmp %r14,%r10` at `0x63d06d7`, mismatch to
  scan C2 at `0x63d09d2`. Then the `shl`/`sar $0x10` extract
  feeding node table `0x65096c0` and a `lock sub
  %r11,0x38(%rsi)` at `0x63d0717`. Deep-resolution tail: `call
  0x63bd6c0` at `0x63d0979` and `0x63d0d2b`, `call 0x63637f0` at
  `0x63d0750`, `call 0x6363260` at `0x63d0c91` and `0x63d1311`;
  loop-back `mov 0x8(%rsp),%rbp` at `0x63d0755` and `jmp
  0x63d03d4` at `0x63d076c` (recompute the size class for the
  next count).
- Scan (ten 8-slot move-to-front scans over the same slot set,
  table+`0x2b0` in `r15`, 16-byte entries, swap-on-hit): A1/A2
  belong to walk A (key `r10`), B1/B2/B3 to walk B (key `r13`),
  C1/C2/C3 to walk C (key `r10`), D1/D2 to the deep walk (key
  `r13` / `r10`). Slot-0 compares: A1 `cmp %rsi,%r10` at
  `0x63d08eb` (slot value loaded into `rsi`, normal), A2 `cmp
  %rsi,%r10` at `0x63d089c` (normal), B1 `cmp 0x2b0(%r15),%r13`
  at `0x63d0dce` (normal), B2 `cmp 0x2b0(%r15),%r13` at
  `0x63d0d83` (normal), B3 `cmp 0x2b0(%r15),%r13` at `0x63d0d37`
  (normal), C1 `cmp %rdx,%r10` at `0x63d0a29` (slot value loaded into
  `rdx`, normal), C2 `cmp %r8,%r10` at `0x63d09d9` (normal), C3 `cmp
  %r8,%r10` at `0x63d098a` (normal), D1 `cmp
  0x2b0(%r15),%r13` at `0x63d12be` (normal), D2 `cmp
  %r8,%r10` at `0x63d0ca2` (slot value loaded into `r8`,
  normal). Reversed-operand compares (key register first):
  B1 slots 1, 2, 4 (`0x63d10b6`, `0x63d1193`, `0x63d11b9`); B2
  slots 3, 4, 5, 6 (`0x63d1439`, `0x63d144c`, `0x63d145f`,
  `0x63d1472`); C3 slots 1, 2, 3, 4 (`0x63d0b1b`, `0x63d0e47`,
  `0x63d14b1`, `0x63d14c1`); D2 slots 1–7 (`0x63d0ed9`,
  `0x63d0f8b`, `0x63d101c`, `0x63d102c`, `0x63d1083`,
  `0x63d1093`, `0x63d115b`). 74 slot-compare instructions, 18
  reversed-operand, 18 of 80 slot positions reversed (D1's loop
  compare at `0x63d132a` serves slots 1–7 in one instruction).
  Hits swap the 16-byte entries and rejoin the walk; exhaustions
  fall to the ten miss blocks: A1 → site 10, A2 → site 9, B1 →
  site 3, B2 → site 6, B3 → site 1, C1 → site 4, C2 → site 8, C3
  → site 7, D1 → site 5, D2 → site 2.
- Lu-miss sites (10): one argument pattern — `rdi` = `r15`
  context, `rsi` = `0x6511a00` (`.bss`), `rdx` = walk table
  pointer (`mov 0x18(%rsp),%rdx`), `rcx` = walk key, `r8d` = 1,
  `r9d` = 0. Site 1 (`0x63d1063`, block `0x63d1043`, scan-B3
  exhaustion, `rcx` = `r10`) rejoins at `0x63d0659` (walk-B
  leaf); site 2 (`0x63d1183`, block `0x63d1168`, scan-D2
  exhaustion, `rcx` = `r12`) rejoins at `0x63d0967` (walk-C
  second extract); site 3 (`0x63d1258`, block `0x63d1238`,
  scan-B1 exhaustion, `rcx` = `r10`) rejoins at `0x63d05df`
  (walk-B first extract); site 4 (`0x63d12a8`, block
  `0x63d1288`, scan-C1 exhaustion, `rcx` = `r12`) rejoins at
  `0x63d06c5` (walk-C first extract); site 5 (`0x63d1416`,
  block `0x63d13fb`, D1-loop exhaustion, `rcx` = `r10`) rejoins
  at `0x63d0d19` (walk-C tail); site 6 (`0x63d15b6`, block
  `0x63d1596`, scan-B2 exhaustion, `rcx` = `r10`) rejoins at
  `0x63d060d` (walk-B second extract); site 7 (`0x63d166c`,
  block `0x63d164c`, scan-C3 exhaustion, `rcx` = `r12`)
  rejoins at `0x63d073f` (walk-C tail); site 8 (`0x63d16b7`,
  block `0x63d1692`, scan-C2 exhaustion, `rcx` = `r12`)
  rejoins at `0x63d06f3` (walk-C second extract); site 9
  (`0x63d177a`, block `0x63d175a`, scan-A2 exhaustion, `rcx` =
  `r14`) rejoins at `0x63d0509` (walk-A second extract); site 10
  (`0x63d17c1`, block `0x63d17a1`, scan-A1 exhaustion, `rcx` =
  `r14`) rejoins at `0x63d04db` (walk-A first extract). Each
  block saves the key register to the stack before the call
  (`r10` → `0x8(%rsp)`, `r10` → `0x20(%rsp)`, `r11` →
  `0x8(%rsp)` / `0x20(%rsp)`) and restores it after; the save
  after the `rcx` setup does not affect that site's `rcx`. The
  `rcx` provenance is proven by reaching-definitions: the only
  `rcx` definition reaching site 1 is `mov %r10,%rcx` at
  `0x63d1048`, site 2 `mov %r12,%rcx` at `0x63d1170`, site 3
  `mov %r10,%rcx` at `0x63d123d`, site 4 `mov %r12,%rcx` at
  `0x63d1290`, site 5 `mov %r10,%rcx` at `0x63d1403`, site 6
  `mov %r10,%rcx` at `0x63d159b`, site 7 `mov %r12,%rcx` at
  `0x63d1654`, site 8 `mov %r12,%rcx` at `0x63d169a`, site 9
  `mov %r14,%rcx` at `0x63d1762`, site 10 `mov %r14,%rcx` at
  `0x63d17a9`. The walk keys themselves are loop-carried: `r10`
  reaches the sites from `mov 0x8(%rsp),%r10` at `0x63d059c`
  (walk-B key) plus restores; `r12` from `mov 0x28(%rbx),%r12`
  at `0x63d0680` (walk-C key); `r14` from `mov %rax,%r14` at
  `0x63d0489` (resolver return, walk-A key) — see the verifier's
  reaching-definition checks for the exact sets. The `rdx` at
  each site is the `mov 0x18(%rsp),%rdx` immediately before its
  block's setup; the `r15` at every site is the entry context
  (`mov %rdi,%r15` at `0x63d03a2`).
- Second-handler site (1): block `0x63d0818`, entered from the
  gate `jg 0x63d0818` at `0x63d0457` when `0x1(%r15)` is
  positive. `lea 0x65096c0,%rdx` at `0x63d0818` (node table);
  `mov (%rdx),%r14` at `0x63d081f`; `test %r14,%r14` at
  `0x63d0822`; `jne 0x63d046d` at `0x63d0825` (non-null skips the
  handler); `lea 0x64da4b0,%rdx` at `0x63d082b`
  (`.data.rel.ro`); `xor %esi,%esi` at `0x63d0832` (`rsi` = 0);
  `mov %r15,%rdi` at `0x63d0834`; `call 0x634ebb0` at
  `0x63d0837`; `mov %rax,%r14` at `0x63d083c`; `jmp 0x63d046d`
  at `0x63d083f` (resolver args).
- Dispatcher: `0x6365150` 1 (key resolver), `0x63d0080` 1 (prev
  FDE, per-element helper), `0x63637f0` 2 (leaf exits),
  `0x634ebb0` 1 (second handler), `0x6352fc0` 1, `0x63edf10` 1,
  `0x63bd6c0` 2 (deep-resolution tail), `0x63ec4c0` 1,
  `0x6363260` 2 (deep-resolution tail), `0x63d9700` 10
  (lu-miss); PLT: `__stack_chk_fail` 1. The #314–#323 windows
  are NOT called from this FDE.
- Exit: a SINGLE ret at `0x63d0817` with two reaching `rax`
  definitions — 0 (`xor %eax,%eax` at `0x63d066f` / `0x63d0d30`
  / `0x63d1316`, leaf exits via `0x63637f0` / `0x63bd6c0` /
  `0x6363260`) or 1 (`mov $0x1,%eax` at `0x63d07f0`,
  resolver-null and size-class overflow paths) — so no single
  exit value is established. Epilogue: `mov 0x48(%rsp),%rdx` at
  `0x63d07f5`; `sub %fs:0x28,%rdx` at `0x63d07fa`; `jne
  0x63d1383` (`__stack_chk_fail@plt`) at `0x63d0803`; `add
  $0x58,%rsp`; pops; `ret`.

## Census

- Raw `0xe8` census (own `.eh_frame` parse, 135,313 FDEs):
  lu-miss 168 sites / 53 FDEs (this FDE 10); bin_table_init 108 sites /
  42 FDEs (this FDE 0); second-handler 64 sites / 28 FDEs (this FDE
  1; the next candidate holds 1).
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278.
- `.bss` `0x64ffe40..0x6728924`; five referenced addresses inside
  (`0x65096c0`, `0x6511a00`, `0x67277c0`, `0x6727a00`,
  `0x6728140`). One `.data.rel.ro` address referenced
  (`0x64da4b0`).

## Correction to #323's pointer

#323's survey pointer for this window (5175 bytes, 1037 strict,
23 calls, 10 lu-miss sites at `0x63d1063`, `0x63d1183`, `0x63d1258`,
`0x63d12a8`, `0x63d1416`, `0x63d15b6`, `0x63d166c`, `0x63d16b7`,
`0x63d177a`, and `0x63d17c1`, 0 bin_table_init sites, 1
second-handler site at `0x63d0837`, 1 ret at `0x63d0817`, bsr 2)
was verified correct by targeted objdump census. No correction
(`prior_pointer_verified`).

## Frontier status

Eleventh packet of the lu-miss-caller frontier (53 FDEs, 168 sites,
16 survivors): #314 on `0x63495b0`, #315 on `0x6353a70`, #316 on
`0x6355900`, #317 on `0x63577f0`, #318 on `0x635a7a0`, #319 on
`0x635c6d0`, #320 on `0x635e2e0`, #321 on `0x63c9650`, #322 on
`0x63ccd60`, #323 on `0x63cddd0`. This window is a SHARED survivor
(in both the lu-miss survivor list and the second-handler survivor
list), so claiming it consumes one slot of the combined 25-FDE
miss-handler pool (lu-miss 16 ∪ second-handler 18, 9 shared).
Five lu-miss survivors remain after this packet: `0x63d17e0`,
`0x63d2a80`, `0x63d3f0e`, `0x63d4048`, `0x63e94a0`.

## Disjointness

Range-only collector over all prior records. The window
`0x63d03a0..0x63d17d7` overlaps no prior range (verifier: 77,391 priors
scanned, 0 skipped, disjointness NONE). The next candidate `0x63d17e0..0x63d2a80` is likewise
disjoint from all priors and from this window (verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262, NOT called
  from this FDE), the lu-miss handler `0x63d9700..0x63d987b` (#215),
  the second miss handler `0x634ebb0..0x634eccd` (called once at
  `0x63d0837`), the lock-wait helper `0x63bf680..0x63bf7ee` (#251, NOT
  called from this FDE), and the PLT stub `__stack_chk_fail@plt`
  are cited, not claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the prev FDE `0x63d0080..0x63d0398` (called once at `0x63d0582`),
  the next FDE `0x63d17e0..0x63d2a80`, the key resolver
  `0x6365150..0x6365660` (called once at `0x63d0484`), the #300
  window `0x63637f0..0x6363d50` (called twice), the #298 window
  `0x6363260..0x6363552` (called twice), and the #314–#323 windows
  (NOT called from this FDE).
- The `.bss` objects are referenced by address only; their runtime
  contents are not established.
- The entry inputs' caller-side meaning, the walk keys' caller-side
  meaning beyond their origins (resolver return, saved/stored
  phrases), the `0x14`/`0x88`/`0x1` field semantics beyond the
  observed reads/writes, and the dispatcher callees' semantics
  beyond their call sites are not established. The exit values'
  meaning beyond their two distinct paths is not established.

## Verification

- Static verifier `tools/node115_lu_miss_caller_10site_threewalk.py`:
  exit 0 (502 checks, 0 failures).
- Own unit tests `tests/test_node115_lu_miss_caller_10site_threewalk.py`
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

Packet #325 decodes `0x63d17e0..0x63d2a80` (4768 bytes, 928 strict,
20 calls, 10 lu-miss sites at `0x63d2549`, `0x63d2575`, `0x63d26f7`,
`0x63d2738`, `0x63d2771`, `0x63d2871`, `0x63d28a6`, `0x63d29b3`,
`0x63d29e1`, and `0x63d2a76`, 0 bin_table_init sites, 1
second-handler site at `0x63d1c81`, 1 ret at `0x63d1bd7`, bsr 2 —
the next surviving lu-miss caller after this packet, verified by
targeted objdump census against all prior exhibits; it is also a
SHARED survivor, like this packet).
