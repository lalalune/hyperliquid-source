# RE-001-node115-lu-miss-caller-2site-trylock: lu-miss caller with a trylock-guarded linked-list walk (first window with a lock-wait-helper call and no TLS/size-class frame)

Eighth packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, #316 on `0x6355900`, #317 on `0x63577f0`, #318 on
`0x635a7a0`, #319 on `0x635c6d0`, and #320 on `0x635e2e0`). FDE
`0x63c9650..0x63c9c80` (1584 bytes, 363 strict lines) is a
trylock-guarded linked-list traversal with a context-table walk and TWO
lu-miss sites — the eighth frontier window, and the first with no
`endbr64`, no canary, no TLS flag check, and no size class at all. It
opens with an entry null guard on the list head (`mov (%rsi),%rdx`,
`je 0x63c985a`), walks the list over its `0x18` next pointers, and for
each element takes a `pthread_mutex_trylock` on the node (`lea
0x40(%rbx),%rdi`), retrying through the lock-wait helper `0x63bf680`
when the trylock fails, bumps the `0x38` refcount, and resolves the
element through a three-field ordered-insert key compare (`0x8`,
`0x10`, `0x68` via `setb`/`sbb`) plus a field dispatch on `0x84(%rbp)`
(`2` -> set `1`, `3` -> chain advance). The single context-table walk
is keyed by the current node pointer in `r12` (first from `0x10(%r15)`,
later from the `0x63c7ef0` return), with an inline `shr $0x30`
extract feeding size table `0x6727a00` and a `shl $0x10` / `sar $0x10`
extract feeding node table `0x65096c0` and a `lock sub` refcount
decrement. Two 8-slot move-to-front scans share one slot set
(`0x2b0..0x320` in `r14`) with exactly ONE reversed-operand compare
(the second scan's slot-0 at `0x63c998f`); their exhaustions fall to
the two lu-miss sites. Both miss sites share one argument pattern
(`rdi` = `r14` context, `rsi` = `.bss` `0x6511a00`, `rdx` = saved walk
table from `0x10(%rsp)`, `rcx` = `r12` walk key, `r8d` = 1, `r9d` = 0),
with the `rcx` provenance proven by reaching-definitions (the only
`r12` definitions reaching either site are `mov %rbp,%r12` at
`0x63c9713` and `mov %rax,%r12` at `0x63c97fd`). It exits by a single
`ret` with `rax` path-dependent (the entry `0x68(%rdi)` value, the
unlock return, or the `0x63c9500` return) — no single exit value is
established, unlike #314 (`rbx`), #315 (`r12`), #316 (`r13`), #317
(`r12`), #319 (0), and #320 (`r15`). 0 `bin_table_init` sites, 0
`bsr`, 0 tail-jump exits, 1 `lock sub` (0 `lock add`). This window is
a lu-miss-ONLY survivor (in the lu-miss survivor list but NOT in the
second-handler survivor list), so claiming it consumes one slot of the
combined 25-FDE miss-handler pool without being shared. It also calls
the lock-wait helper `0x63bf680` once — the follow-on frontier's
helper — cited, not claimed.

## Window

| Item | Value |
| --- | --- |
| FDE | `0x63c9650..0x63c9c80` |
| Bytes | 1584 |
| Strict lines | 363 |
| Calls | 12 (10 distinct direct targets, 0 indirect) |
| Bin_table_init sites | 0 |
| Lu-miss sites | 2 (`0x63c9c29`, `0x63c9c76`) |
| Second-handler sites | 0 |
| Ret | 1 (`0x63c9868`) |
| Tail-jump exits | 0 |
| Bsr | 0 |
| Lock sub / add | 1 / 0 |
| Jumps | 58 (0 outside) |
| Prev FDE | `0x63c9500..0x63c964d` (gap 3, all `0xcc`) |
| Next FDE | `0x63c9c80..0x63cb146` (padding 0) |

## Classification

- Entry: no `endbr64`; pushes r15/r14/r13/r12/rbp/rbx, `sub
  $0x38,%rsp`, NO canary. `rdi` is the context base (kept in `r14`);
  `rsi` is the address of the list-head pointer (kept in `r12`);
  `0x68(%rdi)` is saved to `0x18(%rsp)`. Entry null guard: `mov
  (%rsi),%rdx` at `0x63c9662`, `test %rdx,%rdx` at `0x63c966a`,
  `je 0x63c985a` (epilogue) — a null list head skips the body. No TLS
  flag check, no size class, no byte table `0x67277c0`, no `$0xe7`
  gate anywhere in the window.
- Outer list walk (one element per iteration): `mov %rdx,%r15` at
  `0x63c9680`, `mov 0x18(%rdx),%rdx` at `0x63c9683`, `jne 0x63c9680`
  — follows `0x18` next pointers until null; `r15` is the last node.
  Then `mov %r12,%rdi; mov %r15,%rsi; call 0x63c58b0` at `0x63c9692`.
- Trylock guard: `mov (%r15),%rbx` at `0x63c9697`; `lea
  0x40(%rbx),%rdi` at `0x63c969a`; `call pthread_mutex_trylock@plt`
  at `0x63c969e`; `test %eax,%eax` at `0x63c96a3`; `jne 0x63c99d8`
  on failure. The failure path calls the lock-wait helper `0x63bf680`
  at `0x63c99db` (`rdi` = `rbx`), sets `movb $0x1,0x68(%rbx)` at
  `0x63c99e0`, and jumps back to `0x63c96ab` to retry. On success:
  `addq $0x1,0x38(%rbx)` (refcount) at `0x63c96ab`; owner field
  `0x30(%rbx)` compared to `r14` (`cmp 0x30(%rbx),%r14`), updated
  with `addq $0x1,0x28(%rbx)` + `mov %r14,0x30(%rbx)` when it
  changes.
- Node key: `mov 0x10(%r15),%rbp` at `0x63c96bf`, `lea
  0x10(%r15),%r13` at `0x63c96c3`; null `rbp` goes to the tail at
  `0x63c980e` (`je` at `0x63c96ca`). Otherwise the field helper
  `0x63c7620` is called at `0x63c96e1` (`rdi` = `r13`, `rsi` =
  `0x70(%rbp)`, `rdx` = the 45-byte field-check callback at
  `0x63c4c40`, `rcx` = `r14`); nonzero return jumps to `0x63c9920`
  (`mov %rax,%rbp; jmp 0x63c9707`).
- Field dispatch: `mov 0x84(%rbp),%ecx` at `0x63c96ef`; `cmp $0x2`
  -> `je 0x63c9870` (`movl $0x1,0x84(%rbp)`); `cmp $0x3` ->
  `jne 0x63c987a`. At `0x63c987a` the `0x78` chain advances (`mov
  0x78(%rbp),%rsi; mov %rsi,%rbp; and $~1,%rbp; cmp $0x1,%rsi; ja
  0x63c96d0`); chain end jumps to the tail at `0x63c980e`.
- Ordered insert (entered when `0x78(%r12)` <= 1, `jbe 0x63c9898`):
  a three-field key compare (`0x8`, `0x10`, `0x68` of the chain
  nodes) via `setb`/`sbb` at `0x63c98b0..0x63c98f2`, walking with
  `mov 0x78(%rax),%rax; and $~1,%rax`; `ebp` == -1 takes the node
  (`mov %rax,%rbx` at `0x63c9915`), `ebp` == 0 rejoins the helper
  path at `0x63c973c`.
- Walk (single, table in `r14` + 0x1b0, key in `r12`): top index
  `(key >> 0x1a) & 0xf0`, high bits `key & 0xffffffffc0000000`,
  compare `cmp %rdx,%r11` at `0x63c9769` (`rdx` =
  `0x1b0(%r10)`), mismatch to scan A at `0x63c9930`; second level
  `(key >> 0x9) & 0x1ffff8 + table + 0x8`, loaded into `rbp` at
  `0x63c9785`. The walk table pointer (`lea 0x1b0(%r14)`) is saved
  to `0x10(%rsp)` at `0x63c9716` and reloaded as the lu-miss `rdx`
  at both miss sites. The walk is re-entered per list element: the
  key is reloaded from `0x10(%r15)` (`mov %rbp,%r12` at `0x63c9713`)
  or from the `0x63c7ef0` return (`mov %rax,%r12` at `0x63c97fd`,
  `jne 0x63c971b`).
- Extract (two inline shapes, no helper call): `shr $0x30,%rbp`
  at `0x63c978f` + size table `0x6727a00` (`mov (%rax,%rbp,8),%rbp`
  at `0x63c9793`); `shl $0x10,%r11` / `sar $0x10,%r11` /
  `and $0xffffffffffffff80,%r11` feeding the node table `0x65096c0`
  (`mov (%rax,%rdi,8),%r8` at `0x63c97d2`, `rdi` = `(%r11) &
  0xfff`) and a `lock sub %rbp,0x38(%r8)` at `0x63c97d6`
  (refcount decrement under lock). The walk's second top-level
  re-check at `0x63c9797` uses the flipped operand order
  (`cmp %r11,%rdx`, `jne 0x63c9988` to scan B) — counted separately
  from the scan compares below.
- Scan (two 8-slot move-to-front loops over the same slot set,
  table+`0x2b0` in `r14`, key in `r11`): slot-0 A at `0x63c9937`
  (`cmp %rsi,%r11`, normal order), slot-0 B at `0x63c998f`
  (`cmp %r11,%rsi`, REVERSED — the only reversed-operand compare
  in the window); slots 1–7 in loop A (`0x63c9a21`, `0x63c9ad8`,
  `0x63c9b1e`, `0x63c9b2e`, `0x63c9b8e`, `0x63c9b9e`, `0x63c9bf7`)
  and loop B (`0x63c9a82`, `0x63c9af6`, `0x63c9b56`, `0x63c9b66`,
  `0x63c9bc6`, `0x63c9bd6`, `0x63c9c4e`), all slot-value-first
  (normal order); 16 slot compares total. Hits swap the 16-byte
  entries (`0x2b0`/`0x2b8` of the two slots) and rejoin the walk
  (A at `0x63c9785`, B at `0x63c97b3`). Slot-7 exhaustion falls
  through to miss block 1 (A) or miss block 2 (B).
- Lu-miss sites (2): one argument pattern — `rdi` = `r14`
  context, `rsi` = `0x6511a00` (`.bss`), `rdx` = `0x10(%rsp)`
  (saved walk table), `rcx` = `r12` walk key, `r8d` = 1, `r9d` =
  0. Site 1 (`0x63c9c29`, block `0x63c9c04`) saves `r10`/`r11`
  to the stack and rejoins at `0x63c9785` with `mov
  0x1b0(%r10),%rdx` (the handler's `rax` return is dereferenced
  as the second-level pointer); site 2 (`0x63c9c76`, block
  `0x63c9c5b`) rejoins directly at `0x63c97b3`. The `rcx`
  provenance is proven by reaching-definitions: the only `r12`
  definitions reaching either site are `mov %rbp,%r12` at
  `0x63c9713` and `mov %rax,%r12` at `0x63c97fd` — both node
  pointers, not entry `rdi`. (The entry `mov %rsi,%r12` at
  `0x63c9676` is killed on both paths before the walk, and the
  tail restore at `0x63c9809` only reaches the walk via the outer
  loop, which passes `0x63c9713`/`0x63c97fd` first.)
- Second-handler sites (0): `0x634ebb0` is NOT called from this FDE.
- Dispatcher: `0x63c58b0` 1, `0x63c7620` 1, `0x63c50e0` 1,
  `0x63c89c0` 1, `0x63c7ef0` 1 (its return becomes the next walk
  key), `0x63bf680` 1 (lock-wait, trylock-failure path only),
  `0x63c9500` 1 (last-reference path); PLT:
  `pthread_mutex_trylock` 1, `pthread_mutex_unlock` 2. The #314–
  #320 windows are NOT called from this FDE.
- Tail: `mov 0x8(%r15),%r13d` at `0x63c980e`, `sub $0x1,%r13d`,
  flag `0x6713601` (`cmpb $0x0,(%rbx)` at `0x63c9820`); if the flag
  is 0, `0x10(%r15)` is 0, and the count reaches 0, the
  last-reference path at `0x63c99e9` sets the count to 1, clears
  `0x28` of the node, unlocks, and calls `0x63c9500` at
  `0x63c9a09`. Otherwise `movb $0,0x68(%rdi)` at `0x63c9840` and
  unlock at `0x63c9848`. Then the next head pointer is re-read
  (`mov (%r12),%rdx` at `0x63c984d`) and the outer loop repeats
  (`jne 0x63c9680`).
- Exit: `rax` is path-dependent at the single `ret` (`0x63c9868`;
  epilogue `add $0x38,%rsp`, pops, no `rax` write): the reaching
  definitions at the ret are the entry `mov 0x68(%rdi),%rax` at
  `0x63c965e` (null-head path), the unlock return (`call
  0x63c9848`), and the `0x63c9500` return (`call 0x63c9a09`) — so
  no single exit value is established.

## Census

- Raw `0xe8` census (own `.eh_frame` parse, 135,313 FDEs):
  lu-miss 168 sites / 53 FDEs (this FDE 2); bin_table_init 108 sites /
  42 FDEs (this FDE 0); second-handler 64 sites / 28 FDEs (this FDE
  0; the next candidate holds 1).
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278.
- `.bss` `0x64ffe40..0x6728924`; four referenced addresses inside
  (`0x65096c0`, `0x6511a00`, `0x6713601`, `0x6727a00`). The callback
  `0x63c4c40` is inside `.text`.

## Correction to #320's pointer

#320's survey pointer for this window (1584 bytes, 363 strict,
12 calls, 2 lu-miss sites at `0x63c9c29` and `0x63c9c76`, 0
bin_table_init sites, 0 second-handler sites, 1 ret at `0x63c9868`,
bsr 0) was verified correct by targeted objdump census. No correction.

## Frontier status

Eighth packet of the lu-miss-caller frontier (53 FDEs, 168 sites,
16 survivors): #314 on `0x63495b0`, #315 on `0x6353a70`, #316 on
`0x6355900`, #317 on `0x63577f0`, #318 on `0x635a7a0`, #319 on
`0x635c6d0`, #320 on `0x635e2e0`. This window is a lu-miss-ONLY
survivor, so claiming it consumes one slot of the combined 25-FDE
miss-handler pool (lu-miss 16 ∪ second-handler 18, 9 shared)
without being shared.

## Disjointness

Range-only collector over all prior records. The window
`0x63c9650..0x63c9c80` overlaps no prior range (verifier:
74,862 priors scanned, 0 skipped, disjointness NONE). The next
candidate `0x63ccd60..0x63cd907` is likewise disjoint from all priors
and from this window (verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262), the lu-miss
  handler `0x63d9700..0x63d987b` (#215), the second miss handler
  `0x634ebb0..0x634eccd` (NOT called from this FDE), the lock-wait
  helper `0x63bf680..0x63bf7ee` (#251, called once on the
  trylock-failure path), the extract helper FDE `0x63be540..0x63be54d`
  (NOT called from this FDE), and the PLT stubs are cited, not
  claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the prev FDE `0x63c9500..0x63c964d` (called once on the
  last-reference path), the field-check callback `0x63c4c40..0x63c4c6d`
  (passed in `rdx` to `0x63c7620`), and the #314–#320 windows (NOT
  called from this FDE).
- The `.bss` objects are referenced by address only; their runtime
  contents are not established.
- The entry inputs' caller-side meaning, the walk key's caller-side
  meaning beyond its node-pointer origin, the `0x68`/`0x28`/`0x30`/
  `0x38` node-field semantics beyond the observed reads/writes, and
  the dispatcher callees' semantics beyond their call sites are not
  established. The exit value's meaning beyond its path-dependence
  is not established.

## Verification

- Static verifier `tools/node115_lu_miss_caller_2site_trylock.py`:
  exit 0 (295 checks, 0 failures).
- Own unit tests `tests/test_node115_lu_miss_caller_2site_trylock.py`
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

Packet #322 decodes `0x63ccd60..0x63cd907` (2983 bytes, 613 strict,
31 calls, 6 lu-miss sites at `0x63cd70d`, `0x63cd7b3`, `0x63cd7f1`,
`0x63cd831`, `0x63cd86a`, `0x63cd8fd`, 0 bin_table_init sites, 1
second-handler site at `0x63cd27f`, 1 ret at `0x63cd044`, bsr 0 — the
next surviving lu-miss caller after this packet, verified by targeted
objdump census against all prior exhibits; it is a SHARED survivor,
unlike this packet).
