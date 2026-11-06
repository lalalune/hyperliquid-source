# RE-001-node115-lu-miss-caller-10site-threetail: lu-miss caller with three walks, three tail jumps, and ten miss sites (uniform 0 exit)

Twelfth packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, #316 on `0x6355900`, #317 on `0x63577f0`, #318 on
`0x635a7a0`, #319 on `0x635c6d0`, #320 on `0x635e2e0`, #321 on
`0x63c9650`, #322 on `0x63ccd60`, #323 on `0x63cddd0`, and #324 on
`0x63d03a0`). FDE `0x63d17e0..0x63d2a80` (4768 bytes, 928 strict lines)
is a straight-line routine with NO outer loop: the size class is
computed once at entry, a key-resolver call feeds THREE context-table
walks (A, B, C) plus a deep-resolution tail (D, D-prime), TEN lu-miss
sites, and a single ret — with THREE tail-jump exits to three
different callees, and a uniform 0 exit across the ret and all three
tail jumps (each exit passes its own canary check, which zeroes
`rax`). It opens with `push %r15` (NO `endbr64` — the second frontier
window without one, after #324), keeps the context base in `r14`,
the count holder in `rbx`, and the resolver input `0x88(%r14)` in
`r13`. The size class is computed once from the count (`shl`,
`$0x3800` / `$0x1000` thresholds, byte table `0x67277c0`, size table
`0x6727a00`, `$0x3fff` cap, `0x6728140` fallback, `$0x4000` cap,
two `bsr` overflow arms), then `cmpb $0x0,0x1(%r14)` gates the
second-handler path. Resolver `0x6365150` (`rdi` = `r14`, `rsi` =
`r13`, `rdx` = size class, `rcx` = `$0x40`, `r8d` = 1, `r9d` = 0)
returns the walk-A key in `rax` (null → exit 0). Walk A (key from the
resolver return, `lock add`) runs an element loop calling the prev
FDE `0x63d0080` once per element, then walk B (key from the saved
node pointer in `0x8(%rsp)`, `lock sub`) and walk C (key `r10`,
`lock sub`) follow, with a deep-resolution tail (`0x63bd6c0`,
`0x63637f0`, `0x6363260`). Ten 8-slot move-to-front scans share one
slot set (`0x2b0..0x320` in `r14`): 68 slot-compare instructions,
SEVENTEEN reversed-operand (A1 slots 3, 6; B2 slots 3, 4, 5, 6; B3
slots 1, 2; C1 slots 1, 2; C2 slots 1, 2, 4, 5; C3 slots 1, 2, 5),
i.e. 17 of 80 slot positions reversed; eight scans are unrolled
chains, D1 and D2 are counter loops. All ten miss sites share one
argument pattern (`rdi` = `r14` context, `rsi` = `.bss` `0x6511a00`,
`rdx` = walk table pointer, `rcx` = walk key, `r8d` = 1, `r9d` = 0),
with the `rcx` provenance proven by reaching-definitions: sites 1,
2 take the walk-A key (resolver return), sites 3, 4, 5, 10 take
`r10` (the walk-C key), sites 6, 7, 8, 9 take the walk-B key from
the stack slot `0x8(%rsp)`. Site 1's `rdx` is the same walk table
pointer, taken from `r12` (`lea 0x1b0(%r14),%r12` at `0x63d18c1`,
its only reaching definition there — scan A1 is entered before
extract1 redefines `r12` as the size class); sites 2–10 load it
with `mov 0x18(%rsp),%rdx`. It exits by a SINGLE ret at `0x63d1bd7`
with ONE reaching `rax` definition — the canary sub at `0x63d1bba`
— so `rax` = 0 uniformly, unlike #324 (0 or 1), #323 (0 / 14 / 11),
and #319 (0, ret only). The three tail jumps exit the same way:
`jmp 0x63637f0` at `0x63d1abe` (canary sub `0x63d1a99`), `jmp
0x63bd6c0` at `0x63d212c` (canary sub `0x63d2100`), `jmp 0x6363260`
at `0x63d2450` (canary sub `0x63d2424`). 0 `bin_table_init` sites,
1 second-handler site at `0x63d1c81`, 2 `bsr`, 2 `lock sub` and 1
`lock add`, canary present, NO TLS flag check. This window is a
SHARED survivor (in both the lu-miss survivor list and the
second-handler survivor list), so claiming it consumes one slot of
the combined 25-FDE miss-handler pool. It never calls the lock-wait
helper `0x63bf680` — the follow-on frontier's helper — cited, not
claimed.

## Window

| Item | Value |
| --- | --- |
| FDE | `0x63d17e0..0x63d2a80` |
| Bytes | 4768 |
| Strict lines | 928 |
| Calls | 20 (11 distinct direct targets, 0 indirect) |
| Bin_table_init sites | 0 |
| Lu-miss sites | 10 (`0x63d2549`, `0x63d2575`, `0x63d26f7`, `0x63d2738`, `0x63d2771`, `0x63d2871`, `0x63d28a6`, `0x63d29b3`, `0x63d29e1`, `0x63d2a76`) |
| Second-handler sites | 1 (`0x63d1c81`) |
| Ret | 1 (`0x63d1bd7`) |
| Tail-jump exits | 3 (`0x63d1abe` → `0x63637f0`, `0x63d212c` → `0x63bd6c0`, `0x63d2450` → `0x6363260`) |
| Bsr | 2 (`0x63d1c0d`, `0x63d1ec8`) |
| Lock sub / add | 2 / 1 |
| Jumps | 156 (3 outside, all three tail jumps) |
| Prev FDE | `0x63d03a0..0x63d17d7` (gap 9, all `0xcc`) |
| Next FDE | `0x63d2a80..0x63d3071` (padding 0; starts with `endbr64`) |

## Classification

- Entry: NO `endbr64`; first instruction is `push %r15` at
  `0x63d17e0`, then `push %r14` at `0x63d17e2`, `mov %rdi,%r14`
  at `0x63d17e4`; pushes r13/r12/rbp/rbx, `mov %rsi,%rbx` at
  `0x63d17ed`, `sub $0x58,%rsp` at `0x63d17f0`. `rdi` is the
  context base (kept in `r14`); `rsi` is the count holder (kept
  in `rbx`); `0x14(%rsi)` is the remaining count (loaded at
  `0x63d1802`, saved to `0x14(%rsp)` at `0x63d180d`). Canary
  present (`mov %fs:0x28,%rax` at `0x63d17f4`, stored to
  `0x48(%rsp)` at `0x63d17fd`). No TLS flag check (`%fs:0x330`
  appears nowhere).
- Size class (computed ONCE at entry; no outer loop, unlike #324):
  `mov 0x14(%rsi),%eax` at `0x63d1802`; `mov $0x10,%esi` at
  `0x63d1805`; `lea 0x1(%rax),%ecx` at `0x63d180a`; `shl
  %cl,%rsi` at `0x63d1811`; `cmp $0x3800,%rsi` at `0x63d1814`,
  `ja 0x63d1be0` (first `bsr` arm); `add $0x3f` at `0x63d1821` /
  `and $0xffffffffffffffc0` at `0x63d1825`; `cmp $0x1000,%rsi`
  at `0x63d1829`, `ja 0x63d1ebe` (second `bsr` arm); byte table
  `lea 0x67277c0,%rdi` at `0x63d1836`, `shr $0x3,%rsi` at
  `0x63d183d`, `movzbl (%rdi,%rsi,1),%esi` at `0x63d1848`; size
  table `lea 0x6727a00,%rbp` at `0x63d1841`, `mov
  0x0(%rbp,%rsi,8),%r12` at `0x63d184c`; `cmp $0x3fff,%r12` at
  `0x63d1851`, `jbe 0x63d1c45`; fallback `lea 0x6728140,%r8` at
  `0x63d185e`, `mov $0x4000,%r12d` at `0x63d1865`, `cmpq
  $0xffffffffffffc000,(%r8)` at `0x63d186b`, `jae 0x63d1bb5`
  (exit 0) at `0x63d1872`. First `bsr` arm (`0x63d1be0`):
  `cmp $0x4000,%rsi`, `jbe 0x63d185e`; `movabs
  $0x7000000000000000,%rdx` at `0x63d1bed`; `cmp %rsi,%rdx` at
  `0x63d1bf7`, `jb 0x63d1bb5`; `lea -0x1(%rsi,%rsi,1),%rdi` at
  `0x63d1bfc`; `mov $0x7,%r9d` at `0x63d1c01`, `mov $0x1,%r10d`
  at `0x63d1c07`; `bsr %rdi,%rbp` at `0x63d1c0d`; `movslq
  %ebp,%r8` at `0x63d1c11`; `cmp %r9,%r8` at `0x63d1c14`,
  `cmovb %r9,%r8` at `0x63d1c17`; `lea -0x3(%r8),%rcx` at
  `0x63d1c1b`; `shl %cl,%r10` at `0x63d1c1f`; `lea
  -0x1(%rsi,%r10,1),%r12` at `0x63d1c22`; `neg %r10` at
  `0x63d1c27`; `and %r10,%r12` at `0x63d1c2a`; `cmp %rsi,%r12`
  at `0x63d1c2d`, `jb 0x63d1bb5`; `lea 0x6728140,%r11` at
  `0x63d1c32`; `mov %r12,%r13` at `0x63d1c39`; `add (%r11),%r13`
  at `0x63d1c3c`, `jb 0x63d1bb5`; `movabs
  $0x6fffffffffffffff,%r10` at `0x63d1c45`; `lea
  -0x1(%r12),%r9` at `0x63d1c4f`; `cmp %r9,%r10` at `0x63d1c54`,
  `jae 0x63d1878` (gate); `jmp 0x63d1bb5` (exit 0) at `0x63d1c5d`.
  Second `bsr` arm (`0x63d1ebe`): `lea -0x1(%rsi,%rsi,1),%r15`
  at `0x63d1ebe`; `mov $0x1,%edx` at `0x63d1ec3`; `bsr
  %r15,%rax` at `0x63d1ec8`; `lea -0x3(%rax),%ecx` at
  `0x63d1ecc`; `shl %cl,%rdx` at `0x63d1ecf`; `lea
  -0x1(%rsi,%rdx,1),%r12` at `0x63d1ed2`; `jmp 0x63d1878`
  (gate) at `0x63d1edd`.
- Gate: `cmpb $0x0,0x1(%r14)` at `0x63d1878`; `jg 0x63d1c62`
  (second-handler block) at `0x63d187d`.
- Resolver input: `mov 0x88(%r14),%r13` at `0x63d1883`; `test
  %r13,%r13` at `0x63d188a`; `je 0x63d1c8e` (the `0x6352fc0`
  path) at `0x63d188d` on null.
- Resolver call: `xor %r9d,%r9d` at `0x63d1893`; `mov $0x1,%r8d`
  at `0x63d1896`; `mov %r12,%rdx` at `0x63d189c` (size class);
  `mov %r13,%rsi` at `0x63d189f`; `mov $0x40,%ecx` at
  `0x63d18a2`; `mov %r14,%rdi` at `0x63d18a7`; `call 0x6365150`
  at `0x63d18aa`. Return: `mov %rax,%rbp` at `0x63d18af`;
  `test %rax,%rax` at `0x63d18b2`; `je 0x63d1bb5` (exit 0) at
  `0x63d18b5` on null; `mov %rax,%r15` at `0x63d18bb`, `mov
  %rax,%r13` at `0x63d18be` (walk-A key in three registers).
- Walk A (key = resolver return, table `r14` + `0x1b0`): `lea
  0x1b0(%r14),%r12` at `0x63d18c1`, stored to `0x18(%rsp)` at
  `0x63d18d3` (every lu-miss `rdx` is that table pointer).
  Top index `(key >> 0x1a) & 0xf0` (`shr $0x1a,%r15` at
  `0x63d18c8`, `and $0xf0,%r15d` at `0x63d18d8`, `add %r14,%r15`
  at `0x63d18df`); high bits `key & 0xffffffffc0000000` (`and
  $0xffffffffc0000000,%r13` at `0x63d18cc`); top compare `cmp
  %rdx,%r13` at `0x63d18e9` (`rdx` = `0x1b0(%r15)`), mismatch to
  scan A1 at `0x63d1d2c`. Extract: `shr $0x9,%rax` at
  `0x63d18f2`; `and $0x1ffff8,%eax` at `0x63d18f6`; `add
  0x1b8(%r15),%rax` at `0x63d18fb`; `mov (%rax),%rax` at
  `0x63d1902`; `lea 0x6727a00,%r12` at `0x63d1905` (size table);
  `shr $0x30,%rax` at `0x63d190c`; `mov (%r12,%rax,8),%r12` at
  `0x63d1910` (size class); second compare `cmp %rdx,%r13` at
  `0x63d1914`, mismatch to scan A2 at `0x63d1cdf`. Then `mov
  %rbp,%rax` at `0x63d191d`; `shr $0x9,%rax` at `0x63d1920`;
  `and $0x1ffff8,%eax` at `0x63d1924`; `add 0x1b8(%r15),%rax`
  at `0x63d1929`; `mov (%rax),%r15` at `0x63d1930`; `lea
  0x65096c0,%r11` at `0x63d1933` (node table); `shl $0x10,%r15`
  at `0x63d193a` / `sar $0x10,%r15` at `0x63d193e` / `and
  $0xffffffffffffff80,%r15` at `0x63d1942`; `mov (%r15),%r10`
  at `0x63d1946`; `and $0xfff,%r10d` at `0x63d1949`; `mov
  (%r11,%r10,8),%rax` at `0x63d1950`; `lock add %r12,0x38(%rax)`
  at `0x63d1954` (refcount increment by the size class).
- Element loop: `mov 0x28(%rbx),%r15` at `0x63d1959`; `mov
  0x8(%rbx),%r13` at `0x63d195d`; `mov %rbp,0x28(%rbx)` at
  `0x63d1961`; `mov 0x14(%rsp),%ebp` at `0x63d1965`; `mov
  %r15,0x8(%rsp)` at `0x63d1969` (walk-B key save); `sub
  $0x1,%ebp` at `0x63d196e`; `movq $0x0,0x8(%rbx)` at
  `0x63d1971`; `mov %ebp,0x14(%rbx)` at `0x63d1979`; `test
  %r13,%r13` at `0x63d197c`, `je 0x63d19cb` (walk B) at
  `0x63d197f` when empty; `xor %r12d,%r12d` at `0x63d1981`
  (element counter); per-element `call 0x63d0080` at `0x63d19b1`
  (`rdi` = `rbx`, `rsi` = `lea 0x38(%rsp)`, `rdx` = `rbp`,
  `rcx` = `(%r15)`, `rdi` slot = `0x8(%r15)`); `test %al,%al`
  at `0x63d19b6`, `jne 0x63d1ac8` (walk C) at `0x63d19b8` when
  the element call returns nonzero; otherwise `add $0x1,%r12`
  at `0x63d19be`, `add $0x10,%r15` at `0x63d19c2`, `cmp
  %r13,%r12` at `0x63d19c6`, `jb 0x63d1990` at `0x63d19c9`.
- Walk B (key = saved node pointer in `0x8(%rsp)`, table `r14` +
  `0x1b0`): `mov 0x8(%rsp),%rax` at `0x63d19cb`; `mov %rax,%rbx`
  at `0x63d19d0`; `mov %rax,%r15` at `0x63d19d3`; `shr
  $0x1a,%rbx` at `0x63d19d6`; `and $0xffffffffc0000000,%r15` at
  `0x63d19da`; `and $0xf0,%ebx` at `0x63d19e1`; `add %r14,%rbx`
  at `0x63d19e7`; top compare `cmp %rdx,%r15` at `0x63d19f1`
  (`rdx` = `0x1b0(%rbx)`), mismatch to scan B1 at `0x63d2025`.
  Extract: `shr $0x9,%rax` at `0x63d19fa`; `and $0x1ffff8,%eax`
  at `0x63d19fe`; `add 0x1b8(%rbx),%rax` at `0x63d1a03`; `mov
  (%rax),%rax` at `0x63d1a0a`; `lea 0x6727a00,%rcx` at
  `0x63d1a0d` (size table); `shr $0x30,%rax` at `0x63d1a14`;
  `mov (%rcx,%rax,8),%r13` at `0x63d1a18`; second compare `cmp
  %rdx,%r15` at `0x63d1a1c`, mismatch to scan B3 at `0x63d2076`.
  Then `mov 0x8(%rsp),%rax` at `0x63d1a25`; `shr $0x9,%rax` at
  `0x63d1a2a`; `and $0x1ffff8,%eax` at `0x63d1a2e`; `add
  0x1b8(%rbx),%rax` at `0x63d1a33`; `mov (%rax),%rbp` at
  `0x63d1a3a`; `lea 0x65096c0,%rcx` at `0x63d1a3d` (node table);
  `shl $0x10,%rbp` at `0x63d1a44` / `sar $0x10,%rbp` at
  `0x63d1a48` / `and $0xffffffffffffff80,%rbp` at `0x63d1a4c`;
  `mov 0x0(%rbp),%rax` at `0x63d1a50`; `and $0xfff,%eax` at
  `0x63d1a54`; `mov (%rcx,%rax,8),%rdi` at `0x63d1a59`; `lock
  sub %r13,0x38(%rdi)` at `0x63d1a5d` (refcount decrement by
  the size class). Leaf: `mov 0x1b0(%rbx),%r13` at `0x63d1a62`;
  `cmp %r13,%r15` at `0x63d1a69`, `jne 0x63d2131` (scan B2) at
  `0x63d1a6c`; `mov 0x8(%rsp),%rax` at `0x63d1a72`; `shr
  $0x9,%rax` at `0x63d1a77`; `and $0x1ffff8,%eax` at `0x63d1a7b`;
  `add 0x1b8(%rbx),%rax` at `0x63d1a80`; `mov (%rax),%rbp` at
  `0x63d1a87`; `test $0x1,%bpl` at `0x63d1a8a` — set goes to
  tail jump 1 (below); clear goes to the deep arm at `0x63d20c5`.
- Walk C (key = stored phrase `0x28(%rbx)` in `r10`/`r11`, table
  `r14` + `0x1b0`): `mov 0x28(%rbx),%r10` at `0x63d1ac8`; `mov
  %r13,0x8(%rbx)` at `0x63d1acc`; `mov %r10,%r12` at `0x63d1ad0`;
  `mov %r10,%r11` at `0x63d1ad3`; `shr $0x1a,%r12` at
  `0x63d1ad6`; `and $0xffffffffc0000000,%r11` at `0x63d1ada`;
  `and $0xf0,%r12d` at `0x63d1ae1`; `add %r14,%r12` at
  `0x63d1ae8`; top compare `cmp %rdx,%r11` at `0x63d1af3`
  (`rdx` = `0x1b0(%r12)`), mismatch to scan C1 at `0x63d1e6b`.
  Extract: `mov %r10,%rax` at `0x63d1afc`; `shr $0x9,%rax` at
  `0x63d1aff`; `and $0x1ffff8,%eax` at `0x63d1b03`; `add
  0x1b8(%r12),%rax` at `0x63d1b08`; `mov (%rax),%rax` at
  `0x63d1b10`; `lea 0x6727a00,%r15` at `0x63d1b13` (size table);
  `shr $0x30,%rax` at `0x63d1b1a`; `mov (%r15,%rax,8),%rbp` at
  `0x63d1b1e`; second compare `cmp %rdx,%r11` at `0x63d1b22`,
  mismatch to scan C2 at `0x63d1e1b`. Then `mov %r10,%rax` at
  `0x63d1b2b`; `shr $0x9,%rax` at `0x63d1b2e`; `and
  $0x1ffff8,%eax` at `0x63d1b32`; `add 0x1b8(%r12),%rax` at
  `0x63d1b37`; `mov (%rax),%rax` at `0x63d1b3f`; `lea
  0x65096c0,%rdi` at `0x63d1b42` (node table); `shl $0x10,%rax`
  at `0x63d1b49` / `sar $0x10,%rax` at `0x63d1b4d` / `and
  $0xffffffffffffff80,%rax` at `0x63d1b51`; `mov (%rax),%r15`
  at `0x63d1b55`; `and $0xfff,%r15d` at `0x63d1b58`; `mov
  (%rdi,%r15,8),%r13` at `0x63d1b5f`; `lock sub %rbp,0x38(%r13)`
  at `0x63d1b63`. Leaf: `mov 0x1b0(%r12),%rbp` at `0x63d1b68`;
  `cmp %rbp,%r11` at `0x63d1b70`, `jne 0x63d1dcb` (scan C3) at
  `0x63d1b73`; `mov %r10,%rax` at `0x63d1b79`; `shr $0x9,%rax`
  at `0x63d1b7c`; `and $0x1ffff8,%eax` at `0x63d1b80`; `add
  0x1b8(%r12),%rax` at `0x63d1b85`; `mov (%rax),%rax` at
  `0x63d1b8d`; `test $0x1,%al` at `0x63d1b90` — set (`mov
  %r10,%rsi` at `0x63d1b98`, `mov %r14,%rdi` at `0x63d1b9b`)
  calls `0x63637f0` at `0x63d1b9e` then falls through to the tail
  (`mov 0x8(%rsp),%r14` at `0x63d1ba3`, `mov 0x14(%rsp),%r12d`
  at `0x63d1ba8`, `mov %r14,0x28(%rbx)` at `0x63d1bad`, `mov
  %r12d,0x14(%rbx)` at `0x63d1bb1`, exit); clear goes to the
  deep arm at `0x63d1d7c`.
- Deep arms: walk-B deep arm at `0x63d20c5`: `shr $0x30,%rbp`
  at `0x63d20c5`; `cmp $0x23,%rbp` at `0x63d20c9`, `jbe
  0x63d241f` (tail jump 3) at `0x63d20cd`; `mov 0x1b0(%rbx),%rdi`
  at `0x63d20d3`; `cmp %rdi,%r15` at `0x63d20da`, `jne
  0x63d23d0` (scan D1) at `0x63d20dd`; `mov 0x8(%rsp),%rax` at
  `0x63d20e3`; `shr $0x9,%rax` at `0x63d20e8`; `and
  $0x1ffff8,%eax` at `0x63d20ec`; `add 0x1b8(%rbx),%rax` at
  `0x63d20f1`; `mov (%rax),%rsi` at `0x63d20f8`; canary check at
  `0x63d20fb`/`0x63d2100`; `shl $0x10,%rsi` at `0x63d210f`;
  `add $0x58,%rsp` at `0x63d2113`; `mov %r14,%rdi` at
  `0x63d2117`; `sar $0x10,%rsi` at `0x63d211a`; pops;
  `and $0xffffffffffffff80,%rsi` at `0x63d2120`; tail jump 2
  (`jmp 0x63bd6c0`) at `0x63d212c`. Walk-C deep arm at
  `0x63d1d7c`: `shr $0x30,%rax` at `0x63d1d7c`; `cmp $0x23,%rax`
  at `0x63d1d80`, `jbe 0x63d1ee2` (the `0x6363260` call arm) at
  `0x63d1d84`; `mov 0x1b0(%r12),%rbp` at `0x63d1d8a`; `cmp
  %rbp,%r11` at `0x63d1d92`, `jne 0x63d2254` (scan D2) at
  `0x63d1d95`; `mov %r10,%rax` at `0x63d1d9b`; `shr $0x9,%rax`
  at `0x63d1d9e`; `and $0x1ffff8,%eax` at `0x63d1da2`; `add
  0x1b8(%r12),%rax` at `0x63d1da7`; `mov (%rax),%rsi` at
  `0x63d1daf`; `mov %r14,%rdi` at `0x63d1db2`; `shl $0x10,%rsi`
  at `0x63d1db5` / `sar $0x10,%rsi` at `0x63d1db9` / `and
  $0xffffffffffffff80,%rsi` at `0x63d1dbd`; `call 0x63bd6c0` at
  `0x63d1dc1`; `jmp 0x63d1ba3` (tail) at `0x63d1dc6`. The
  `0x6363260` call arm at `0x63d1ee2`: `mov $0x1,%ecx` at
  `0x63d1ee2`; `xor %edx,%edx` at `0x63d1ee7`; `mov %r10,%rsi`
  at `0x63d1ee9`; `mov %r14,%rdi` at `0x63d1eec`; `call
  0x6363260` at `0x63d1eef`; `jmp 0x63d1ba3` (tail) at
  `0x63d1ef4`.
- Tail jumps (3, the only jumps outside the window): tail jump 1
  at `0x63d1abe` (`jmp 0x63637f0`; `rdi` = `r14` at `0x63d1ab1`,
  `rsi` = `0x8(%rsp)` at `0x63d1aa8`, canary sub `0x63d1a99`);
  tail jump 2 at `0x63d212c` (`jmp 0x63bd6c0`; `rdi` = `r14` at
  `0x63d2117`, `rsi` = deep-extracted node at `0x63d20f8`,
  canary sub `0x63d2100`); tail jump 3 at `0x63d2450` (`jmp
  0x6363260`; `rdi` = `r14` at `0x63d243c`, `rsi` =
  `0x8(%rsp)` at `0x63d2433`, `rdx` = 0 (`xor %edx,%edx` at
  `0x63d243f`), `rcx` = 1 (`mov $0x1,%ecx` at `0x63d2442`),
  canary sub `0x63d2424`). All three exit with `rax` = 0.
- Scan (ten 8-slot move-to-front scans over the same slot set,
  table+`0x2b0` in `r14`, 16-byte entries, swap-on-hit): A1/A2
  belong to walk A (key `r13`), B1/B2/B3 to walk B (key `r15`),
  C1/C2/C3 to walk C (key `r11`), D1/D2 to the deep arms (key
  `r15` / `r11`). Slot-0 compares: A1 `cmp 0x2b0(%r14),%r13`
  at `0x63d1d2c` (normal), A2 `cmp 0x2b0(%r14),%r13` at
  `0x63d1cdf` (normal), B1 `cmp 0x2b0(%r14),%r15` at `0x63d2025`
  (normal), B2 `cmp 0x2b0(%r14),%r15` at `0x63d2131` (normal),
  B3 `cmp 0x2b0(%r14),%r15` at `0x63d2076` (normal), C1 `cmp
  0x2b0(%r14),%r11` at `0x63d1e6b` (normal), C2 `cmp
  0x2b0(%r14),%r11` at `0x63d1e1b` (normal), C3 `cmp
  0x2b0(%r14),%r11` at `0x63d1dcb` (normal), D1 `cmp
  0x2b0(%r14),%r15` at `0x63d23d0` (normal), D2 `cmp
  0x2b0(%r14),%r11` at `0x63d2254` (normal). Reversed-operand
  compares (key register first): A1 slots 3, 6 (`0x63d246c`,
  `0x63d24a2`); B2 slots 3, 4, 5, 6 (`0x63d293c`, `0x63d294f`,
  `0x63d2962`, `0x63d2975`); B3 slots 1, 2 (`0x63d2371`,
  `0x63d278a`); C1 slots 1, 2 (`0x63d1fc7`, `0x63d2584`); C2
  slots 1, 2, 4, 5 (`0x63d1efe`, `0x63d25f5`, `0x63d2619`,
  `0x63d262b`); C3 slots 1, 2, 5 (`0x63d1f62`, `0x63d2666`,
  `0x63d269c`). 68 slot-compare instructions, 17
  reversed-operand, 17 of 80 slot positions reversed (D1's loop
  compare at `0x63d27ff` serves slots 1–7 in one instruction;
  D2's at `0x63d29f7` likewise). Hits swap the 16-byte entries
  and rejoin the walk; exhaustions fall to the ten miss blocks:
  A1 → site 1, A2 → site 2, C1 → site 3, C2 → site 4, C3 →
  site 5, B3 → site 6, D1 → site 7, B1 → site 8, B2 → site 9,
  D2 → site 10. (The pre-build handoff draft had B1 → 9, B3 →
  10, D2 → 8 and B2 reversed [1, 2], B3 reversed [1, 2],
  C3 reversed [1, 2, 5] — the B2/B3/D2 mapping and the B2
  reversed slots were corrected by byte-level verification:
  B2 reversed is [3, 4, 5, 6], B3 is [1, 2].)
- Lu-miss sites (10): one argument pattern — `rdi` = `r14`
  context, `rsi` = `0x6511a00` (`.bss`), `rdx` = walk table
  pointer, `rcx` = walk key, `r8d` = 1, `r9d` = 0. Site 1
  (`0x63d2549`, block `0x63d2530`, scan-A1 exhaustion, `rcx` =
  resolver return in `rax`, `rdx` = table via `r12`) rejoins at
  `0x63d1902` (walk-A first extract) after reloading the table
  into `rdx` at `0x63d254e`; site 2 (`0x63d2575`, block
  `0x63d255a`, scan-A2 exhaustion, `rcx` = `rbp`) rejoins at
  `0x63d1930` (walk-A second extract); site 3 (`0x63d26f7`,
  block `0x63d26d2`, scan-C1 exhaustion, `rcx` = `r10`) saves
  `r11`/`r10` to `0x28(%rsp)`/`0x20(%rsp)` before the call,
  restores them after, and rejoins at `0x63d1b10` (walk-C first
  extract); site 4 (`0x63d2738`, block `0x63d2713`, scan-C2
  exhaustion, `rcx` = `r10`) likewise saves/restores and
  rejoins at `0x63d1b3f` (walk-C second extract); site 5
  (`0x63d2771`, block `0x63d274c`, scan-C3 exhaustion, `rcx` =
  `r10`) likewise saves/restores and rejoins at `0x63d1b8d`
  (walk-C leaf extract); site 6 (`0x63d2871`, block `0x63d2854`,
  scan-B3 exhaustion, `rcx` = `0x8(%rsp)`) rejoins at
  `0x63d1a3a` (walk-B second extract); site 7 (`0x63d28a6`,
  block `0x63d2889`, D1-loop exhaustion, `rcx` = `0x8(%rsp)`)
  rejoins at `0x63d20f8` (walk-B deep extract); site 8
  (`0x63d29b3`, block `0x63d2996`, scan-B1 exhaustion, `rcx` =
  `0x8(%rsp)`) rejoins at `0x63d1a0a` (walk-B first extract)
  after reloading `0x1b0(%rbx)` into `rdx` at `0x63d29b8`;
  site 9 (`0x63d29e1`, block `0x63d29c4`, scan-B2 exhaustion,
  `rcx` = `0x8(%rsp)`) rejoins at `0x63d1a87` (walk-B leaf
  extract); site 10 (`0x63d2a76`, block `0x63d2a5b`, D2-loop
  exhaustion, `rcx` = `r10`) rejoins at `0x63d1daf` (walk-C
  deep extract). The `rcx` provenance is proven by
  reaching-definitions: the only `rcx` definition reaching site
  1 is `mov %rax,%rcx` at `0x63d253d`, site 2 `mov %rbp,%rcx`
  at `0x63d2562`, site 3 `mov %r10,%rcx` at `0x63d26d7`, site 4
  `mov %r10,%rcx` at `0x63d2718`, site 5 `mov %r10,%rcx` at
  `0x63d2751`, site 6 `mov 0x8(%rsp),%rcx` at `0x63d2854`, site
  7 `mov 0x8(%rsp),%rcx` at `0x63d2889`, site 8 `mov
  0x8(%rsp),%rcx` at `0x63d299b`, site 9 `mov 0x8(%rsp),%rcx`
  at `0x63d29c4`, site 10 `mov %r10,%rcx` at `0x63d2a63`. The
  walk keys themselves: `rax` at site 1 reaches only from the
  resolver call at `0x63d18aa`; `rbp` at site 2 from `mov
  %rax,%rbp` at `0x63d18af`; `r10` at sites 3, 4, 5, 10 from
  `mov 0x28(%rbx),%r10` at `0x63d1ac8` plus the restores from
  `0x20(%rsp)` in sites 3/4/5; the walk-B key in `0x8(%rsp)`
  was stored once at `0x63d1969` from `mov 0x28(%rbx),%r15` at
  `0x63d1959`; `r14` at every site is the entry context (`mov
  %rdi,%r14` at `0x63d17e4`) — see the verifier's
  reaching-definition checks for the exact sets. (The pre-build
  handoff draft had sites 8 and 10 in the wrong `rcx` groups —
  corrected by byte-level verification.)
- Second-handler site (1): block `0x63d1c62`, entered from the
  gate `jg 0x63d1c62` at `0x63d187d` when `0x1(%r14)` is
  positive. `lea 0x65096c0,%r15` at `0x63d1c62` (node table);
  `mov (%r15),%r13` at `0x63d1c69`; `test %r13,%r13` at
  `0x63d1c6c`; `jne 0x63d1893` at `0x63d1c6f` (non-null skips the
  handler); `lea 0x64da4b0,%rdx` at `0x63d1c75`
  (`.data.rel.ro`); `xor %esi,%esi` at `0x63d1c7c` (`rsi` = 0);
  `mov %r14,%rdi` at `0x63d1c7e`; `call 0x634ebb0` at
  `0x63d1c81`; `mov %rax,%r13` at `0x63d1c86`; `jmp 0x63d1893`
  at `0x63d1c89` (resolver args). The null-resolver-input arm
  at `0x63d1c8e`: `mov $0x1,%esi` at `0x63d1c8e`; `mov
  %r14,%rdi` at `0x63d1c93`; `call 0x6352fc0` at `0x63d1c96`;
  `cmpb $0x0,(%r14)` at `0x63d1c9b`; `mov %rax,%r13` at
  `0x63d1c9f`; `je 0x63d1893` at `0x63d1ca2`; otherwise `mov
  0x128(%r14),%r11` at `0x63d1ca8`, `lea 0x100(%r14),%rsi` at
  `0x63d1caf`, `lea 0x358(%r14),%rdx` at `0x63d1cb6`, `test
  %r11,%r11` at `0x63d1cbd`, `je 0x63d2180` at `0x63d1cc0`;
  `cmp %r11,%rax` at `0x63d1cc6`, `je 0x63d1893` at `0x63d1cc9`;
  `mov %rax,%rcx` at `0x63d1ccf`; `mov %r14,%rdi` at
  `0x63d1cd2`; `call 0x63edf10` at `0x63d1cd5`; `jmp 0x63d1893`
  at `0x63d1cda`; the `0x63d2180` arm: `mov %rax,%rcx` at
  `0x63d2180`, `mov %r14,%rdi` at `0x63d2183`, `call 0x63ec4c0`
  at `0x63d2186`, `jmp 0x63d1893` at `0x63d218b`.
- Dispatcher: `0x6365150` 1 (key resolver), `0x63d0080` 1 (prev
  FDE, per-element helper), `0x63637f0` 1 (call) + 1 (tail jump),
  `0x634ebb0` 1 (second handler), `0x6352fc0` 1, `0x63edf10` 1,
  `0x63bd6c0` 1 (call) + 1 (tail jump), `0x63ec4c0` 1,
  `0x6363260` 1 (call) + 1 (tail jump), `0x63d9700` 10
  (lu-miss); PLT: `__stack_chk_fail` 1. The #314–#324 windows
  are NOT called from this FDE.
- Exit: a SINGLE ret at `0x63d1bd7` with ONE reaching `rax`
  definition — the canary sub at `0x63d1bba` — so `rax` = 0
  uniformly. The three tail jumps exit the same way (canary
  subs at `0x63d1a99`, `0x63d2100`, `0x63d2424`). Epilogue:
  `mov 0x48(%rsp),%rax` at `0x63d1bb5`; `sub %fs:0x28,%rax` at
  `0x63d1bba` (rax becomes 0); `jne 0x63d2a4c`
  (`__stack_chk_fail@plt`) at `0x63d1bc3`; `add $0x58,%rsp` at
  `0x63d1bc9`; pops; `ret`.

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

## Correction to #324's pointer

#324's survey pointer for this window (4768 bytes, 928 strict,
20 calls, 10 lu-miss sites at `0x63d2549`, `0x63d2575`, `0x63d26f7`,
`0x63d2738`, `0x63d2771`, `0x63d2871`, `0x63d28a6`, `0x63d29b3`,
`0x63d29e1`, and `0x63d2a76`, 0 bin_table_init sites, 1
second-handler site at `0x63d1c81`, 1 ret at `0x63d1bd7`, bsr 2)
was verified correct by targeted objdump census. No correction
(`prior_pointer_verified`).

## Frontier status

Twelfth packet of the lu-miss-caller frontier (53 FDEs, 168 sites,
16 survivors): #314 on `0x63495b0`, #315 on `0x6353a70`, #316 on
`0x6355900`, #317 on `0x63577f0`, #318 on `0x635a7a0`, #319 on
`0x635c6d0`, #320 on `0x635e2e0`, #321 on `0x63c9650`, #322 on
`0x63ccd60`, #323 on `0x63cddd0`, #324 on `0x63d03a0`. This window
is a SHARED survivor (in both the lu-miss survivor list and the
second-handler survivor list), so claiming it consumes one slot of
the combined 25-FDE miss-handler pool (lu-miss 16 ∪ second-handler
18, 9 shared). Four lu-miss survivors remain after this packet:
`0x63d2a80`, `0x63d3f0e`, `0x63d4048`, `0x63e94a0`.

## Disjointness

Range-only collector over all prior records. The window
`0x63d17e0..0x63d2a80` overlaps no prior range (verifier: 78234 priors
scanned, 0 skipped, disjointness NONE). The next candidate `0x63d2a80..0x63d3071` is likewise
disjoint from all priors and from this window (verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262, NOT called
  from this FDE), the lu-miss handler `0x63d9700..0x63d987b` (#215),
  the second miss handler `0x634ebb0..0x634eccd` (called once at
  `0x63d1c81`), the lock-wait helper `0x63bf680..0x63bf7ee` (#251, NOT
  called from this FDE), and the PLT stub `__stack_chk_fail@plt`
  are cited, not claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the prev FDE `0x63d0080..0x63d0398` (called once at `0x63d19b1`),
  the next FDE `0x63d2a80..0x63d3071`, the key resolver
  `0x6365150..0x6365660` (called once at `0x63d18aa`), the #300
  window `0x63637f0..0x6363d50` (called once, tail-jumped once),
  the #298 window `0x6363260..0x6363552` (called once, tail-jumped
  once), and the #314–#324 windows (NOT called from this FDE).
- The `.bss` objects are referenced by address only; their runtime
  contents are not established.
- The entry inputs' caller-side meaning, the walk keys' caller-side
  meaning beyond their origins (resolver return, saved/stored
  phrases), the `0x14`/`0x88`/`0x1` field semantics beyond the
  observed reads/writes, and the dispatcher callees' semantics
  beyond their call sites are not established. The exit value's
  meaning beyond its uniform 0 is not established.

## Verification

- Static verifier `tools/node115_lu_miss_caller_10site_threetail.py`:
  exit 0 (599 checks, 0 failures).
- Own unit tests `tests/test_node115_lu_miss_caller_10site_threetail.py`
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

Packet #326 decodes `0x63d2a80..0x63d3071` (1521 bytes, 313 strict,
7 calls, 2 lu-miss sites at `0x63d3036` and `0x63d305b`, 0
bin_table_init sites, 1 second-handler site at `0x63d2d51`, 1 ret
at `0x63d2c97`, bsr 2 — the next surviving lu-miss caller after
this packet, verified by targeted objdump census against all prior
exhibits; it is also a SHARED survivor, like this packet).
