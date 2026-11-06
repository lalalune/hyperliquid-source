# RE-001-node115-lu-miss-caller-2site-singlewalk: lu-miss caller with one walk, two miss sites, and a 0-or-1 exit

Thirteenth packet of the lu-miss-caller frontier (after #314 on `0x63495b0`,
#315 on `0x6353a70`, #316 on `0x6355900`, #317 on `0x63577f0`, #318 on
`0x635a7a0`, #319 on `0x635c6d0`, #320 on `0x635e2e0`, #321 on
`0x63c9650`, #322 on `0x63ccd60`, #323 on `0x63cddd0`, #324 on
`0x63d03a0`, and #325 on `0x63d17e0`). FDE `0x63d2a80..0x63d3071`
(1521 bytes, 313 strict lines) is a single-walk routine: the size
class is computed once at entry from the input count, a key-resolver
call feeds ONE context-table walk (walk A, `lock add`), TWO lu-miss
sites, and a single ret with two possible exit values. It opens with
`endbr64`, keeps the context base in `rbp`, the count holder in
`rbx`, and the resolver input `0x88(%rbp)` in `r13`. The entry
prologue first initializes the `rsi` struct (a 16-byte constant from
`0x454c10` written with `movups`, then the computed fields
`0x10`/`0x18`/`0x20`/`0x28`) and computes a power-of-two size `r8`
from the input count (a divide-by-3 step via `mul` by
`0xaaaaaaaaaaaaaaab`, then a `log2` loop at `0x63d2ae8`). The size
class then goes through the usual thresholds (`$0x3800` / `$0x1000`
/ `$0x4000`, byte table `0x67277c0`, size table `0x6727a00`,
`$0x3fff` cap, `0x6728140` fallback, `$0x4000` cap, two `bsr`
overflow arms), then `cmpb $0x0,0x1(%rbp)` gates the second-handler
path. Resolver `0x6365150` (`rdi` = `rbp`, `rsi` = `r13`, `rdx` =
size class, `rcx` = `$0x40`, `r8d` = 1, `r9d` = 0) returns the walk
key in `rax` (null → store 0 to `0x28(%rbx)` and exit 1). Walk A (key
= resolver return, `lock add`) has TWO 8-slot move-to-front scans
over one slot set (`0x2b0..0x320` in `rbp`): 16 slot-compare
instructions, SIX reversed-operand (A1 slots 1, 3, 5, 6; A2 slots 5,
6), i.e. 6 of 16 slot positions reversed; slot 0 and slot 1 are
checked directly, slots 2–7 are an unrolled chain, and hits swap the
16-byte entries and rejoin the walk. Both miss sites share one
argument pattern (`rdi` = `rbp` context, `rsi` = `.bss` `0x6511a00`,
`rdx` = walk table pointer, `rcx` = walk key, `r8d` = 1, `r9d` = 0),
with the `rcx` provenance proven by reaching-definitions: site 1
takes `r12` (the resolver return), site 2 takes `rax` (the resolver
return). Site 1's `rdx` is the walk table pointer from `lea
0x1b0(%rbp),%rdx` at `0x63d2bf0` (its only reaching definitions there
are that `lea` and site 2's stack restore at `0x63d3067`, which
reloads the same value); site 2's `rdx` is the same table pointer,
saved to `0x8(%rsp)` before the call and restored after. It exits by
a SINGLE ret with two reaching `rax` definitions — 0 (`xor
%eax,%eax` at `0x63d2c83`, success path) or 1 (`mov $0x1,%eax` at
`0x63d2d02`, size-class overflow / resolver-null paths) — so no
single exit value is established, like #324 (0 or 1), unlike #325
(uniform 0) and #323 (0 / 14 / 11). 0 `bin_table_init` sites, 1
second-handler site at `0x63d2d51`, 2 `bsr`, 0 tail-jump exits, 1
`lock add` and 0 `lock sub`, NO canary, NO TLS flag check. This
window is a SHARED survivor (in both the lu-miss survivor list and
the second-handler survivor list), so claiming it consumes one slot
of the combined 25-FDE miss-handler pool. It never calls the
lock-wait helper `0x63bf680` — the follow-on frontier's helper —
cited, not claimed. There is NO walk B or C, NO element loop, NO call
to the prev FDE `0x63d0080`, and NO deep-resolution tail
(`0x63bd6c0` / `0x63637f0` / `0x6363260`) — the first frontier window
with a single walk only, the first with `endbr64` present but NO
canary (after #321, which had neither), and the first with zero
`lock sub` instructions.

## Window

| Item | Value |
| --- | --- |
| FDE | `0x63d2a80..0x63d3071` |
| Bytes | 1521 |
| Strict lines | 313 |
| Calls | 7 (6 distinct direct targets, 0 indirect) |
| Bin_table_init sites | 0 |
| Lu-miss sites | 2 (`0x63d3036`, `0x63d305b`) |
| Second-handler sites | 1 (`0x63d2d51`) |
| Ret | 1 (`0x63d2c97`) |
| Tail-jump exits | 0 |
| Bsr | 2 (`0x63d2b54`, `0x63d2e4c`) |
| Lock sub / add | 0 / 1 |
| Jumps | 51 (0 outside) |
| Prev FDE | `0x63d17e0..0x63d2a80` (gap 0, directly adjacent) |
| Next FDE | `0x63d3080..0x63d379c` (padding 15, all `0xcc`) |

## Classification

- Entry: `endbr64` at `0x63d2a80`, then `push %r15` at `0x63d2a84`;
  pushes r14/r13/r12/rbp/rbx, `sub $0x18,%rsp`. `rdi` is the context
  base (kept in `rbp` at `0x63d2a90`); `rsi` is the struct holder
  (kept in `rbx` at `0x63d2aa4`); `rdx` is the input count (kept in
  `rax` at `0x63d2a86`); `rcx` is saved to `rdi` at `0x63d2a93`
  (later stored to `0x18(%rbx)`). NO canary (`%fs:0x28` appears
  nowhere, no `__stack_chk_fail` call). No TLS flag check
  (`%fs:0x330` appears nowhere).
- Struct init (entry prologue): `movdqa -0x5f7dea3(%rip),%xmm0` at
  `0x63d2aab` (16-byte constant from `0x454c10`), `movups
  %xmm0,(%rsi)` at `0x63d2ab3` writes it into the `rsi` struct.
  Count rounding: `mov %rdx,%rax` at `0x63d2a86`; `mul %rcx` at
  `0x63d2aa1` with `rcx` = `0xaaaaaaaaaaaaaaab` (divide by 3);
  `mov %rdx,%rsi` at `0x63d2ab6`, `and $0xfffffffffffffffe,%rdx`
  at `0x63d2ab9`, `shr $1,%rsi` at `0x63d2abd`, `lea
  0x3(%rsi,%rdx,1),%rax` at `0x63d2ac0`, second `mul %rcx` at
  `0x63d2ac5`, `shr $1,%rdx` at `0x63d2ac8`, `shl $0x2,%rdx` at
  `0x63d2acb`; `cmp $0x4,%rdx` at `0x63d2acf`, `jbe 0x63d2d10`
  (small-count path) at `0x63d2ad3`.
- Log2 loop (power-of-two size `r8`): `mov $0x2,%ecx` at
  `0x63d2ad9`, `mov $0x1,%r9d` at `0x63d2ade`; loop head
  `0x63d2ae8`: `mov %ecx,%r10d`, `mov %r9,%r11`, `add $0x1,%ecx`,
  `shl %cl,%r11`, `cmp %rdx,%r11`, `jb 0x63d2ae8` at `0x63d2af7`;
  `sub $0x1,%r10d` at `0x63d2af9`; `mov %r8,0x20(%rbx)` at
  `0x63d2afd`; `mov $0x10,%r8d` at `0x63d2b01`; `movd
  %r10d,%xmm1` at `0x63d2b07`; `shl %cl,%r8` at `0x63d2b0c`;
  `mov %rdi,0x18(%rbx)` at `0x63d2b0f`; `pshufd $0xe0,%xmm1,%xmm2`
  at `0x63d2b13`; `movq %xmm2,0x10(%rbx)` at `0x63d2b18`. Small-count
  path at `0x63d2d10`: `mov %r8,0x20(%rbx)`, `mov $0x8,%r8d`,
  `movq $0x0,0x10(%rbx)`, `mov %rdi,0x18(%rbx)`, `jmp 0x63d2cb9`
  (byte table).
- Size class: `cmp $0x3800,%r8` at `0x63d2b1d`, `jbe 0x63d2ca0`
  (round-up path) at `0x63d2b24`; `cmp $0x4000,%r8` at `0x63d2b2a`,
  `jbe 0x63d2cdd` (fallback) at `0x63d2b31`. Round-up path at
  `0x63d2ca0`: `add $0x3f` / `and $0xffffffffffffffc0`; `cmp
  $0x1000,%r8` at `0x63d2ca8`, `ja 0x63d2e47` (second `bsr` arm) at
  `0x63d2caf`; `shr $0x3,%r8` at `0x63d2cb5`; byte table `lea
  0x67277c0,%r9` at `0x63d2cb9`, `movzbl (%r9,%r8,1),%r11d` at
  `0x63d2cc0`; size table `lea 0x6727a00,%r8` at `0x63d2cc5`,
  `mov (%r8,%r11,8),%r12` at `0x63d2ccc`; `cmp $0x3fff,%r12` at
  `0x63d2cd0`, `jbe 0x63d2b90` at `0x63d2cd7`. Fallback at
  `0x63d2cdd`: `lea 0x6728140,%r13`, `mov $0x4000,%r12d`, `mov
  0x0(%r13),%r14`, `add $0x4000,%r14`; `cmp $0x3fff,%r14` at
  `0x63d2cf5`, `ja 0x63d2ba8` (gate) at `0x63d2cfc`. First `bsr` arm
  at `0x63d2b37`: `movabs $0x7000000000000000,%r12`; `cmp
  %r8,%r12` at `0x63d2b41`, `jb 0x63d2d02` (exit 1) at `0x63d2b44`;
  `lea -0x1(%r8,%r8,1),%r13` at `0x63d2b4a`; `mov $0x7,%edi` at
  `0x63d2b4f`; `bsr %r13,%r14` at `0x63d2b54`; `movslq
  %r14d,%r15` at `0x63d2b58`; `cmp %rdi,%r15` at `0x63d2b5b`,
  `cmovb %rdi,%r15` at `0x63d2b5e`; `lea -0x3(%r15),%rcx` at
  `0x63d2b62`; `shl %cl,%r9` at `0x63d2b66`; `lea
  -0x1(%r8,%r9,1),%r12` at `0x63d2b69`; `neg %r9` at `0x63d2b6e`;
  `and %r9,%r12` at `0x63d2b71`; `cmp %r8,%r12` at `0x63d2b74`,
  `jb 0x63d2d02` at `0x63d2b77`; `lea 0x6728140,%rsi` at
  `0x63d2b7d`; `mov %r12,%rax` at `0x63d2b84`; `add (%rsi),%rax`
  at `0x63d2b87`, `jb 0x63d2d02` at `0x63d2b8a`; `movabs
  $0x6fffffffffffffff,%rdi` at `0x63d2b90`; `lea -0x1(%r12),%r15`
  at `0x63d2b9a`; `cmp %r15,%rdi` at `0x63d2b9f`, `jb 0x63d2d02`
  at `0x63d2ba2`. Second `bsr` arm at `0x63d2e47`: `lea
  -0x1(%r8,%r8,1),%rdx` at `0x63d2e47`; `bsr %rdx,%r10` at
  `0x63d2e4c`; `lea -0x3(%r10),%ecx` at `0x63d2e50`; `shl
  %cl,%r9` at `0x63d2e54`; `lea -0x1(%r8,%r9,1),%r12` at
  `0x63d2e57`; `neg %r9` at `0x63d2e5c`; `and %r9,%r12` at
  `0x63d2e5f`; `jmp 0x63d2ba8` (gate) at `0x63d2e62`.
- Gate: `cmpb $0x0,0x1(%rbp)` at `0x63d2ba8`; `jg 0x63d2d32`
  (second-handler block) at `0x63d2bac`.
- Resolver input: `mov 0x88(%rbp),%r13` at `0x63d2bb2`; `test
  %r13,%r13` at `0x63d2bb9`; `je 0x63d2dad` (the `0x6352fc0`
  path) at `0x63d2bbc` on null.
- Resolver call: `mov %r12,%rdx` at `0x63d2bc2` (size class); `xor
  %r9d,%r9d` at `0x63d2bc5`; `mov $0x1,%r8d` at `0x63d2bc8`;
  `mov %r13,%rsi` at `0x63d2bce`; `mov $0x40,%ecx` at
  `0x63d2bd1`; `mov %rbp,%rdi` at `0x63d2bd6`; `call 0x6365150`
  at `0x63d2bd9`. Return: `mov %rax,%r12` at `0x63d2bde`
  (walk key); `test %rax,%rax` at `0x63d2be1`; `je 0x63d2d28`
  at `0x63d2be4` on null (`movq $0x0,0x28(%rbx)` at `0x63d2d28`,
  then exit 1); `mov %rax,%r13` at `0x63d2bea`; `mov %rax,%r15`
  at `0x63d2bed`.
- Walk A (key = resolver return, table `rbp` + `0x1b0`): `lea
  0x1b0(%rbp),%rdx` at `0x63d2bf0` (every lu-miss `rdx` is that
  table pointer); `shr $0x1a,%r13` at `0x63d2bf7`; `and
  $0xffffffffc0000000,%r15` at `0x63d2bfb`; `and $0xf0,%r13d`
  at `0x63d2c02`; `add %rbp,%r13` at `0x63d2c09`; `mov
  0x1b0(%r13),%r10` at `0x63d2c0c`; top compare `cmp %r10,%r15`
  at `0x63d2c13`, mismatch to scan A1 at `0x63d2d5e`.
  Extract: `shr $0x9,%rax` at `0x63d2c1c`; `and $0x1ffff8,%eax`
  at `0x63d2c20`; `add 0x1b8(%r13),%rax` at `0x63d2c25`; `mov
  (%rax),%rax` at `0x63d2c2c`; `lea 0x6727a00,%r9` at `0x63d2c2f`
  (size table); `shr $0x30,%rax` at `0x63d2c36`; `mov
  (%r9,%rax,8),%r14` at `0x63d2c3a` (size class); second compare
  `cmp %r10,%r15` at `0x63d2c3e`, mismatch to scan A2 at
  `0x63d2dfe`. Then `mov %r12,%rax` at `0x63d2c47`; `shr
  $0x9,%rax` at `0x63d2c4a`; `and $0x1ffff8,%eax` at `0x63d2c4e`;
  `add 0x1b8(%r13),%rax` at `0x63d2c53`; `mov (%rax),%r13` at
  `0x63d2c5a`; `lea 0x65096c0,%rax` at `0x63d2c5d` (node table);
  `shl $0x10,%r13` at `0x63d2c64` / `sar $0x10,%r13` at
  `0x63d2c68` / `and $0xffffffffffffff80,%r13` at `0x63d2c6c`;
  `mov 0x0(%r13),%rsi` at `0x63d2c70`; `and $0xfff,%esi` at
  `0x63d2c74`; `mov (%rax,%rsi,8),%r9` at `0x63d2c7a`; `lock add
  %r14,0x38(%r9)` at `0x63d2c7e` (refcount increment by the size
  class). Then `xor %eax,%eax` at `0x63d2c83` (exit 0); `mov
  %r12,0x28(%rbx)` at `0x63d2c85` (store the resolved key);
  epilogue at `0x63d2c89`; `ret` at `0x63d2c97`.
- Scan A1 (entered from the top-compare mismatch, key `r15`):
  slot 0 `cmp 0x2b0(%rbp),%r15` at `0x63d2d5e` (normal), miss to
  `0x63d2eda`; hit swaps the 16-byte entries (`mov
  %r10,0x2b0(%rbp)` at `0x63d2d6b`, etc.) and rejoins at the
  first extract (`jmp 0x63d2c2c` at `0x63d2da8`). Slot 1 `cmp
  %r15,0x2c0(%rbp)` at `0x63d2ee0` (REVERSED), miss to the
  unrolled chain at `0x63d2fac`; hit swaps via the index-based
  block at `0x63d2eed` (`mov %r9d,%ecx`, `r9d` = 1) and rejoins
  at the first extract via `0x63d2d87`. Unrolled chain at
  `0x63d2fac`: slot 2 `cmp 0x2d0(%rbp),%r15` at `0x63d2fb2`
  (normal), slot 3 `cmp %r15,0x2e0(%rbp)` at `0x63d2fc5`
  (REVERSED), slot 4 `cmp 0x2f0(%rbp),%r15` at `0x63d2fd8`
  (normal), slot 5 `cmp %r15,0x300(%rbp)` at `0x63d2feb`
  (REVERSED), slot 6 `cmp %r15,0x310(%rbp)` at `0x63d2ffe`
  (REVERSED), slot 7 `cmp 0x320(%rbp),%r15` at `0x63d300b`
  (normal); hits jump to the index-based swap at `0x63d2eed`
  with `r9d` = slot index; slot-7 miss falls to the miss-site-2
  block at `0x63d3040`. A1 reversed slots: 1, 3, 5, 6.
- Scan A2 (entered from the second-compare mismatch, key `r15`):
  slot 0 `cmp 0x2b0(%rbp),%r15` at `0x63d2dfe` (normal), miss to
  `0x63d2e77`; hit swaps the 16-byte entries and rejoins at the
  second extract (`jmp 0x63d2c5a` at `0x63d2e42`). Slot 1 `cmp
  0x2c0(%rbp),%r15` at `0x63d2e7c` (normal), miss to the
  unrolled chain at `0x63d2f3f`; hit swaps via the index-based
  block at `0x63d2e89` (`ecx` = 1) and rejoins at the second
  extract via `0x63d2e23`. Unrolled chain at `0x63d2f3f`: slot 2
  `cmp 0x2d0(%rbp),%r15` at `0x63d2f44` (normal), slot 3 `cmp
  0x2e0(%rbp),%r15` at `0x63d2f56` (normal), slot 4 `cmp
  0x2f0(%rbp),%r15` at `0x63d2f68` (normal), slot 5 `cmp
  %r15,0x300(%rbp)` at `0x63d2f7a` (REVERSED), slot 6 `cmp
  %r15,0x310(%rbp)` at `0x63d2f8c` (REVERSED), slot 7 `cmp
  0x320(%rbp),%r15` at `0x63d2f99` (normal); hits jump to the
  index-based swap at `0x63d2e89` with `ecx` = slot index;
  slot-7 miss falls to the miss-site-1 block at `0x63d3020`. A2
  reversed slots: 5, 6.
- Lu-miss sites (2): one argument pattern — `rdi` = `rbp`
  context, `rsi` = `0x6511a00` (`.bss`), `rdx` = walk table
  pointer, `rcx` = walk key, `r8d` = 1, `r9d` = 0. Site 1
  (`0x63d3036`, block `0x63d3020`, scan-A2 exhaustion, `rcx` =
  `r12`) rejoins at `0x63d2c5a` (walk-A second extract); site 2
  (`0x63d305b`, block `0x63d3040`, scan-A1 exhaustion, `rcx` =
  `rax`) rejoins at `0x63d2c2c` (walk-A first extract) after
  restoring the table pointer (`mov 0x8(%rsp),%rdx` at
  `0x63d3067`) and reloading the slot (`mov 0x1b0(%r13),%r10` at
  `0x63d3060`). Each block's `rdx` is the walk table pointer
  from `lea 0x1b0(%rbp),%rdx` at `0x63d2bf0`: site 1 takes it
  directly (its only reaching definitions are that `lea` and
  site 2's restore at `0x63d3067`, which reloads the same saved
  value); site 2 saves it to `0x8(%rsp)` before the call
  (`mov %rdx,0x8(%rsp)` at `0x63d3056`) and restores it after.
  The `rcx` provenance is proven by reaching-definitions: the
  only `rcx` definition reaching site 1 is `mov %r12,%rcx` at
  `0x63d302a`, site 2 `mov %rax,%rcx` at `0x63d304a`; `r12` at
  both sites is `mov %rax,%r12` at `0x63d2bde` (the resolver
  return), and `rax` at site 2 is the resolver call at
  `0x63d2bd9` itself (no `rax` write on the scan-A1 exhaustion
  path). The `rbp` at every site is the entry context (`mov
  %rdi,%rbp` at `0x63d2a90`).
- Second-handler site (1): block `0x63d2d32`, entered from the
  gate `jg 0x63d2d32` at `0x63d2bac` when `0x1(%rbp)` is
  positive. `lea 0x65096c0,%rsi` at `0x63d2d32` (node table);
  `mov (%rsi),%r13` at `0x63d2d39`; `test %r13,%r13` at
  `0x63d2d3c`; `jne 0x63d2bc2` at `0x63d2d3f` (non-null skips the
  handler); `lea 0x64da4b0,%rdx` at `0x63d2d45`
  (`.data.rel.ro`); `xor %esi,%esi` at `0x63d2d4c` (`rsi` = 0);
  `mov %rbp,%rdi` at `0x63d2d4e`; `call 0x634ebb0` at
  `0x63d2d51`; `mov %rax,%r13` at `0x63d2d56`; `jmp 0x63d2bc2`
  at `0x63d2d59` (resolver args).
- Null-resolver-input arm: block `0x63d2dad`, entered from `je
  0x63d2dad` at `0x63d2bbc` when `0x88(%rbp)` is null. `mov
  $0x1,%esi` at `0x63d2dad`; `mov %rbp,%rdi` at `0x63d2db2`;
  `call 0x6352fc0` at `0x63d2db5`; `cmpb $0x0,0x0(%rbp)` at
  `0x63d2dba`; `mov %rax,%r13` at `0x63d2dbe`; `je 0x63d2bc2` at
  `0x63d2dc1`; otherwise `mov 0x128(%rbp),%rax` at `0x63d2dc7`,
  `lea 0x100(%rbp),%rsi` at `0x63d2dce`, `lea 0x358(%rbp),%rdx`
  at `0x63d2dd5`, `test %rax,%rax` at `0x63d2ddc`, `je
  0x63d2e67` at `0x63d2ddf`; `cmp %rax,%r13` at `0x63d2de5`,
  `je 0x63d2bc2` at `0x63d2de8`; `mov %r13,%rcx` at `0x63d2dee`,
  `mov %rbp,%rdi` at `0x63d2df1`, `call 0x63edf10` at
  `0x63d2df4`, `jmp 0x63d2bc2` at `0x63d2df9`; the `0x63d2e67`
  arm: `mov %r13,%rcx` at `0x63d2e67`, `mov %rbp,%rdi` at
  `0x63d2e6a`, `call 0x63ec4c0` at `0x63d2e6d`, `jmp 0x63d2bc2`
  at `0x63d2e72`.
- Dispatcher: `0x6365150` 1 (key resolver), `0x634ebb0` 1 (second
  handler), `0x6352fc0` 1, `0x63edf10` 1, `0x63ec4c0` 1,
  `0x63d9700` 2 (lu-miss); PLT: none. The #314–#325 windows are
  NOT called from this FDE.
- Exit: a SINGLE ret at `0x63d2c97` with two reaching `rax`
  definitions — 0 (`xor %eax,%eax` at `0x63d2c83`, success path)
  or 1 (`mov $0x1,%eax` at `0x63d2d02`, size-class overflow /
  resolver-null paths) — so no single exit value is established.
  Epilogue: `add $0x18,%rsp` at `0x63d2c89`; pops; `ret`. The
  exit-1 block at `0x63d2d02` jumps to the shared epilogue.

## Census

- Raw `0xe8` census (own `.eh_frame` parse, 135,313 FDEs):
  lu-miss 168 sites / 53 FDEs (this FDE 2); bin_table_init 108 sites /
  42 FDEs (this FDE 0); second-handler 64 sites / 28 FDEs (this FDE
  1; the next candidate holds 0).
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278.
- `.bss` `0x64ffe40..0x6728924`; five referenced addresses inside
  (`0x65096c0`, `0x6511a00`, `0x67277c0`, `0x6727a00`,
  `0x6728140`). One `.data.rel.ro` address referenced
  (`0x64da4b0`).

## Correction to #325's pointer

#325's survey pointer for this window (1521 bytes, 313 strict,
7 calls, 2 lu-miss sites at `0x63d3036` and `0x63d305b`, 0
bin_table_init sites, 1 second-handler site at `0x63d2d51`, 1 ret
at `0x63d2c97`, bsr 2) was verified correct by targeted objdump
census. No correction (`prior_pointer_verified`).

## Frontier status

Thirteenth packet of the lu-miss-caller frontier (53 FDEs, 168 sites,
16 survivors): #314 on `0x63495b0`, #315 on `0x6353a70`, #316 on
`0x6355900`, #317 on `0x63577f0`, #318 on `0x635a7a0`, #319 on
`0x635c6d0`, #320 on `0x635e2e0`, #321 on `0x63c9650`, #322 on
`0x63ccd60`, #323 on `0x63cddd0`, #324 on `0x63d03a0`, #325 on
`0x63d17e0`. This window is a SHARED survivor (in both the lu-miss
survivor list and the second-handler survivor list), so claiming it
consumes one slot of the combined 25-FDE miss-handler pool
(lu-miss 16 ∪ second-handler 18, 9 shared). Three lu-miss survivors
remain after this packet: `0x63d3f0e`, `0x63d4048`, `0x63e94a0`.

## Disjointness

Range-only collector over all prior records. The window
`0x63d2a80..0x63d3071` overlaps no prior range (verifier: 79,077
priors scanned, 0 skipped, disjointness NONE). The next candidate
`0x63d3f0e..0x63d4048` is likewise disjoint from all priors and from
this window (verifier).

## Not covered

- The bin_table_init body `0x63d9880..0x63d9a64` (#262, NOT called
  from this FDE), the lu-miss handler `0x63d9700..0x63d987b` (#215),
  the second miss handler `0x634ebb0..0x634eccd` (called once at
  `0x63d2d51`), the lock-wait helper `0x63bf680..0x63bf7ee` (#251, NOT
  called from this FDE), and the prev FDE `0x63d17e0..0x63d2a80`
  (#325, NOT called from this FDE) are cited, not claimed.
- The dispatcher callees' bodies are cited, not claimed — including
  the next FDE `0x63d3080..0x63d379c`, the key resolver
  `0x6365150..0x6365660` (called once at `0x63d2bd9`), and the
  #314–#325 windows (NOT called from this FDE).
- The `.bss` objects are referenced by address only; their runtime
  contents are not established.
- The entry inputs' caller-side meaning, the count-rounding
  arithmetic's caller-side meaning beyond the observed operations,
  the `0x14`/`0x88`/`0x1` field semantics beyond the observed
  reads/writes, and the dispatcher callees' semantics beyond their
  call sites are not established. The exit values' meaning beyond
  their two distinct paths is not established.

## Verification

- Static verifier `tools/node115_lu_miss_caller_2site_singlewalk.py`:
  exit 0 (375 checks, 0 failures).
- Own unit tests `tests/test_node115_lu_miss_caller_2site_singlewalk.py`
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

Packet #327 decodes `0x63d3f0e..0x63d4048` (314 bytes, 75 strict,
1 call, 1 lu-miss site at `0x63d4003`, 0 bin_table_init sites, 0
second-handler sites, 1 ret at `0x63d4047`, bsr 0 — the next
surviving lu-miss caller after this packet, verified by targeted
objdump census against all prior exhibits; a lu-miss-ONLY survivor,
not shared, unlike this packet).
