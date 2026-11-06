# RE-001: lu lu-miss 1-site single-walk extract caller

First packet of the lu-miss-caller frontier: FDE `0x63495b0..0x6349775`
(453 bytes, 100 strict lines) is a single-walk lookup-with-extract routine
with one lu-miss site and NO bin_table_init call, NO trylock, NO size class,
NO init guard, NO canary, NO endbr64. One context-table walk resolves a
second-level pointer, an inline `shl $0x10` / `sar $0x10` extract decodes
five fields from the node descriptor directly into the output struct, and a
single 8-slot move-to-front scan (zero reversed-operand compares) falls
through to the single lu-miss call on exhaustion. The routine returns the
output struct pointer in `rax` — NOT 0, unlike the bin_table_init caller
chain, where `eax` = 0 at `ret`.

## Window

- FDE `0x63495b0..0x6349775`, 453 bytes, 100 strict mnemonic lines.
- Previous FDE `0x6349560..0x63495a5` (gap 11 bytes, all `0xcc`).
- Next FDE `0x6349780..0x6349bd9` (padding 11 bytes, all `0xcc`).
- Frame: no `endbr64`, no `sub %rsp`, no canary; prologue is
  `mov %rcx,%rax`, `push %rbx`, `mov %rsi,%r10`, `mov %rdi,%rbx`;
  epilogue is `mov %rbx,%rax`, `pop %rbx`, `ret`.
- Entry: `rdi` = output struct (kept in `rbx`), `rsi` = context (kept in
  `r10`, passed as `rdi` to the lu-miss handler), `rdx` = table base,
  `rcx` = lookup key.
- Target: node #115 only, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  105,896,032 bytes. Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.

## Classification

**Walk (single, table in `rdx`).** Key = entry `rcx`
(`mov %rcx,%rax` at `0x63495b0`, `mov %rcx,%rsi` at `0x63495be`). Top
index `(key >> 0x1a) & 0xf0` (`shr $0x1a,%rax` at `0x63495ba`,
`and $0xf0,%eax` at `0x63495c1`, `add %rdx,%rax` at `0x63495cd`), high
bits `key & 0xffffffffc0000000` (`and` at `0x63495c6`), top-level
compare `cmp %rdi,%rsi` at `0x63495d3`; a mismatch falls to the scan at
`0x6349630`. Second level `(key >> 0x9) & 0x1ffff8 + table + 0x8`
(`shr $0x9,%rcx` at `0x63495d8`, `and $0x1ffff8,%ecx` at `0x63495dc`,
`add 0x8(%rax),%rcx` at `0x63495e2`). The second-level pointer is loaded
into `rsi` at `0x63495e9` — it is NOT stored to an output slot; it feeds
the extract.

**Extract (inline, from the second-level value in `rsi`).**
`mov %rsi,%rax` / `%rdx` / `%r10` / `%r11` at `0x63495ec`–`0x63495f5`,
then `shl $0x10,%rax` at `0x63495f8`, `sar $0x10,%rax` at `0x6349603`
(sign-extended 48-bit value), `and $0xffffffffffffff80,%rax` at
`0x6349611` (low 7 bits cleared). Five stores into the struct at `rbx`:
`mov %rax,(%rbx)` at `0x6349620` (the 48-bit value);
`mov %r11d,0x8(%rbx)` at `0x6349626` (descriptor `>> 0x30`,
`shr $0x30,%r11` at `0x6349615`);
`mov %edx,0xc(%rbx)` at `0x634961d` ((descriptor `>> 0x2`) `& 0x7`,
`shr $0x2,%rdx` at `0x63495fc`, `and $0x7,%edx` at `0x634960a`);
`mov %r10b,0x10(%rbx)` at `0x634962a` ((descriptor `>> 0x1`) `& 0x1`,
`shr $1,%r10` at `0x6349607`, `and $0x1,%r10d` at `0x6349619`);
`mov %sil,0x11(%rbx)` at `0x634960d` (descriptor `& 0x1`,
`and $0x1,%esi` at `0x6349600`). There is NO helper call, NO size class,
NO trylock: the extract decodes directly into the output struct and the
routine returns (`mov %rbx,%rax` at `0x6349623`, `pop %rbx`,
`ret` at `0x634962f`).

**Scan (single 8-slot move-to-front, table+`0x100` in `rdx`, key in
`rsi`).**

- Slot 0 at `0x6349630` (`cmp 0x100(%rdx),%rsi`), slot 1 at `0x6349676`,
  slot 2 at `0x63496e9`, slot 3 at `0x63496f8`, slot 4 at `0x634970b`,
  slot 5 at `0x634971e`, slot 6 at `0x6349731`, slot 7 at `0x634973e`
  (`cmp 0x170(%rdx),%rsi`) — all eight compares are memory-first, ZERO
  reversed-operand compares (unlike the bin_table_init caller chain,
  where reversed compares were common).
- Slot-index `mov`s set `r8d` = 1..7 before the slot 1..7 compares
  (`0x6349670`, `0x63496e3`, `0x63496f2`, `0x6349705`, `0x6349718`,
  `0x634972b`, `0x6349747`); the shared move-to-front block at `0x634967f`
  uses `r8d` as the slot index (`r9d` = index-1, shift `*16`, swap slot
  toward head). Slot-0 hits use the inline block at
  `0x6349639..0x6349667` (it swaps the top-level entry's second-level
  base with the scan slot's stored base and recomputes the second-level
  pointer from the swapped base). Both rejoin `jmp 0x63495e9` into the
  second-level deref. Exhaustion falls to lu-miss `0x6349758`.

**Lu-miss site (1).**

| site | rdi | rsi | rdx | rcx | rejoin |
| --- | --- | --- | --- | --- | --- |
| `0x634976b` | entry rsi | 0x6511a00 (.bss) | entry rdx | entry rcx (key) | jmp `0x63495e9` (rax -> extract) |

(`r8d` = 1, `r9d` = 0. Block `0x6349758`: `lea 0x6511a00(%rip),%rsi`,
`xor %r9d,%r9d`, `mov $0x1,%r8d`, `mov %r10,%rdi`, `call 0x63d9700`,
`jmp 0x63495e9`. Provenance, verified by the verifier's exact
miss-path write-set check over the 39 traced instructions from entry to
the call: `r10` is written only at entry (`mov %rsi,%r10` at
`0x63495b4`) — the extract-path writes (`0x63495f2`, `0x6349607`,
`0x6349619`) and the shared-MTF write (`0x63496b3`) are all on
non-miss paths; `rcx` and `rdx` are never written on the miss path, so
they still hold the entry key and table base (the `shr $0x9` /
`and $0x1ffff8` at `0x63495d8`/`0x63495dc` run only on the top-level-match
path); `r8d` is last written `$0x1` at `0x6349762`; `r9d` is zeroed at
`0x634975f`. Note the difference from the bin_table_init caller chain:
there `rdi` was the `rbp` context and `rcx` was set by an explicit
`mov` before the call; here `rdi` is entry `rsi` and `rcx` is the
untouched entry key.)

**Exit (1 ret, no tail jump).** The single `ret` is at `0x634962f`
(`mov %rbx,%rax` at `0x6349623` + `pop %rbx`). All 13 jump
instructions target inside the window. `rax` = `rbx` at exit (the
output struct pointer); the only `%eax` write in the window is the
top-index `and $0xf0,%eax` at `0x63495c1`. There is no `sete`, no
`mov $0x1,%eax`, no canary, and no null-flag epilogue — this routine
does not report null slots in `eax`. The observable effects are the
five output stores into `(%rbx)`.

**The referenced `.bss` object is not file data.** `0x6511a00`
(lu-miss `rsi`) lies inside `.bss` (`0x64ffe40..0x6728924`, NOBITS,
verified by own ELF parse, exact end asserted). Its contents are
runtime-populated and are not in the file; only the code's use of the
address is claimed.

## Census (from the objdump exhibit, never copied from a prior packet)

- Strict mnemonic lines: 100.
- Calls: 1 (lu-miss only — no bin_table_init, no helper, no PLT call).
- Lu-miss sites: 1 (`0x634976b`).
- Bin_table_init sites: 0.
- `ret`: 1 (`0x634962f`). Tail-jump exits: 0. `bsr`: 0. `lock sub`: 0.
  `lock add`: 0. Jumps: 13 (0 outside the window).
- Raw `0xe8` census (byte scan for `e8` with rel32 target `0x63d9700`,
  grouped by enclosing `.eh_frame` FDE, own parse of 135,313 FDEs
  sorted before bisect): total 168, tiers 1x18, 2x14, 3x1, 4x11, 5x1,
  6x2, 7x1, 8x1, 10x3, 13x1, across 53 FDEs. This FDE holds 1 raw site,
  matching its 1 objdump site. Raw `0xe8` with rel32 target `0x63d9880`
  (bin_table_init): 0 in this FDE.
- `.rela.dyn`: 60,723 total, 59,534 RELATIVE. `.rela.plt`: 278
  entries, counted separately (direct ELF parse; readelf `-W`
  cross-checked — non-wide output truncates the JUMP_SLOT type
  name and undercounts).

## Lu-miss-caller frontier survey — NEW

The bin_table_init caller survey is complete (108 sites, 42 FDEs,
0 survivors — packets #275–#313 claimed them all). This packet opens
the next frontier: callers of the lu-miss handler `0x63d9700` that do
NOT call bin_table_init. Method: own `.eh_frame` parse (135,313 FDEs)
+ raw-`0xe8` census + prior-exhibit overlap check over 68,124 prior
range entries at survey time (0 skipped; the verifier's fresh
collection scanned 68,962 priors, worktree copies included). Result: 168 lu-miss sites in 53 FDEs, **16
survivors**, first in address order `0x63495b0` (this packet):

| start | end | bytes | lu-miss sites | also 2nd-handler survivor |
| --- | --- | --- | --- | --- |
| `0x63495b0` | `0x6349775` | 453 | 1 | no |
| `0x6353a70` | `0x635582b` | 7611 | 1 | yes |
| `0x6355900` | `0x63577e2` | 7906 | 1 | yes |
| `0x63577f0` | `0x635a786` | 12182 | 1 | yes |
| `0x635a7a0` | `0x635c6c7` | 7975 | 4 | yes |
| `0x635c6d0` | `0x635de25` | 5973 | 7 | no |
| `0x635e2e0` | `0x635f315` | 4149 | 1 | yes |
| `0x63c9650` | `0x63c9c80` | 1584 | 2 | no |
| `0x63ccd60` | `0x63cd907` | 2983 | 6 | yes |
| `0x63cddd0` | `0x63ce23b` | 1131 | 2 | no |
| `0x63d03a0` | `0x63d17d7` | 5175 | 10 | yes |
| `0x63d17e0` | `0x63d2a80` | 4768 | 10 | yes |
| `0x63d2a80` | `0x63d3071` | 1521 | 2 | yes |
| `0x63d3f0e` | `0x63d4048` | 314 | 1 | no |
| `0x63d4048` | `0x63d4171` | 297 | 1 | no |
| `0x63e94a0` | `0x63e9bf2` | 1874 | 3 | no |

(Full per-candidate census in records.json under `survey`.)

**Combined miss-handler pool.** The second miss handler `0x634ebb0`
has 28 FDEs / 64 sites / 18 survivors; 9 FDEs are survivors in BOTH
lists (`0x6353a70`, `0x6355900`, `0x63577f0`, `0x635a7a0`,
`0x635e2e0`, `0x63ccd60`, `0x63d03a0`, `0x63d17e0`, `0x63d2a80`), so
the combined miss-handler pool is **25 distinct FDEs** — a shared FDE
is one packet, not two. The lock-wait helper `0x63bf680` caller
frontier (385 FDEs / 474 sites / 344 survivors) is held as the
follow-on frontier after the lu-miss pool.

## Disjointness

Range-only collector over the merged tree plus all prior
`hl-wt-calls*` worktree records (exhibits/windows only, all
range-bearing forms, decimal-integer start/end accepted, plain
`int(x, 16)` for hex strings). The window `0x63495b0..0x6349775`
overlaps no prior range (verifier: 68,962 priors scanned, 0 skipped,
disjointness NONE), including packet #313's window
`0x63c2f00..0x63c3328`, packet #312's window `0x63bc730..0x63bcb12`,
packet #215's handler FDE `0x63d9700..0x63d987b`, and packet #262's
bin_table_init window `0x63d9880..0x63d9a64`. The next candidate
`0x6353a70..0x635582b` is likewise disjoint from all priors
(verifier-checked).

## Not covered

- The lu-miss handler `0x63d9700..0x63d987b` (#215) and the
  bin_table_init body `0x63d9880..0x63d9a64` (#262) are cited, not
  claimed.
- The lock-wait helper `0x63bf680..0x63bf7ee` (#251) and the PLT stubs
  are cited, not claimed.
- The neighboring FDEs are not decoded here. The next FDE
  `0x6353a70..0x635582b` is the next question for packet #315.
- The entry `rsi` context's caller-side meaning, the `r8d`/`r9d`
  values' caller-side meaning, and the semantics of the five output
  fields beyond the store sites are not established. The `.bss`
  object at `0x6511a00` is referenced by address only; its runtime
  contents are not established.
- The remaining 15 lu-miss survivors are future packets
  (`0x6353a70` is next).

## Verification

- Static verifier `tools/node115_lu_miss_caller_1site.py`:
  exit 0 (134 checks, 0 failures).
- Own unit tests `tests/test_node115_lu_miss_caller_1site.py`
  (tamper controls first — hex flip, strict-count change, call-site
  change, injected overlap — each makes the temp-copy verifier fail;
  the clean temp copy passes): exit 0 (12 checks, 0 failures).
- `make verify`: exit 0 (559 evidence-packet manifests, 7159
  entries).
- `make catalogue-check`: exit 2 with the pre-existing `Stale
  catalogue: README.md` failure, also present on a pristine
  checkout; not a packet regression.
- Full `make test` is not run (584 files on the new base; hours of
  runtime and VM-restart risk). This deviation from the repository's
  stated gate is declared here rather than hidden.
- `.hex` exhibits are raw binary bytes, not hex text.

## Next question

Packet #315 decodes `0x6353a70..0x635582b` (7611 bytes, 1 lu-miss
site, 0 bin_table_init sites, 6 second-handler sites — the next
lu-miss survivor in address order after this packet, verified by
program against all prior exhibits; it is also a survivor of the
second miss handler `0x634ebb0`, so claiming it consumes it from the
combined 25-FDE miss-handler pool).
