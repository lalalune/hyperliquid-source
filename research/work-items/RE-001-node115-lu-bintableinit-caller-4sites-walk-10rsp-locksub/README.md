# RE-001: lu bin_table_init 10rsp locksub walk caller, 4 sites

Thirteenth bin_table_init caller FDE in the node-115 lookup chain: the lookup
walk at `0x63ec900..0x63ed06d` (1901 bytes, 407 strict lines, 17 calls,
0 ret), carrying over from packet #286's next question. Like #285 (plain rsp,
4 sites, 0 ret, 1 lock sub) and #286 (plain rsp, 4 sites, 0 ret, 1 lock sub,
key = entry rsi) and unlike #280 (one stack temp `0x10(%rsp)`, 4 sites, no
lock sub), #281 (plain rsp, 4 sites, 0 ret, no lock sub), #282 (plain rsp,
4 sites, 1 ret), #283 (one stack temp `lea 0x120(%rsp)`, 4 sites, 13 lu-miss
fallbacks), and #284 (one stack temp `lea 0x60(%rsp)`, 4 sites, 1 ret), this
FDE uses one stack temp `lea 0x10(%rsp)` at all four null-context
bin_table_init sites, pairs the walk with four lu-miss fallbacks, has no
size-class blocks (0 bsr), has no ret (the single exit is a canary-checked
tail-jump), and executes a `lock sub` refcount decrement during node
resolution. It differs from #285/#286 in the key's provenance: here the key
is the `+0xa0` field of the struct pointed to by the second argument's first
field (kept in rbx), while #285 read the key from the second argument's
`+0x28` field and #286 used the entry argument rsi itself. Static analysis
only; the target binary is never executed.

Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
(fetch-confirmed at build time). Target binary `artifacts/node/115/hl-node`,
105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Prior pointer verified (no correction)

Packet #286's records named this FDE `0x63ec900..0x63ed06d` with 1901 bytes
and 4 raw candidates. Both figures are verified correct:
`0x63ed06d - 0x63ec900 = 0x76d = 1901` bytes, computed by program from the
`.eh_frame` bounds (previous FDE ends exactly at `0x63ec900`, next FDE starts
at `0x63ed070`), and the objdump census finds exactly 4 bin_table_init
sites. No #286 framing is corrected. This packet exhausts the 4-raw caller
tier: after it, no 4-raw bin_table_init caller FDE remains unclaimed (see
Raw-e8 ranking below).

## The FDE

- Window: `0x63ec900..0x63ed06d`, 1901 bytes, 407 strict lines (address +
  bytes field + tab + mnemonic starting with a lowercase letter;
  byte-continuation lines excluded), 17 calls, 0 ret.
- Frame: `sub $0x1a8,%rsp`, canary at `0x198(%rsp)`, two canary checks (at
  `0x63ecab1` and `0x63ecb08`, each `sub %fs:0x28,%rax` followed by `jne` to
  the `__stack_chk_fail` call at `0x63ed03e`). Entry starts with pushes,
  not endbr64.
- Bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte range fields,
  not ULEB; CIE pointer relative to the CIE_id field, rec+4, not rec), not
  from endbr64 scanning. Previous FDE `0x63ec7a0..0x63ec900`, gap before
  0 bytes. Next FDE `0x63ed070..0x63ed089`, padding after 3 bytes (`0xcc`).
- Entry: rdi = context (kept in r12), rsi points to a struct whose first
  field is r15 (`mov (%rsi),%r15` at `0x63ec914`); `0x28(%r15)` is kept in
  r14, and the key is `0xa0(%r15)` (kept in rbx). The table pointer is
  `lea 0x1b0(%r12)`. The context is tested for null at every
  bin_table_init branch (all four test `%r12,%r12`).
- Exits: no ret. One tail-jump exit at `0x63ecadb` (full pop sequence via
  the shared epilogue at `0x63ecac2`, then `jmp 0x6360ed0`). The same
  callee `0x6360ed0` is also an ordinary call target at `0x63eca85`; the
  calls to `0x63637f0`, `0x63bd6c0` (packet #279's caller FDE), and
  `0x6363260` are ordinary returning calls, not exits — unlike #285/#286,
  where those three were tail-jump exits.
- Prologue loop at `0x63ec940`: calls helper `0x63ead50` with a counter in
  ebx against the `0x23` threshold and the count at `0x6728850`; the
  above-threshold path calls `0x63eb870`. The loop runs before the walk.
- Gate references (mechanism only): the `(value>>0x30)` vs `0x23` gate at
  `0x63ecc68` (shr `$0x30`, cmp `$0x23`, jbe `0x63ecd11`). No `.bss` gate
  byte of the `0x6713606` kind seen in #278/#279/#283/#284 is referenced
  in this FDE. Referenced tables `0x6727a00`, `0x65096c0`, `0x6511a00`
  are all .bss addresses; only the mechanism is reported, never runtime
  values.

## The walk (single shape, four null-context sites)

Top index: `(key >> 0x1a) & 0xf0` into the table at context + `0x1b0`; the
stored high bits (`key & 0xffffffffc0000000`) are compared against the
entry. On match, the second level is `(key >> 0x9) & 0x1ffff8` added to the
table's `+0x8` slot, yielding a node pointer. The node value is then
resolved through the `0x6727a00` table indexed by `(value >> 0x30)`. On a
top-level mismatch, the walk inserts: it writes the new key and swaps the
`0x100`/`0x108` fields of the table entry.

The second walk section differs from the first in its node resolution: it
reads the `0x65096c0` table by index (at `0x63eca0f..0x63eca2b`: shl/sar
`$0x10`, mask `$0xffffffffffffff80`, indexed read into r8) and then
executes `lock sub %r9,0x38(%r8)` at `0x63eca2f` — a refcount decrement
present here and in #285/#286 (there with `%r14` as the decremented
register), but absent from #283's and #284's walks.

Bin_table_init sites (all rdi = `lea 0x10(%rsp)`, each block the target of
exactly one `je` on a null-context test):

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x63ecb28` | `0x63ecb20` | test %r12,%r12; je from `0x63ec98c` | via r15 | jmp `0x63ec992` |
| `0x63ecb8d` | `0x63ecb80` | test %r12,%r12; je from `0x63ec9e6` | via r15 | fall-through `0x63ecb92` |
| `0x63ecc05` | `0x63ecbf8` | test %r12,%r12; je from `0x63eca3f` | via r9 | fall-through `0x63ecc0a` |
| `0x63ece23` | `0x63ece16` | test %r12,%r12; je from `0x63ecc81` | via r11 | jmp `0x63ecc87` |

## The scan (8 slots, four shapes)

The scan array sits at walk-table + `0x100`, 16-byte entries, slot 0 the
MRU head (never compared); slot-0 head entries are compared in each walk
variant (at `0x63ecb38` on rsi, `0x63ecbb0` on r15, `0x63ecc20` on r10,
`0x63ecdd6` on rdx) and slot-1 entries at `0x63eccc8` (rsi), `0x63ecd2d`
(r10), `0x63ecd7a` (r15). On a hit, the hit entry swaps into slot 0
(move-to-front).

- Unrolled scan at `0x63ece37..0x63ece8c`: slots 2..7 at `0x120..0x170` of
  the r10 table, exhaustion falls to lu-miss `0x63eceb9`.
- Unrolled scan at `0x63ecec8..0x63ecf1d`: slots 2..7 at `0x120..0x170` of
  the r15 table (slot 3 uses the reversed-operand form
  `cmp %r13,0x130(%r15)`), exhaustion falls to lu-miss `0x63ecf4e`.
- Unrolled scan at `0x63ecf62..0x63ecfb7`: slots 2..7 at `0x120..0x170` of
  the rsi table, exhaustion falls to lu-miss `0x63ecfe9`.
- Indexed loop at `0x63ecff8`: base rdx, index rsi from 1 while != 8,
  byte index rdi = index * 16, hit swaps into slot 0, exhaustion falls to
  lu-miss `0x63ed063`.

Lu-miss sites (all rdi = r12 context, rsi = `lea 0x6511a00`, rcx = rbx
key, r8 = 1, r9 = 0):

| site | rdx | rejoin |
| --- | --- | --- |
| `0x63eceb9` | r10 | jmp `0x63eca65` |
| `0x63ecf4e` | r15 | jmp `0x63eca0c` |
| `0x63ecfe9` | rsi (scan table pointer) | jmp `0x63ec9c9` |
| `0x63ed063` | rdx (scan table pointer) | jmp `0x63ecca7` |

## Size-class blocks

None: 0 bsr instructions in this FDE, like #280/#281/#282/#285/#286 and
unlike #275/#276/#277/#279/#283/#284.

## Raw-e8 ranking and the exhausted 4-raw tier

Raw 0xe8 census (byte scan of `.text` for e8 with rel32 target
`0x63d9880`, grouped by enclosing `.eh_frame` FDE from the readelf FDE
list of 135,313 FDEs; raw counts are an upper bound, site counts come from
objdump mnemonics; total 108, matching the established figure):
10 (#275), 8 (#276), 6 (#277), 6 (#278), 5 (#279), then 4-count FDEs:
`0x63cb150` (#280), `0x63c8d60` (#281), `0x636bd90` (#282),
`0x6350210` (#283), `0x6365660` (#284), `0x63d3080` (#285),
`0x63d5940` (#286), and this FDE `0x63ec900`. After this packet, the
4-raw tier is exhausted: no 4-raw bin_table_init caller FDE remains
unclaimed. There is no 3-raw tier at all (0 FDEs with exactly 3 raw
sites). The next tier is 2-raw with 12 FDEs; the 1-raw tier has 17 FDEs.

## Cited, not claimed

- bin_table_init body `0x63d9880..0x63d9a64` (packet #262).
- lu-miss handler `0x63d9700..0x63d987b` (packet #215).
- Previous FDE `0x63ec7a0..0x63ec900`, next FDE `0x63ed070..0x63ed089`.
- Tail-jump target `0x6360ed0` and ordinary call targets `0x63637f0`,
  `0x63bd6c0` (packet #279), `0x6363260`, `0x6364400` (getter family,
  context only — its internals are not decoded here).
- Prologue loop callees `0x63ead50`, `0x63eb870`.
- Other call targets (context only).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_10rsp_locksub_4sites.py`
  (byte reads only; never executes the binary): exit 0, checks including
  binary size + SHA-256, `.eh_frame` bounds, gap/padding int3 bytes,
  exhibit bytes, strict recount (407), call census (17 total /
  4 bin_table_init / 4 lu-miss / 0 ret), bsr count (0), lock-sub presence
  (1, at `0x63eca2f`), branch shapes at all 4 sites, canary checks,
  records consistency, `.rela.dyn` census (60,723 entries total, 59,534
  RELATIVE, stated distinctly; `.rela.plt` 278 entries counted
  separately), disjointness, slug check, raw-e8 census and ranking, and
  MANIFEST digests.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_10rsp_locksub_4sites.py`:
  exit 0. Tamper controls first (hex flip, strict-count change, call-site
  change, injected overlap — each confirmed to fail the verifier; clean
  temp copy confirmed to pass), plus regeneration comparisons and
  independent strict/census recounts.
- `make verify`: exit 0 (559 evidence-packet manifests, 7161 entries =
  base 7154 + this packet's 7 MANIFEST entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base — not a packet regression, and not claimed
  as passing.
- Full `make test` is NOT attempted: 584 test files on the new base take
  hours and risk a VM-restart kill mid-run; no full-suite tally is
  claimed.
- MANIFEST.sha256: all 7 entries verified with `sha256sum -c`.
- The `.hex` exhibit contains raw binary bytes, not hex text.

## Disjointness

The verifier's range-only collector scans the merged tree plus prior
worktree records and gathers string range fields, [start, end] lists, and
start/end pairs inside exhibits/windows lists or dicts or a dict literally
named "window". It never collects enclosing-fde annotation fields,
census/cited-only metadata subtrees, next-caller pointers, scan
descriptors, or control-flow edges. Self-exclusion is by exact window
equality, never by slug, so an injected overlapping range still fails the
verifier. Disjointness: NONE over prior ranges, 0 overlaps, including
packet #275's caller FDE `0x63cba10..0x63ccd22`, packet #276's caller FDE
`0x63c9c80..0x63cb146`, packet #277's caller FDE `0x63ce8c0..0x63cf8bc`,
packet #278's caller FDE `0x63d4bbe..0x63d5428`, packet #279's caller FDE
`0x63bd8c0..0x63be4ce`, packet #280's caller FDE `0x63cb150..0x63cba04`,
packet #281's caller FDE `0x63c8d60..0x63c94fc`, packet #282's caller FDE
`0x636bd90..0x636c49c`, packet #283's caller FDE `0x6350210..0x6352f5e`,
packet #284's caller FDE `0x6365660..0x63673d9`, packet #285's caller FDE
`0x63d3080..0x63d379c`, packet #286's caller FDE `0x63d5940..0x63d605c`,
packet #215's handler FDE `0x63d9700..0x63d987b`, and packet #262's
bin_table_init window `0x63d9880..0x63d9a64`. The slug
`RE-001-node115-lu-bintableinit-caller-4sites-walk-10rsp-locksub` does not
collide with any merged-tree directory.

## Not covered

- The 2-raw and 1-raw caller tiers (see next question).
- The static leaves and named-only callee families outside this window
  (including the getter family `0x6364400`, called here but not decoded).
- Runtime values of any `.bss` byte (mechanism only, never values).
- Per-scan mapping of all four lu-miss sites to distinct walk variants
  beyond the arguments and rejoins listed above.
- Packet #286's framings are NOT corrected or re-claimed here; its
  1901-byte pointer for this FDE is verified correct as described above.

## Next question

The 4-raw tier is exhausted. Packet #288's scout must survey the 2-raw
tier (12 FDEs — there is no 3-raw tier): `0x6349780..0x6349bd9`,
`0x6361320..0x63620da`, `0x636b940..0x636bd90`, `0x63c89c0..0x63c8d5a`,
`0x63cd910..0x63cddce`, `0x63d4171..0x63d4289`, `0x63d4289..0x63d4425`,
`0x63d4497..0x63d463e`, `0x63d61a0..0x63d6575`, `0x63ed090..0x63ed862`,
`0x63ed8b0..0x63edf05`, `0x63ef8e0..0x63efba2` — verifying each
candidate's objdump site count (raw is an upper bound) and claim status
against prior exhibits before building. No next window is claimed here.
