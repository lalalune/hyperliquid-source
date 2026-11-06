# RE-001-node115-lu-bintableinit-caller-4sites-walk-60rsp

Tenth bin_table_init caller FDE in the node-115 lookup chain: the lookup
walk at `0x6365660..0x63673d9` (7545 bytes, 1607 strict lines, 66 calls,
1 ret), carrying over from packet #283's next question. Unlike #280 (one
stack temp `0x10(%rsp)`, 4 sites), #281 (plain rsp, 4 sites, 0 ret), #282
(plain rsp, 4 sites, 1 ret), and #283 (one stack temp `lea 0x120(%rsp)`,
4 sites, 13 lu-miss fallbacks), this FDE uses one stack temp
`lea 0x60(%rsp)` at all four null-context bin_table_init sites, pairs the
walk with four lu-miss fallbacks, and contains size-class blocks
(10 bsr instructions). The context pointer is the entry argument rdi,
saved to `(%rsp)` and reloaded at each walk entry. Static analysis only;
the target binary is never executed.

Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
(fetch-confirmed at build time). Target binary
`artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Prior pointer verified (no correction)

Packet #283's records named this FDE `0x6365660..0x63673d9` with 7545
bytes and 4 raw candidates. Both figures are verified correct:
`0x63673d9 - 0x6365660 = 0x1d79 = 7545` bytes, computed by program from
the `.eh_frame` bounds (previous FDE ends exactly at `0x6365660`, next
FDE starts at `0x63673e0`), and the objdump census finds exactly 4
bin_table_init sites. No #283 framing is corrected. #283 cited this FDE
(called 4x from within #283's own window, confirmed by counting
`call 6365660` lines in #283's objdump exhibit) without claiming it, so
claiming its own window here is not a duplication; that distinction is
stated explicitly.

## The FDE

- Window: `0x6365660..0x63673d9`, 7545 bytes, 1607 strict lines
  (address + bytes field + tab + mnemonic starting with a lowercase
  letter; byte-continuation lines excluded), 66 calls, 1 ret at
  `0x63658e6` (shared epilogue; return value is r13).
- Frame: `sub $0x1f8,%rsp`, canary at `0x1e8(%rsp)`, canary checks at
  `0x63658c3` (shared epilogue) and `0x63659ec`, both jumping to the
  `__stack_chk_fail` call at `0x6366d8d` on mismatch. Entry starts with
  `endbr64`.
- Bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte range fields,
  not ULEB; CIE pointer relative to the CIE_id field, rec+4, not rec),
  not from endbr64 scanning. Previous FDE `0x6365150..0x6365660`, gap
  before 0 bytes. Next FDE `0x63673e0..0x6367447`, padding after 7 bytes
  (`0xcc`).
- Entry: rdi = context (saved to `(%rsp)`, reloaded as r14/r12/r9 at the
  four walk entries), rsi saved to `0x20(%rsp)`, rdx = key (kept in rbp),
  rcx kept in r12, r9 kept in r13; stack arguments read from
  `0x230/0x238/0x240(%rsp)`.
- Gate references (mechanism only): byte `0x6713606` checked at
  `0x6365822` (cmpb $0x0, je `0x6365a90`) and at `0x6365cbf` (cmpb $0x0,
  jne `0x6366000`) — the same byte gated #278's, #279's, and #283's
  entries. No runtime values are claimed.
- Exits: the ret at `0x63658e6`, plus one tail-jump exit at `0x6365a39`
  (full pop sequence, then jmp to `0x63bd8c0`, packet #279's caller FDE,
  cited not claimed). No other jump leaves the window.

## The walk (single shape, four null-context sites)

Top index: `(key >> 0x1a) & 0xf0` into the table at context + `0x1b0`;
the stored high bits (`key & 0xffffffffc0000000`) are compared against
the entry. On match, the second level is `(key >> 0x9) & 0x1ffff8` added
to the table's `+0x8` slot, yielding a node pointer. The node value is
then resolved through the `0x6727a00` table indexed by
`(value >> 0x30)`, and the `0x65096c0` table is read by index only (mov;
no `lock sub` refcount decrement is observed anywhere in this FDE).
Insert path: on top-level mismatch, writes the new key and swaps the
`0x100/0x108` fields of the table entry. The `(value >> 0x30)` vs
`0x23` gate appears at `0x6366060` (jbe) and `0x6366192`
(cmp $0x23, ja).

Bin_table_init sites (all rdi = `lea 0x60(%rsp)`, each block the target
of exactly one `je` on a null-context test, each followed by a jmp
rejoin, not fall-through):

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x63661c0` | `0x63661b8` | test %r14,%r14; je from `0x6365839` | via rbx | `0x636583f` |
| `0x63665e9` | `0x63665e1` | test %r12,%r12; je from `0x636600f` | via r15 | `0x6366015` |
| `0x63666c3` | `0x63666bb` | test %r12,%r12; je from `0x63660e7` | via r15 | `0x63660ed` |
| `0x6366dde` | `0x6366dd3` | test %r9,%r9; je from `0x6366078` | via r14 (also mov %r14,%rbx) | `0x636607e` |

## The scan (8 slots, four shapes)

The scan array sits at walk-table + `0x100`, 16-byte entries, slot 0
the MRU head (never compared); slots 1..7 are compared, and a hit swaps
the hit entry into slot 0.

- Unrolled scan at `0x6366ee7..0x6366f47`: slots 2..7 at
  `0x120..0x170` compared against rcx, hit path `0x63666e0`,
  exhaustion falls to lu-miss `0x6366f6e`.
- Indexed loop at `0x6366e83`: base r15, index r8 from 1 while != 8,
  hit swaps into slot 0, exhaustion falls to lu-miss `0x636731f`.
- Indexed loop at `0x6366e06`: base r15, index r8 from 1 while != 8,
  hit swaps into slot 0, exhaustion falls to lu-miss `0x636739d`.
- Indexed loop at `0x63672ac`: base rbx, index r11 from 1 while != 8,
  hit swaps into slot 0, exhaustion falls to lu-miss `0x63673cf`.

Lu-miss sites (all rdi = `(%rsp)` context, rsi = `lea 0x6511a00`,
rcx = rbp key, r8 = 1, r9 = 0):

| site | rdx | rejoin |
| --- | --- | --- |
| `0x6366f6e` | rbx | `0x6365878` |
| `0x636731f` | r15 | `0x63660b8` |
| `0x636739d` | r15 | `0x636604f` |
| `0x63673cf` | rbx | `0x63660b8` |

## Size-class blocks

10 bsr instructions (example at `0x6365985`: bsr of `(2*size - 1)`,
clamp to 7, sub 3, shift; thresholds `0x7000000000000000` and `0x4000`
nearby; threshold-byte table `0x67277c0`). Unlike #280/#281/#282, which
had no bsr, and like #283 (14 bsr), this FDE restores the size-class
shape.

## Raw-e8 ranking and remaining candidates

Raw 0xe8 census (byte scan grouped by enclosing `.eh_frame` FDE; raw
counts are an upper bound, site counts come from objdump mnemonics):
10 (#275), 8 (#276), 6 (#277), 6 (#278), 5 (#279), then 4-count FDEs:
`0x63cb150` (#280), `0x63c8d60` (#281), `0x636bd90` (#282),
`0x6350210` (#283), and this FDE `0x6365660`. After this packet, exactly
three 4-raw FDEs remain unclaimed: `0x63d3080..0x63d379c` (1820 bytes),
`0x63d5940..0x63d605c` (1820 bytes), `0x63ec900..0x63ed06d` (1901 bytes).

## Cited, not claimed

- bin_table_init body `0x63d9880..0x63d9a64` (packet #262).
- lu-miss handler `0x63d9700..0x63d987b` (packet #215).
- Previous FDE `0x6365150..0x6365660`, next FDE `0x63673e0..0x6367447`.
- Caller FDE `0x63bd8c0..0x63be4ce` (packet #279, tail-jump target).
- Other call targets (context only).

## Verification

- `tools/node115_lu_bintableinit_caller_walk_60rsp_4sites.py`: exit 0
  (binary size/SHA-256, `.eh_frame` bounds, gap/padding, exhibit bytes,
  strict/call/bsr/ret census, site branch shapes, canary checks,
  no-lock-sub, `.rela.dyn` 60,723 total / 59,534 RELATIVE and
  `.rela.plt` 278, records consistency, disjointness over prior
  records, slug uniqueness, raw-e8 ranking, MANIFEST digests).
- `tests/test_node115_lu_bintableinit_caller_walk_60rsp_4sites.py`:
  tamper controls first (hex flip, strict-count change, call-site
  change, injected overlap — all must fail), then clean temp copy,
  regeneration, and independent recounts.
- `make verify`: exit 0. `make catalogue-check`: fails pre-existing on
  this base with "Stale catalogue: README.md" (also on a pristine
  checkout); not a packet regression.
- Disjointness: NONE over prior records (range-only collector; census
  and cited-only subtrees excluded; self excluded by exact window
  equality).
- `.hex` exhibits are raw binary bytes, not hex text.

## Not covered

- The remaining three 4-raw caller FDEs (see above).
- The static leaves and named-only callee families outside this window.
- Runtime values of any `.bss` byte (mechanism only, never values).

## Next question

Packet #285 decodes `0x63d3080..0x63d379c` (1820 bytes, 4 raw
candidates), the first remaining 4-raw caller FDE in the order #283's
pointer listed them.
