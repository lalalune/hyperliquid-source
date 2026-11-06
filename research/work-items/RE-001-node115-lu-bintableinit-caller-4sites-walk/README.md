# RE-001: lu bin_table_init walk caller, 4 sites

Sixth bin_table_init caller FDE: the lookup walk at
0x63cb150..0x63cba04 (2228 bytes, 469 strict lines, 23 calls,
0 ret), carrying over from packet #279's next question and
packet #277's pointer. Unlike #275 (one stack temp, 10 sites),
#276 (one register, 8 sites), #277 (mixed args, 6 sites), and
#279 (five walk variants, 5 sites), this FDE runs a single
radix walk plus an 8-slot move-to-front scan, with four
null-context bin_table_init sites all using the same stack
temp 0x10(%rsp) and four lu-miss fallbacks. Unlike #278 (a dump
routine with no walk and no lu-miss sites), this FDE pairs the
walk with the scan. Unlike #275/#276/#277/#279, it has no
size-class block (no bsr anywhere in the FDE). All exits are
canary-checked tail-jumps; there is no ret. Static analysis
only; the target binary is never executed.

## The FDE

- Window: 0x63cb150..0x63cba04, 2228 bytes, 469 strict lines
  (address + bytes field + tab + mnemonic starting with a
  lowercase letter; byte-continuation lines excluded), 23
  calls, 0 ret.
- Frame 0x1a8, canary at 0x198(%rsp), canary checks at
  0x63cb3da, 0x63cb4b6 (shared epilogue), and 0x63cb61d, each
  jumping to the `__stack_chk_fail` call at 0x63cb839 on
  mismatch. Entry starts with push %r15 (no endbr64).
- Bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte
  range fields, not ULEB), not from endbr64 scanning. Previous
  FDE 0x63c9c80..0x63cb146 (packet #276's caller, cited not
  claimed), gap before 10 bytes (0xcc int3 padding). Next FDE
  0x63cba10..0x63ccd22 (packet #275's caller, cited not
  claimed), padding after 12 bytes (0xcc).
- Entry: rdi = context (kept in rbp), rsi = key struct (kept
  in rbx), r12 = (%rsi) node pointer, r13 = 0x60(%rsi). Entry
  helper 0x63d3a00 runs, then a mutex trylock sequence:
  pthread_mutex_trylock with a lock-wait fallback to helper
  0x63bf680 (packet #251's, cited not claimed), counter and
  owner bookkeeping, and a 0x84(%rbx) state word (1 takes the
  0x63cb2b8 helper path through 0x63c50e0, otherwise set to
  3). The `.bss` mutex/counter cluster 0x67145c8..0x6714608
  and the byte 0x6713601 are mechanism references only, not
  range claims; 0x67145e0 also appears in #277's mechanism
  description, which claims no bytes here.

## The walk (single shape, four null-context sites)

Top index: (key >> 0x1a) & 0xf0 into the table at context +
0x1b0; the stored high bits (key & 0xffffffffc0000000) are
compared against the entry. On match, the second level is
(key >> 0x9) & 0x1ffff8 added to the table's +0x8 slot,
yielding a node pointer. The node value is then resolved
through the 0x6727a00 table indexed by (value >> 0x30), and
the 0x65096c0-table refcount is decremented with a `lock
sub` on the entry indexed by (value & 0xfff) — the same tail
shape as #278's phase tails. On a top-level mismatch, the
walk inserts: it writes the new key and swaps the 0x100/0x108
fields of the table entry.

## bin_table_init: 4 sites, one arg shape, all rbp == 0 branches

Every site is reached from a `test %rbp,%rbp` followed by
`je`: bin_table_init initializes a fresh bin table whenever
the walk finds no context (rbp == 0). bin_table_init itself
(0x63d9880..0x63d9a64) was claimed by packet #262; only its
caller FDE is claimed here. All four sites use the same stack
temp, unlike #277/#278 (mixed shapes) and #276 (one register).

| site | block | branch | argument | rejoin |
| ---- | ----- | ------ | -------- | ------ |
| 0x63cb548 | 0x63cb540 | test rbp,rbp; je from 0x63cb3a9 | rdi = lea 0x10(%rsp) | 0x63cb54d |
| 0x63cb5ad | 0x63cb5a0 | test rbp,rbp; je from 0x63cb350 | rdi = lea 0x10(%rsp) | 0x63cb5b2 |
| 0x63cb610 | 0x63cb608 | test rbp,rbp; je from 0x63cb2ef | rdi = lea 0x10(%rsp) | 0x63cb615 |
| 0x63cb79f | 0x63cb797 | test rbp,rbp; je from 0x63cb490 | rdi = lea 0x10(%rsp) | 0x63cb7a4 |

Each site block is the target of exactly one `je` (verified).

## The 8-slot scan and the lu-miss fallbacks

Beside the radix walk, the FDE scans an 8-entry array at
context + 0x100 with 16-byte entries. Slot 0 (0x100) is the
most-recently-used head. Scans compare slots 1..7
(0x110..0x170); on a hit, the entry swaps into slot 0
(move-to-front). Three scans are unrolled (context registers
r10, r15, rsi); one is an indexed loop (base r12, index r10,
count rdx from 1 while rdx != 8). On exhaustion, each scan
calls the lu-miss handler (#215's FDE, cited not claimed)
with the same argument shape except for the table-base
register:

| lu-miss site | scan | argument (rdx varies) | rejoin |
| ------------ | ---- | --------------------- | ------ |
| 0x63cb82f | unrolled, base r10 | rdx = r10 | 0x63cb834 |
| 0x63cb8ca | unrolled, base r15 | rdx = r15 | 0x63cb8cf |
| 0x63cb95a | unrolled, base rsi | rdx = rsi | 0x63cb95f |
| 0x63cb9fa | indexed loop at 0x63cb969 | rdx = r12 | 0x63cb9ff |

All four lu-miss calls share: rdi = rbp (context),
rsi = lea 0x6511a00, rcx = rbx (key), r8 = 1, r9 = 0. The
rejoin points resume the radix walk's second level, so a miss
does not abort the walk.

## Exits (0 ret)

All exits are canary-checked tail-jumps, as in #276:

- Shared epilogue at 0x63cb4b6: canary check, pops, tail-jmp
  to walk helper 0x63bd6c0 (the previous FDE, cited not
  claimed).
- Second exit at 0x63cb3da: canary check, pops, tail-jmp to
  helper 0x63637f0 (cited not claimed).
- Third exit at 0x63cb61d: canary check, pops, tail-jmp to
  helper 0x6363260 (cited not claimed).
- A fourth tail-jump at 0x63cb238 goes to
  pthread_mutex_unlock@plt (a tail call, not an exit).

## Other callees (context only, not claims)

- 0x63d3a00 x1, 0x63d37a0 x1: entry helpers.
- 0x63f0b70 x5: pthread_mutex_unlock@plt.
- 0x63f17b0 x2: pthread_mutex_trylock@plt.
- 0x63c9c80 x1: packet #276's caller FDE (cited, not
  claimed).
- 0x63c50e0 x1: helper on the state-word == 1 path.
- 0x63bf680 x2: packet #251's lock-wait helper (cited, not
  claimed).
- 0x63c9500 x1: helper on the 0x10(%r13) == 0 path.
- 0x63f0d70 x1: `__stack_chk_fail`@plt.

## Prior pointer verified (no correction)

Packet #279's records named this FDE "0x63cb150..0x63cba04"
with 2228 bytes and 4 raw candidates. Both figures are
verified correct: 0x63cba04 - 0x63cb150 = 0x8b4 = 2228 bytes,
computed by program from the `.eh_frame` bounds (previous
FDE ends at 0x63cb146, next FDE starts at 0x63cba10), and the
objdump census finds exactly 4 bin_table_init sites. No #279
framing is corrected. Packet #277's pointer to this FDE is
likewise verified.

## Not covered

- The remaining 107 static leaves, unchanged by this packet.
- The callee FDEs' internals beyond their call-site argument
  patterns.
- Runtime values of the `.bss` addresses (mutex cluster,
  counters, gate byte, tables) — only the mechanism is
  reported.
- Whether the four walk paths correspond to four distinct
  callers or one caller inlined four times: observed control
  flow only, not proven.
- The next bin_table_init caller FDE 0x63c8d60..0x63c94fc
  (4 raw candidates, 1948 bytes, verified unclaimed): not
  decoded. Six other 4-raw FDEs also remain (0x6350210,
  0x6365660, 0x636bd90, 0x63d3080, 0x63d5940, 0x63ec900); the
  chain continues from 0x63c8d60.

## Verification

See EVIDENCE.md for the full gate record.
