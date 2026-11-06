# RE-001: lu bin_table_init rsp locksub walk caller, 4 sites

Eleventh bin_table_init caller FDE in the node-115 lookup chain: the lookup
walk at `0x63d3080..0x63d379c` (1820 bytes, 379 strict lines, 9 calls,
0 ret), carrying over from packet #284's next question. Unlike #280 (one
stack temp `0x10(%rsp)`, 4 sites), #281 (plain rsp, 4 sites, 0 ret),
#282 (plain rsp, 4 sites, 1 ret), #283 (one stack temp `lea 0x120(%rsp)`,
4 sites, 13 lu-miss fallbacks), and #284 (one stack temp `lea 0x60(%rsp)`,
4 sites, 1 ret), this FDE uses plain rsp at all four null-context
bin_table_init sites, pairs the walk with four lu-miss fallbacks, has no
size-class blocks (0 bsr), has no ret (all exits are canary-checked
tail-jumps), and — unlike #283/#284 — its walk-B node resolution executes
a `lock sub` refcount decrement. The context pointer is the entry argument
rdi (kept in rbx); the key is read from the second argument's `+0x28`
field into rbp. Static analysis only; the target binary is never executed.

Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
(fetch-confirmed at build time). Target binary
`artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Prior pointer verified (no correction)

Packet #284's records named this FDE `0x63d3080..0x63d379c` with 1820
bytes and 4 raw candidates. Both figures are verified correct:
`0x63d379c - 0x63d3080 = 0x71c = 1820` bytes, computed by program from
the `.eh_frame` bounds (previous FDE ends at `0x63d3071`, next FDE starts
at `0x63d37a0`), and the objdump census finds exactly 4 bin_table_init
sites. No #284 framing is corrected.

## The FDE

- Window: `0x63d3080..0x63d379c`, 1820 bytes, 379 strict lines
  (address + bytes field + tab + mnemonic starting with a lowercase
  letter; byte-continuation lines excluded), 9 calls, 0 ret.
- Frame: `sub $0x198,%rsp`, canary at `0x188(%rsp)`, three canary checks
  (at `0x63d31ad`, `0x63d334f`, `0x63d3391`, each `sub %fs:0x28,%rax`
  followed by `jne` to the `__stack_chk_fail` call at `0x63d376a`).
  Entry starts with `endbr64`.
- Bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte range fields,
  not ULEB; CIE pointer relative to the CIE_id field, rec+4, not rec),
  not from endbr64 scanning. Previous FDE `0x63d2a80..0x63d3071`, gap
  before 15 bytes (`0xcc`). Next FDE `0x63d37a0..0x63d37a9`, padding
  after 4 bytes (`0xcc`).
- Entry: rdi = context (kept in rbx), rsi's `+0x28` field = key (kept in
  rbp), rsi becomes the table pointer `lea 0x1b0(%rdi)`. The context is
  tested for null at every bin_table_init branch except site 1, which
  branches on the entry rdi itself.
- Exits: no ret. Three tail-jump exits, each after a canary-checked
  full pop sequence: `jmp 0x63637f0` (at `0x63d31ca`), `jmp 0x63bd6c0`
  (packet #279's caller FDE, at `0x63d3375`), `jmp 0x6363260` (at
  `0x63d33b5`). No other jump leaves the window.
- Referenced tables `0x6727a00`, `0x65096c0`, `0x6511a00` are all .bss
  addresses; only the mechanism is reported, never runtime values. No
  `.bss` gate byte of the `0x6713606` kind seen in #278/#279/#283/#284
  is referenced in this FDE.

## The walk (single shape, four null-context sites)

Top index: `(key >> 0x1a) & 0xf0` into the table at context + `0x1b0`;
the stored high bits (`key & 0xffffffffc0000000`) are compared against
the entry. On match, the second level is `(key >> 0x9) & 0x1ffff8` added
to the table's `+0x8` slot, yielding a node pointer. The node value is
then resolved through the `0x6727a00` table indexed by
`(value >> 0x30)`. The `(value >> 0x30)` vs `0x23` gate appears at
`0x63d3300..0x63d3308` (cmp `$0x23`, jbe `0x63d3380`). On a top-level
mismatch, the walk inserts: it writes the new key and swaps the
`0x100`/`0x108` fields of the table entry.

Walk B differs from walk A in its node resolution: it reads the
`0x65096c0` table by index (at `0x63d313c..0x63d3158`) and then executes
`lock sub %r14,0x38(%r8)` at `0x63d315c` — a refcount decrement present
here but absent from #283's and #284's walks.

Bin_table_init sites (all rdi = plain rsp, each block the target of
exactly one `je` on a null-context test):

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x63d31d6` | `0x63d31d0` | test %rdi,%rdi; je from `0x63d30b9` | via r12 | jmp `0x63d30bf` |
| `0x63d3236` | `0x63d3230` | test %rbx,%rbx; je from `0x63d3113` | via r15 | fall-through `0x63d323b` |
| `0x63d329e` | `0x63d3298` | test %rbx,%rbx; je from `0x63d316b` | via r14 | fall-through `0x63d32a3` |
| `0x63d3526` | `0x63d3520` | test %rbx,%rbx; je from `0x63d3314` | via r15 | jmp `0x63d331a` |

## The scan (8 slots, three shapes)

The scan array sits at walk-table + `0x100`, 16-byte entries, slot 0
the MRU head (never compared); slots 1..7 are compared, and a hit swaps
the hit entry into slot 0.

- Slot-0 head comparisons in each walk variant (e.g. `cmp 0x100(%rsi),
  %r13` at `0x63d31e8`, `cmp 0x100(%r15),%r13` at `0x63d3250`,
  `cmp 0x100(%r14),%r13` at `0x63d32b8`, `cmp 0x100(%r15),%r13` at
  `0x63d34de`).
- Unrolled scan at `0x63d3663..0x63d36cb`: slots 2..7 at
  `0x120..0x170` of the rsi table compared against r13, hit path
  `0x63d34a2`, exhaustion falls to lu-miss `0x63d36e9`.
- Indexed loop at `0x63d36f9`: base r15, index r11 = index * 16 from 1
  while != 8, hit swaps into slot 0, exhaustion falls to lu-miss
  `0x63d3792`.

Lu-miss sites (all rdi = rbx context, rsi = `lea 0x6511a00`,
rcx = rbp key, r8 = 1, r9 = 0):

| site | rdx | rejoin |
| --- | --- | --- |
| `0x63d35c1` | r14 | `0x63d3191` |
| `0x63d3659` | r15 | `0x63d3139` |
| `0x63d36e9` | rsi (scan table pointer) | `0x63d30f7` |
| `0x63d3792` | r15 | `0x63d333b` |

## Size-class blocks

None: 0 bsr instructions in this FDE, like #280/#281/#282 and unlike
#275/#276/#277/#279/#283/#284.

## Raw-e8 ranking and remaining candidates

Raw 0xe8 census (byte scan grouped by enclosing `.eh_frame` FDE; raw
counts are an upper bound, site counts come from objdump mnemonics):
10 (#275), 8 (#276), 6 (#277), 6 (#278), 5 (#279), then 4-count FDEs:
`0x63cb150` (#280), `0x63c8d60` (#281), `0x636bd90` (#282),
`0x6350210` (#283), `0x6365660` (#284), and this FDE `0x63d3080`.
After this packet, exactly two 4-raw FDEs remain unclaimed:
`0x63d5940..0x63d605c` (1820 bytes) and `0x63ec900..0x63ed06d`
(1901 bytes).

## Cited, not claimed

- bin_table_init body `0x63d9880..0x63d9a64` (packet #262).
- lu-miss handler `0x63d9700..0x63d987b` (packet #215).
- Previous FDE `0x63d2a80..0x63d3071`, next FDE `0x63d37a0..0x63d37a9`.
- Tail-jump targets `0x63637f0`, `0x63bd6c0` (packet #279), `0x6363260`.
- Other call targets (context only).

## Verification

- `tools/node115_lu_bintableinit_caller_walk_rsp_locksub_4sites.py`:
  exit 0 (checks: binary size/SHA-256, `.eh_frame` bounds, gap/padding,
  exhibit bytes, strict/call/bsr/ret census, site branch shapes, canary
  checks, lock-sub presence, `.rela.dyn` 60,723 total / 59,534 RELATIVE
  and `.rela.plt` 278, records consistency, disjointness over prior
  records, slug uniqueness, raw-e8 ranking, MANIFEST digests).
- `tests/test_node115_lu_bintableinit_caller_walk_rsp_locksub_4sites.py`:
  exit 0 (tamper controls first — hex flip, strict-count change,
  call-site change, injected overlap, all correctly fail — then clean
  temp copy, regeneration, and independent recounts).
- `make verify`: exit 0 (559 manifests, 7161 entries).
  `make catalogue-check`: fails pre-existing on this base with "Stale
  catalogue: README.md" (also on a pristine checkout); not a packet
  regression. The full `make test` suite (584 files on this base) is not
  run by design (hours + VM-restart risk); this deviation is stated
  honestly here rather than claimed as a pass.
- Disjointness: NONE over prior records (range-only collector; census
  and cited-only subtrees excluded; self excluded by exact window
  equality).
- `.hex` exhibits are raw binary bytes, not hex text.

## Not covered

- The remaining two 4-raw caller FDEs (see above).
- The static leaves and named-only callee families outside this window.
- Runtime values of any `.bss` byte (mechanism only, never values).
- Per-scan mapping of all four lu-miss sites to distinct walk variants
  beyond the arguments and rejoins listed above.

## Next question

Packet #286 decodes `0x63d5940..0x63d605c` (1820 bytes, 4 raw
candidates), the first remaining 4-raw caller FDE in the order #283's
pointer listed them.
