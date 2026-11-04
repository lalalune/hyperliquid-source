RE-001: lu bin_table_init rsp locksub rsikey walk caller, 4 sites

Twelfth bin_table_init caller FDE in the node-115 lookup chain: the lookup
walk at `0x63d5940..0x63d605c` (1820 bytes, 378 strict lines, 9 calls,
0 ret), carrying over from packet #285's next question. Like #285 (plain
rsp, 4 sites, 0 ret, 1 lock sub) and unlike #280 (one stack temp
`0x10(%rsp)`, 4 sites), #281 (plain rsp, 4 sites, 0 ret, no lock sub),
#282 (plain rsp, 4 sites, 1 ret), #283 (one stack temp `lea 0x120(%rsp)`,
4 sites, 13 lu-miss fallbacks), and #284 (one stack temp `lea 0x60(%rsp)`,
4 sites, 1 ret), this FDE uses plain rsp at all four null-context
bin_table_init sites, pairs the walk with four lu-miss fallbacks, has no
size-class blocks (0 bsr), has no ret (all exits are canary-checked
tail-jumps), and executes a `lock sub` refcount decrement during node
resolution. It differs from #285 in the key's provenance: here the key is
the entry argument rsi itself (kept in rbp), while #285 read the key from
the second argument's `+0x28` field. Static analysis only; the target
binary is never executed.

Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
(fetch-confirmed at build time). Target binary
`artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Prior pointer verified (no correction)

Packet #285's records named this FDE `0x63d5940..0x63d605c` with 1820
bytes and 4 raw candidates. Both figures are verified correct:
`0x63d605c - 0x63d5940 = 0x71c = 1820` bytes, computed by program from
the `.eh_frame` bounds (previous FDE ends exactly at `0x63d5940`, next
FDE starts at `0x63d6060`), and the objdump census finds exactly 4
bin_table_init sites. No #285 framing is corrected.

## The FDE

- Window: `0x63d5940..0x63d605c`, 1820 bytes, 378 strict lines
  (address + bytes field + tab + mnemonic starting with a lowercase
  letter; byte-continuation lines excluded), 9 calls, 0 ret.
- Frame: `sub $0x198,%rsp`, canary at `0x188(%rsp)`, three canary checks
  (at `0x63d5a5f`, `0x63d5c06`, `0x63d5c48`, each `sub %fs:0x28,%rax`
  followed by `jne` to the `__stack_chk_fail` call at `0x63d602a`).
  Entry starts with pushes, not endbr64.
- Bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte range fields,
  not ULEB; CIE pointer relative to the CIE_id field, rec+4, not rec),
  not from endbr64 scanning. Previous FDE `0x63d5850..0x63d5940`, gap
  before 0 bytes. Next FDE `0x63d6060..0x63d6199`, padding after 4 bytes
  (`0xcc`).
- Entry: rdi = context (kept in rbx), rsi = key (kept in rbp), rsi then
  becomes the table pointer `lea 0x1b0(%rdi)`. The context is tested for
  null at every bin_table_init branch except site 1, which branches on
  the entry rdi itself.
- Exits: no ret. Three tail-jump exits, each after a canary-checked
  full pop sequence: `jmp 0x63637f0` (at `0x63d5a85`), `jmp 0x63bd6c0`
  (packet #279's caller FDE, at `0x63d5c35`), `jmp 0x6363260` (at
  `0x63d5c75`). No other jump leaves the window.
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
`0x63d5bc0..0x63d5bc8` (shr `$0x30`, cmp `$0x23`, jbe `0x63d5c40`, the
canary-checked exit path). On a top-level mismatch, the walk inserts:
it writes the new key and swaps the `0x100`/`0x108` fields of the table
entry (e.g. at `0x63d5ab5..0x63d5ae6`).

The walk section entered via the site-2 rejoin (`0x63d59f4`) differs
from the first in its node resolution: it reads the `0x65096c0` table
by index (at `0x63d59f7..0x63d5a13`: shl/sar `$0x10`, mask
`$0xffffffffffffff80`, indexed read into r8) and then executes
`lock sub %r14,0x38(%r8)` at `0x63d5a17` — a refcount decrement present
here and in #285, but absent from #283's and #284's walks.

Bin_table_init sites (all rdi = plain rsp, each block the target of
exactly one `je` on a null-context test):

| site | block | branch | argument | rejoin |
| --- | --- | --- | --- | --- |
| `0x63d5a96` | `0x63d5a90` | test %rdi,%rdi; je from `0x63d5974` | via r12 | jmp `0x63d597a` |
| `0x63d5af6` | `0x63d5af0` | test %rbx,%rbx; je from `0x63d59ce` | via r15 | fall-through `0x63d5afb` |
| `0x63d5b5e` | `0x63d5b58` | test %rbx,%rbx; je from `0x63d5a26` | via r14 | fall-through `0x63d5b63` |
| `0x63d5de6` | `0x63d5de0` | test %rbx,%rbx; je from `0x63d5bd4` | via r15 | jmp `0x63d5bda` |

## The scan (8 slots, four shapes)

The scan array sits at walk-table + `0x100`, 16-byte entries. Slot-0
head entries are compared in each walk variant (at `0x63d5aa8` on rsi,
`0x63d5b10` on r15, `0x63d5b78` on r14, `0x63d5d9e` on r15); slot-1
entries are compared at `0x63d5c86` (r14), `0x63d5ced` (r15), and
`0x63d5d55` (rsi). On a hit, the hit entry swaps into slot 0
(move-to-front: shared hit code at `0x63d5c93`, `0x63d5cfa`, and
`0x63d5d62`).

- Unrolled scan at `0x63d5df6..0x63d5e56`: slots 2..7 at
  `0x120..0x170` of the r14 table compared against r13, hit path
  `mov $0x7,%r11d; jmp 0x63d5c93`, exhaustion falls to lu-miss
  `0x63d5e81`.
- Unrolled scan at `0x63d5e90..0x63d5eec`: slots 2..7 at
  `0x120..0x170` of the r15 table, hit path `mov $0x7,%esi;
  jmp 0x63d5cfa`, exhaustion falls to lu-miss `0x63d5f19`.
- Unrolled scan at `0x63d5f28..0x63d5f84`: slots 2..7 at
  `0x120..0x170` of the rsi table, hit path `mov $0x7,%edi;
  jmp 0x63d5d62`, exhaustion falls to lu-miss `0x63d5fa9`.
- Indexed loop at `0x63d5fb3..0x63d6037`: base r15, index r10 from 1
  while != 8, byte index r11 = index * 16, cmp
  `0x100(%r15,%r11,1),%r13`, hit swaps into slot 0
  (`0x63d5fca..0x63d6025`, then jmp `0x63d5bfb`), exhaustion falls to
  lu-miss `0x63d6052`.

Lu-miss sites (all rdi = rbx context, rsi = `lea 0x6511a00`,
rcx = rbp key, r8 = 1, r9 = 0):

| site | rdx | rejoin |
| --- | --- | --- |
| `0x63d5e81` | r14 | `0x63d5a4c` |
| `0x63d5f19` | r15 | `0x63d59f4` |
| `0x63d5fa9` | rsi (scan table pointer) | `0x63d59b2` |
| `0x63d6052` | r15 | `0x63d5bfb` |

## Size-class blocks

None: 0 bsr instructions in this FDE, like #280/#281/#282/#285 and unlike
#275/#276/#277/#279/#283/#284.

## Raw-e8 ranking and remaining candidates

Raw 0xe8 census (byte scan grouped by enclosing `.eh_frame` FDE; raw
counts are an upper bound, site counts come from objdump mnemonics):
10 (#275), 8 (#276), 6 (#277), 6 (#278), 5 (#279), then 4-count FDEs:
`0x63cb150` (#280), `0x63c8d60` (#281), `0x636bd90` (#282),
`0x6350210` (#283), `0x6365660` (#284), `0x63d3080` (#285), and this
FDE `0x63d5940`. After this packet, exactly one 4-raw FDE remains
unclaimed: `0x63ec900..0x63ed06d` (1901 bytes).

## Cited, not claimed

- bin_table_init body `0x63d9880..0x63d9a64` (packet #262).
- lu-miss handler `0x63d9700..0x63d987b` (packet #215).
- Previous FDE `0x63d5850..0x63d5940`, next FDE `0x63d6060..0x63d6199`.
- Tail-jump targets `0x63637f0`, `0x63bd6c0` (packet #279), `0x6363260`.
- Other call targets (context only).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_rsp_locksub_rsikey_4sites.py`
  (byte reads only; never executes the binary): exit 0, 53 checks,
  including binary size + SHA-256, `.eh_frame` bounds, gap/padding int3
  bytes, exhibit bytes, strict recount (378), call census (9 total /
  4 bin_table_init / 4 lu-miss / 0 ret), bsr count (0), lock-sub
  presence (1, at `0x63d5a17`), branch shapes at all 4 sites, canary
  checks, records consistency, `.rela.dyn` census (60,723 entries
  total, 59,534 RELATIVE, stated distinctly; `.rela.plt` 278 entries
  counted separately), disjointness, slug check, raw-e8 census and
  ranking, and MANIFEST digests.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_rsp_locksub_rsikey_4sites.py`:
  exit 0, 13 checks. Tamper controls first (hex flip, strict-count
  change, call-site change, injected overlap — each confirmed to fail
  the verifier; clean temp copy confirmed to pass), plus regeneration
  comparisons and independent strict/census recounts.
- `make verify`: exit 0 (559 evidence-packet manifests, 7161 entries =
  base 7154 + this packet's 7 MANIFEST entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base — not a packet regression, and not claimed
  as passing.
- Full `make test` is NOT attempted: 584 test files on the new base
  take hours and risk a VM-restart kill mid-run; no full-suite tally is
  claimed.
- MANIFEST.sha256: all 7 entries verified with `sha256sum -c`.
- The `.hex` exhibit contains raw binary bytes, not hex text.

## Disjointness

The verifier's range-only collector scans the merged tree plus prior
worktree records and gathers string range fields, [start, end] lists,
and start/end pairs inside exhibits/windows lists or dicts or a dict
literally named "window". It never collects enclosing-fde annotation
fields, census/cited-only metadata subtrees, next-caller pointers, scan
descriptors, or control-flow edges. Self-exclusion is by exact window
equality, never by slug, so an injected overlapping range still fails
the verifier. Disjointness: NONE over prior ranges, 0 overlaps,
including packet #275's caller FDE `0x63cba10..0x63ccd22`, packet
#276's caller FDE `0x63c9c80..0x63cb146`, packet #277's caller FDE
`0x63ce8c0..0x63cf8bc`, packet #278's caller FDE `0x63d4bbe..0x63d5428`,
packet #279's caller FDE `0x63bd8c0..0x63be4ce`, packet #280's caller
FDE `0x63cb150..0x63cba04`, packet #281's caller FDE
`0x63c8d60..0x63c94fc`, packet #282's caller FDE `0x636bd90..0x636c49c`,
packet #283's caller FDE `0x6350210..0x6352f5e`, packet #284's caller
FDE `0x6365660..0x63673d9`, packet #285's caller FDE
`0x63d3080..0x63d379c`, packet #215's handler FDE `0x63d9700..0x63d987b`,
and packet #262's bin_table_init window `0x63d9880..0x63d9a64`. The slug
`RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-locksub-rsikey`
does not collide with any merged-tree directory.

## Not covered

- The remaining one 4-raw caller FDE (`0x63ec900`, see above).
- The static leaves and named-only callee families outside this window.
- Runtime values of any `.bss` byte (mechanism only, never values).
- Per-scan mapping of all four lu-miss sites to distinct walk variants
  beyond the arguments and rejoins listed above.
- The next bin_table_init caller FDE `0x63ec900..0x63ed06d` (4 raw
  candidates, 1901 bytes, verified unclaimed): not decoded.
- Packet #285's framings are NOT corrected or re-claimed here; its
  1820-byte pointer for this FDE is verified correct as described above.
