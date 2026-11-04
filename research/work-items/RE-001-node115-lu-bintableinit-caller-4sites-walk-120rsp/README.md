# RE-001-node115-lu-bintableinit-caller-4sites-walk-120rsp

Ninth bin_table_init caller FDE in the node-115 lookup chain: the lookup
walk at `0x6350210..0x6352f5e` (11598 bytes, 2382 strict lines, 90 calls,
1 ret), carrying over from packet #282's next question. Unlike #280 (one
stack temp `0x10(%rsp)`, 4 sites), #281 (plain rsp, 4 sites, 0 ret), and
#282 (plain rsp, 4 sites, 1 ret), this FDE uses one stack temp
`lea 0x120(%rsp)` at all four null-context bin_table_init sites, pairs the
walk with thirteen lu-miss fallbacks, and — unlike #280/#281/#282 — contains
size-class blocks (14 bsr instructions). The context pointer is derived from
the thread pointer, not passed in a register. Static analysis only; the
target binary is never executed.

Base: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
(fetch-confirmed at build time). Target binary
`artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Prior pointer verified (no correction)

Packet #282's records named this FDE `0x6350210..0x6352f5e` with 11598
bytes and 4 raw candidates. Both figures are verified correct:
`0x6352f5e - 0x6350210 = 0x2d4e = 11598` bytes, computed by program from
the `.eh_frame` bounds (previous FDE ends at `0x635020a`, next FDE starts
at `0x6352f60`), and the objdump census finds exactly 4 bin_table_init
sites. No #282 framing is corrected.

## The FDE

- Window: `0x6350210..0x6352f5e`, 11598 bytes, 2382 strict lines
  (address + bytes field + tab + mnemonic starting with a lowercase
  letter; byte-continuation lines excluded), 90 calls, 1 ret at
  `0x63504fc` (shared epilogue; return value is rbp, the entry-computed
  mask `(1 << cl)` with bit 0 cleared).
- Frame: `sub $0x2b8,%rsp`, canary at `0x2a8(%rsp)`, canary check at
  `0x63504d1` jumping to the `__stack_chk_fail` call at `0x6351f42` on
  mismatch. Entry starts with `push %r15` (no endbr64).
- Bounds from `.eh_frame` (PC-relative sdata4, fixed 4-byte range fields,
  not ULEB), not from endbr64 scanning. Previous FDE
  `0x634ffd0..0x635020a`, gap before 6 bytes (`0xcc`). Next FDE
  `0x6352f60..0x6352fb6`, padding after 2 bytes (`0xcc`).
- Entry: rdi = key (kept in r12), rsi = third argument (kept in r13),
  edx = index (kept in r10 via movslq), ecx = flag byte (kept in r11b).
  The context pointer rbx is derived from the thread pointer (fs:0 plus
  `-0x10a8`); it is tested for null at every bin_table_init branch.
- Gate references (mechanism only): flag byte at `0x6511738` read at
  `0x6350270`; TLS byte fs:0x330 checked at `0x6350262`
  (jne `0x6350d70`); byte `0x6713606` checked at `0x635036e`/`0x635037d`
  (cmpb $0x0, jne `0x63505d8`) — the same byte gated #278's and #279's
  entries. No runtime values are claimed.

## The walk (single shape, four null-context sites)

Top index: `(key >> 0x1a) & 0xf0` into the table at context + `0x1b0`;
the stored high bits (`key & 0xffffffffc0000000`) are compared against
the entry. On match, the second level is `(key >> 0x9) & 0x1ffff8` added
to the table's `+0x8` slot, yielding a node pointer. The node value is
then resolved through the `0x6727a00` table indexed by
`(value >> 0x30)`, and the `0x65096c0` table is read by index (no
`lock sub` refcount decrement is observed in this FDE, unlike #278's
phase tails and #280's walk). On a top-level mismatch, the walk inserts:
it writes the new key and swaps the `0x100`/`0x108` fields of the table
entry. A `(value >> 0x30)` vs `0x23` threshold gate is also present.

Size-class blocks (14 bsr instructions, e.g. at `0x6350798`): bsr of
`(2 * size - 1)`, class clamped to 7, minus 3, shifted; thresholds
`0x7000000000000000` and `0x4000` nearby. This restores the size-class
shape seen in #275/#276/#277/#279 but absent from #280/#281/#282.

## bin_table_init: 4 sites, one arg shape, all rbx == 0 branches

Every site is reached from a null-context branch on rbx: site 1 falls
through a `test %rbx,%rbx` followed by `jne` away, sites 2–4 are `je`
targets of `test %rbx,%rbx`. bin_table_init initializes a fresh bin
table whenever the walk finds no context. bin_table_init itself
(`0x63d9880..0x63d9a64`) was claimed by packet #262; only its caller
FDE is claimed here. All four sites use the same stack temp
`lea 0x120(%rsp)`, unlike #280's `0x10(%rsp)` and #281/#282's plain rsp.

| site | block | branch | argument | rejoin |
| ---- | ----- | ------ | -------- | ------ |
| 0x6350e15 | 0x6350e00 | test rbx,rbx; jne away from 0x6350dfa | rdi = lea 0x120(%rsp) | 0x63502ca |
| 0x6351683 | 0x635166e | test rbx,rbx; je from 0x63510aa | rdi = lea 0x120(%rsp) | 0x63510b0 |
| 0x6351aba | 0x6351aaf | test rbx,rbx; je from 0x6350c2b | rdi = lea 0x120(%rsp) | 0x6350c31 |
| 0x635223a | 0x635222f | test rbx,rbx; je from 0x63519ab | rdi = lea 0x120(%rsp) | 0x63519b1 |

Each site block is the target of exactly one branch (verified: site 1
by fall-through, sites 2–4 by a single `je` each).

## The 8-slot scan and the lu-miss fallbacks

Beside the radix walk, the FDE scans an 8-entry array at walk-table +
`0x100` with 16-byte entries. Slot 0 (base + `0x100`) is the
most-recently-used head: it is never compared. Slot 1 is compared
separately (e.g. at `0x635145d`), then slots 2..7 are compared in
unrolled form (e.g. at `0x6351e74..0x6351ec9`, hit path `0x635146a`);
on a hit, the entry swaps into slot 0 (move-to-front). An indexed loop
at `0x6351e05` (index r12 from 1, 16-byte entries at context + `0x2b0`)
shows the same hit-swap shape. On exhaustion, each scan calls the
lu-miss handler (#215's FDE, cited not claimed) with the same argument
shape except for rcx/rdx:

| lu-miss site | rdx | rcx | rejoin |
| ------------ | --- | --- | ------ |
| 0x6351f03 | r14 | r12 | 0x6351f08 |
| 0x63523c1 | lea 0x1b0(%rbx) | rbp | 0x63523c6 |
| 0x63526b8 | lea 0x1b0(%rbx) | rbp | 0x6350cc6 |
| 0x6352859 | lea 0x1b0(%rbx) | r12 | 0x635285e |
| 0x635296d | r13 | r12 | 0x6350c57 |
| 0x6352b54 | lea 0x1b0(%rbx) | r12 | 0x6352b59 |
| 0x6352b93 | lea 0x1b0(%rbx) | r12 | 0x6352b98 |
| 0x6352c19 | lea 0x1b0(%rbx) | r12 | 0x6350a44 |
| 0x6352d86 | lea 0x1b0(%rbx) | r12 | 0x6352d8b |
| 0x6352dc5 | lea 0x1b0(%rbx) | r12 | 0x6352dca |
| 0x6352edb | r11 | r12 | 0x6352ee0 |
| 0x6352f15 | lea 0x1b0(%rbx) | rbp | 0x63513f4 |
| 0x6352f4f | lea 0x1b0(%rbx) | r12 | 0x6352f54 |

All thirteen lu-miss calls share: rdi = rbx (context),
rsi = lea `0x6511a00`, r8 = 1, r9 = 0. The rejoin points resume the
walk, so a miss does not abort it.

## Other callees (context only, not claims)

- `0x6365660` x4: the next 4-raw candidate FDE (cited, not claimed).
- `0x6365150` x4, `0x63f0a60` (memcpy@plt) x4, `0x63b7240` x4,
  `0x63b73a0` x4, `0x63ead50` x4, `0x63eb870` x4, `0x63495b0` x4,
  `0x63637f0` x4, `0x6363260` x6, `0x63bd6c0` x6: repeated walk/scan
  helpers (cited, not claimed).
- `0x63be4d0` x2, `0x63be540` x2, `0x6349780` x2, `0x63c2e80` x2,
  `0x63c3b00` x2, `0x63eec80` x2, `0x63c3780` x2: paired helpers.
- Single sites: `0x63c3890`, `0x6362f90`, `0x63c2f00`, `0x63c3330`,
  `0x634ebb0` (#261's window, cited), `0x63ef8e0`, `0x63ed8b0`,
  `0x63bf5b6`, `0x63f0bf0`, `0x63f0d70` (`__stack_chk_fail`@plt).

## Verification

- Static verifier
  `tools/node115_lu_bintableinit_caller_walk_120rsp_4sites.py`
  (byte reads only; never executes the binary): exit 0, 58 checks, including binary size + SHA-256,
  `.eh_frame` bounds, gap/padding int3 bytes, exhibit bytes, strict
  recount (2382), call census (90 total / 4 bin_table_init / 13
  lu-miss / 1 ret), bsr count (14), branch shapes at all 4 sites,
  records consistency, `.rela.dyn` census (60,723 entries total,
  59,534 RELATIVE, stated distinctly; `.rela.plt` 278 entries counted
  separately), disjointness, slug check, raw-e8 census and ranking,
  and MANIFEST digests.
- Own unit tests
  `tests/test_node115_lu_bintableinit_caller_walk_120rsp_4sites.py`:
  tamper controls first (hex flip, strict-count change, call-site
  list change, injected overlap — each confirmed to fail the
  verifier; clean temp copy confirmed to pass), plus regeneration
  comparisons and independent strict/census recounts.
- `make verify`: exit 0 (559 evidence-packet manifests, 7161 entries
  = base 7154 + this packet's 7 MANIFEST entries).
- `make catalogue-check`: exit 2, pre-existing `Stale catalogue:
  README.md` on the new base — not a packet regression, and not
  claimed as passing.
- Full `make test` is NOT attempted: 584 test files on the new base
  take hours and risk a VM-restart kill mid-run; no full-suite tally
  is claimed.
- MANIFEST.sha256: all 7 entries verified with `sha256sum -c`.
- Raw-e8 census for target `0x63d9880` grouped by enclosing
  `.eh_frame` FDE: 10 (#275), 8 (#276), 6 (#277), 6 (#278), 5 (#279),
  4 (#280), 4 (#281), 4 (#282), 4 (this FDE). This FDE's raw count
  (4) equals its objdump-verified site count (4). Remaining 4-raw
  FDEs after this packet: `0x6365660..0x63673d9` (7545 bytes),
  `0x63d3080..0x63d379c` (1820 bytes), `0x63d5940..0x63d605c`
  (1820 bytes), `0x63ec900..0x63ed06d` (1901 bytes).

## Disjointness

The verifier's range-only collector scans the merged tree plus prior
worktree records and gathers string range fields, [start, end] lists,
and start/end pairs inside exhibits/windows lists or dicts or a dict
literally named "window". It never collects enclosing-fde annotation
fields, census/cited-only metadata subtrees, next-caller pointers, scan
descriptors, or control-flow edges. Self-exclusion is by exact window
equality, never by slug, so an injected overlapping range still fails
the verifier. The window is disjoint from every prior claimed range,
including packet #275's caller FDE `0x63cba10..0x63ccd22`, packet
#276's caller FDE `0x63c9c80..0x63cb146`, packet #277's caller FDE
`0x63ce8c0..0x63cf8bc`, packet #278's caller FDE
`0x63d4bbe..0x63d5428`, packet #279's caller FDE
`0x63bd8c0..0x63be4ce`, packet #280's caller FDE
`0x63cb150..0x63cba04`, packet #281's caller FDE
`0x63c8d60..0x63c94fc`, packet #282's caller FDE
`0x636bd90..0x636c49c`, packet #215's handler FDE
`0x63d9700..0x63d987b`, and packet #262's bin_table_init window
`0x63d9880..0x63d9a64`. The slug
`RE-001-node115-lu-bintableinit-caller-4sites-walk-120rsp` does not
collide with any merged-tree directory.

## Not covered

- The remaining 107 static leaves, unchanged by this packet.
- The callee FDEs' internals beyond their call-site argument patterns.
- Runtime values of the data addresses (gate bytes, tables) — only the
  mechanism is reported.
- Whether the four walk paths correspond to four distinct callers or
  one caller inlined four times: observed control flow only, not
  proven.
- The thirteen lu-miss scans are not each individually mapped to a
  distinct walk variant: the scan shape is established from the
  verified unrolled and indexed-loop examples, and every miss site's
  arguments and rejoin are listed above.
- The next bin_table_init caller FDE `0x6365660..0x63673d9` (4 raw
  candidates, 7545 bytes, verified unclaimed): not decoded. Three
  other 4-raw FDEs also remain (`0x63d3080`, `0x63d5940`,
  `0x63ec900`); the chain continues from `0x6365660`.
- Packet #282's framings are NOT corrected or re-claimed here; its
  11598-byte pointer for this FDE is verified correct as described
  above.
