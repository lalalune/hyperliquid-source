# RE-001: lu-miss caller 1site lookup

Fourteenth packet of the lu-miss-caller frontier (callers of the
lu-miss handler 0x63d9700 that do not call bin_table_init): a 314-byte
FDE with a single call — the lu-miss site itself — and no size-class
computation at all.

## Window

| Field | Value |
| --- | --- |
| FDE | 0x63d3f0e..0x63d4048 |
| Size | 314 bytes |
| Strict instructions | 75 |
| Calls | 1 (1 distinct direct, 0 indirect) |
| lu-miss sites | 1 (0x63d4003) |
| bin_table_init sites | 0 |
| second-handler sites | 0 |
| Ret | 1 (0x63d4047) |
| bsr | 0 |
| lock sub / lock add | 0 / 0 |
| Jumps | 7 (0 outside) |
| endbr64 | 0 (entry is `mov %rdx,%r8`) |
| Canary | none (no `%fs:0x28`, no `__stack_chk_fail` call) |
| TLS flag check | none |

## Shape

The entry passes rdi through (rdi is the context, saved to rax at
0x63d3f15 and restored to rdi at the miss site), takes the table base
from rsi, and takes the lookup key from rdx. There is NO size-class
computation: no byte table (0x67277c0), no size table (0x6727a00), no
$0x3fff cap, no fallback table (0x6728140), no bsr arms, no resolver
call (0x6365150), no count rounding. This is the first frontier
window with no size-class computation at all.

The lookup is a top-index lookup plus one 8-slot move-to-front scan:

- Top index: `(key >> 0x1a) & 0xf0`, added to the table base (rsi +
  0x1b0); the top slot's high bits are compared against `key &
  0xffffffffc0000000` (`cmp %r9,%rdi` at 0x63d3f36, register-first
  operand order — a table compare, not a slot compare).
- Top match: second-level extract `(key >> 0x9) & 0x1ffff8` plus the
  top slot's low pointer, then jmp to the resolve tail (0x63d4008).
- Scan: one 8-slot move-to-front scan over 0x100..0x180 in r10
  (table base). Slot 0 is checked directly at 0x63d3f53; slots 1–7
  are checked in a counter loop (head 0x63d3f7c, compare 0x63d3f83,
  bound `cmp $0x8,%rdx` at 0x63d3fe7). A hit swaps the top value
  into the slot (bubble-up-by-one). Slot-0 hit rejoins at the
  extract tail (0x63d3fce); loop hits rejoin there too.
- Exhaustion falls through to the miss block (0x63d3fed).

## Slot compares

| Slot | Address | Operands | Reversed? |
| --- | --- | --- | --- |
| 0 | 0x63d3f53 | `cmp 0x100(%rsi),%rdi` | no (memory-first) |
| loop (1–7) | 0x63d3f83 | `cmp 0x100(%r10,%rsi,1),%rdi` | no (memory-first) |

2 slot-compare instructions, ZERO reversed-operand, 0 of 8 slot
positions reversed. (Convention: a compare is reversed when the
register comes first, e.g. `cmp %r11,0x2b0(%rbx)`; memory-first is
normal.)

## The single lu-miss site

| Field | Value |
| --- | --- |
| Site | 0x63d4003 |
| Block | 0x63d3fed |
| Scan | single 8-slot scan (slot 0 + counter loop slots 1–7) |
| rdi | rax (entry rdi; only def `mov %rdi,%rax` at 0x63d3f15) |
| rsi | .bss 0x6511a00 (only def `lea 0x6511a00,%rsi` at 0x63d3fed) |
| rdx | walk table pointer (entry rsi, via r10; only def `mov %r10,%rdx` at 0x63d3ff7) |
| rcx | rdx (entry key; only def `mov %rdx,%rcx` at 0x63d3f26) |
| r8d | 1 (only def `mov $0x1,%r8d` at 0x63d3ffd) |
| r9d | 0 (only def `xor %r9d,%r9d` at 0x63d3ff4) |
| Rejoin | 0x63d4008 (resolve tail; fall-through after the call) |

The argument pattern is the frontier standard (rdi = context, rsi =
.bss 0x6511a00, rdx = table pointer, rcx = key, r8d = 1, r9d = 0).
The rcx provenance is proven by reaching-definitions: the only
reaching def at the site is `mov %rdx,%rcx` at 0x63d3f26, and rdx
there is the entry key (entry `mov %rdx,%r8` at 0x63d3f0e copies it
first, and no other write to rdx reaches the site). The r10 at the
site is the entry table base (`mov %rsi,%r10` at 0x63d3f50).

## Calls

| Target | Count | Sites |
| --- | --- | --- |
| 0x63d9700 (lu-miss handler) | 1 | 0x63d4003 |

No other calls: no bin_table_init, no second handler (0x634ebb0), no
lock-wait helper (0x63bf680), no key resolver (0x6365150), no
#314–#326 window calls, no PLT calls, no indirect calls.

## Exit

A single ret at 0x63d4047 with ONE reaching rax definition:
`mov 0x14(%rsp),%rax` at 0x63d4035. The resolve tail (0x63d4008)
loads node[0] from the resolved pointer (top-match pointer, hit
pointer, or the lu-miss call's return — three reaching defs at the
tail entry), then extracts fields: bit 0 to 0x1d(%rsp), `node[0] >>
0x30` to 0x14(%rsp) (the exit value, truncated to 32 bits), bits 1–3
to 0x18(%rsp), bit 1 of the shifted value to 0x1c(%rsp) (reloaded
into edx). The exit value is data-dependent; no constant exit value
is established. (Unlike #324/#325/#326, which had two reaching rax
definitions or multiple exits, this window has exactly one.)

## Frontier position

This is the fourteenth packet of the lu-miss-caller frontier (16
survivors): #314 on 0x63495b0, #315 on 0x6353a70, #316 on 0x6355900,
#317 on 0x63577f0, #318 on 0x635a7a0, #319 on 0x635c6d0, #320 on
0x635e2e0, #321 on 0x63c9650, #322 on 0x63ccd60, #323 on 0x63cddd0,
#324 on 0x63d03a0, #325 on 0x63d17e0, #326 on 0x63d2a80, and this
packet on 0x63d3f0e.

This window is a **lu-miss-ONLY survivor (NOT shared)**: it is in the
16-FDE lu-miss survivor list but NOT in the 18-FDE second-handler
survivor list, so claiming it consumes one slot of the combined
25-FDE miss-handler pool without double-counting a shared FDE.

It is the SMALLEST lu-miss-caller window so far (314 bytes; #314 was
453) and the first with no size-class computation, the first with a
single call, and the first whose scan uses a counter loop with zero
reversed-operand compares.

## Disjointness

The claimed set is this FDE only (0x63d3f0e..0x63d4048). The verifier
scans every prior records.json exhibit range in the tree (79,920 priors scanned, 0 skipped) and reports NONE overlapping. Cited, not claimed:
the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init
0x63d9880..0x63d9a64 (#262), the second miss handler 0x634ebb0, the
lock-wait helper 0x63bf680 (#251), the key resolver 0x6365150, the
prev FDE 0x63d3eee..0x63d3f0e, the next FDE 0x63d4048..0x63d4171,
and the #314–#326 windows. The next candidate 0x63d4048..0x63d4171
is likewise disjoint from all priors.

Raw 0xe8 census (own .eh_frame parse, 135,313 FDEs): lu-miss 168
sites / 53 FDEs (this FDE 1); bin_table_init 108 / 42 (this FDE 0);
second-handler 64 / 28 (this FDE 0).

## Verification

- Static verifier `tools/node115_lu_miss_caller_1site_lookup.py`: exit
  0 (226 checks, 0 failures).
- Unit tests `tests/test_node115_lu_miss_caller_1site_lookup.py`:
  exit 0 (12 checks, 0 failures). Tamper controls first: a hex flip,
  a strict-count change, a call-site change, and an injected overlap
  of #326's window each make the temp-copy verifier fail; the clean
  temp copy passes; byte-exact revert passes again.
- `make verify`: exit 0 (559 manifests / 7159 entries).
- `make catalogue-check`: exit 2 (pre-existing `Stale catalogue:
  README.md`, also present on a pristine checkout — not a
  regression).
- Full `make test` is NOT run: the new base has 584 test files, and
  a full run takes hours and risks a VM restart mid-run. This
  deviation is declared here and in the PR body.

## Next question

Packet #328 decodes 0x63d4048..0x63d4171 (297 bytes, 76 strict, 1
call, 1 lu-miss site at 0x63d4127, 0 bin_table_init sites, 0
second-handler sites, 1 ret at 0x63d4170, bsr 0 — the next surviving
lu-miss caller after this packet; a lu-miss-ONLY survivor, not
shared, like this packet).
