# RE-001: lu-miss caller 1site direct

Fifteenth packet of the lu-miss-caller frontier (callers of the
lu-miss handler 0x63d9700 that do not call bin_table_init): a 297-byte
FDE with a single call — the lu-miss site itself — and no size-class
computation at all. It is the SMALLEST lu-miss-caller window so far.

## Window

| Field | Value |
| --- | --- |
| FDE | 0x63d4048..0x63d4171 |
| Size | 297 bytes |
| Strict instructions | 76 |
| Calls | 1 (1 distinct direct, 0 indirect) |
| lu-miss sites | 1 (0x63d4127) |
| bin_table_init sites | 0 |
| second-handler sites | 0 |
| Ret | 1 (0x63d4170) |
| bsr | 0 |
| lock sub / lock add | 0 / 0 |
| Jumps | 7 (0 outside) |
| endbr64 | 0 (entry is `mov %rsi,%rax`) |
| Canary | none (no `%fs:0x28`, no `__stack_chk_fail` call) |
| TLS flag check | none |

## Shape

The entry takes four inputs: rdi is the output struct (saved to rbx
at 0x63d4059 and returned in rax at the ret), rsi is the context
(saved to rax at 0x63d4048 and restored to rdi at the miss site),
rdx is the table base (moved to rsi at 0x63d404b), and rcx is the
lookup key (never written on the walk→scan→miss path). There is NO
size-class computation: no byte table (0x67277c0), no size table
(0x6727a00), no $0x3fff cap, no fallback table (0x6728140), no bsr
arms, no resolver call (0x6365150), no count rounding. This is the
second frontier window with no size-class computation at all (#327
was the first).

The lookup is a top-index lookup plus one 8-slot move-to-front scan:

- Top index: `(key >> 0x1a) & 0xf0`, added to the table base (rsi);
  the top slot's high bits are compared against `key &
  0xffffffffc0000000` (`cmp %r10,%r9` at 0x63d406f, register-first
  operand order — a table compare, not a slot compare).
- Top match: second-level extract `(key >> 0x9) & 0x1ffff8` plus the
  top slot's low pointer, then jmp to the resolve tail (0x63d412c).
- Scan: one 8-slot move-to-front scan over 0x100..0x180 in rsi
  (table base). Slot 0 is checked directly at 0x63d4089; slots 1–7
  are checked in a counter loop (head 0x63d409b, compare 0x63d40a7,
  bound `cmp $0x8,%rdi` at 0x63d410b). A hit swaps the top value
  into the slot (bubble-up-by-one). Slot-0 hit rejoins at the
  extract tail (0x63d40e0); loop hits rejoin there too.
- Exhaustion falls through to the miss block (0x63d4111).

## Slot compares

| Slot | Address | Operands | Reversed? |
| --- | --- | --- | --- |
| 0 | 0x63d4089 | `cmp 0x100(%rsi),%r9` | no (memory-first) |
| loop (1–7) | 0x63d40a7 | `cmp 0x100(%rsi,%r8,1),%r9` | no (memory-first) |

2 slot-compare instructions, ZERO reversed-operand, 0 of 8 slot
positions reversed. (Convention: a compare is reversed when the
register comes first, e.g. `cmp %r11,0x2b0(%rbx)`; memory-first is
normal.)

## The single lu-miss site

| Field | Value |
| --- | --- |
| Site | 0x63d4127 |
| Block | 0x63d4111 |
| Scan | single 8-slot scan (slot 0 + counter loop slots 1–7) |
| rdi | rax (entry rsi; only def `mov %rsi,%rax` at 0x63d4048) |
| rsi | .bss 0x6511a00 (only def `lea 0x6511a00,%rsi` at 0x63d4114) |
| rdx | walk table pointer (entry rdx, via rsi; only def `mov %rsi,%rdx` at 0x63d4111) |
| rcx | rcx (entry key; no write on the walk→scan→miss path) |
| r8d | 1 (only def `mov $0x1,%r8d` at 0x63d4121) |
| r9d | 0 (only def `xor %r9d,%r9d` at 0x63d411b) |
| Rejoin | 0x63d412c (resolve tail; fall-through after the call) |

The argument pattern matches the frontier standard (rdi = context,
rsi = .bss 0x6511a00, rdx = table pointer, rcx = key, r8d = 1, r9d =
0), with one role swap relative to #327: here the context reaching
the miss handler is entry rsi (via rax), while entry rdi is the
output struct (saved to rbx), not the context. The rcx provenance is
proven by reaching-definitions: rcx has NO reaching def at the site
other than the entry value itself — no write to rcx on the
walk→scan→miss path.

## Calls

| Target | Count | Sites |
| --- | --- | --- |
| 0x63d9700 (lu-miss handler) | 1 | 0x63d4127 |

No other calls: no bin_table_init, no second handler (0x634ebb0), no
lock-wait helper (0x63bf680), no key resolver (0x6365150), no
#314–#327 window calls, no PLT calls, no indirect calls.

## Exit

A single ret at 0x63d4170 with ONE reaching rax definition:
`mov %rbx,%rax` at 0x63d4166. The resolve tail (0x63d412c) loads
node[0] from the resolved pointer (top-match pointer, hit pointer,
or the lu-miss call's return — three reaching defs at the tail
entry), then extracts fields into the output struct at rbx: the
sign-extended low 16 bits of node[0] (low 7 bits cleared) to 0x0,
`node[0] >> 0x30` (truncated to 32 bits) to 0x8, `(node[0] >> 2) &
0x7` to 0xc, bit 1 of `node[0] >> 1` to 0x10, and bit 0 of node[0]
to 0x11. The exit value is the entry rdi (the output struct
pointer); no constant exit value is established beyond the pointer
identity. The window has NO stack frame adjustment at all (no
sub/add rsp; only push/pop %rbx).

## Frontier position

This is the fifteenth packet of the lu-miss-caller frontier (16
survivors): #314 on 0x63495b0, #315 on 0x6353a70, #316 on 0x6355900,
#317 on 0x63577f0, #318 on 0x635a7a0, #319 on 0x635c6d0, #320 on
0x635e2e0, #321 on 0x63c9650, #322 on 0x63ccd60, #323 on 0x63cddd0,
#324 on 0x63d03a0, #325 on 0x63d17e0, #326 on 0x63d2a80, #327 on
0x63d3f0e, and this packet on 0x63d4048.

This window is a **lu-miss-ONLY survivor (NOT shared)**: it is in the
16-FDE lu-miss survivor list but NOT in the 18-FDE second-handler
survivor list, so claiming it consumes one slot of the combined
25-FDE miss-handler pool without double-counting a shared FDE.

It is the SMALLEST lu-miss-caller window so far (297 bytes; #327 was
314) and the second with no size-class computation, the second with
a single call, and the second whose scan uses a counter loop with
zero reversed-operand compares.

## Disjointness

The claimed set is this FDE only (0x63d4048..0x63d4171). The verifier
scans every prior records.json exhibit range in the tree (80,763 priors scanned, 0 skipped) and reports NONE overlapping. Cited, not claimed:
the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init
0x63d9880..0x63d9a64 (#262), the second miss handler 0x634ebb0, the
lock-wait helper 0x63bf680 (#251), the key resolver 0x6365150, the
prev FDE 0x63d3f0e..0x63d4048 (#327 window), the next FDE
0x63d4171..0x63d4289, and the #314–#327 windows. The next candidate
0x63e94a0..0x63e9bf2 is likewise disjoint from all priors.

Raw 0xe8 census (own .eh_frame parse, 135,313 FDEs): lu-miss 168
sites / 53 FDEs (this FDE 1); bin_table_init 108 / 42 (this FDE 0);
second-handler 64 / 28 (this FDE 0).

## Verification

- Static verifier `tools/node115_lu_miss_caller_1site_direct.py`: exit
  0 (228 checks, 0 failures).
- Unit tests `tests/test_node115_lu_miss_caller_1site_direct.py`:
  exit 0 (12 checks, 0 failures). Tamper controls first: a hex flip,
  a strict-count change, a call-site change, and an injected overlap
  of #327's window each make the temp-copy verifier fail; the clean
  temp copy passes; byte-exact revert passes again.
- `make verify`: exit 0 (559 manifests / 7159 entries).
- `make catalogue-check`: exit 2 (pre-existing `Stale catalogue:
  README.md`, also present on a pristine checkout — not a
  regression).
- Full `make test` is NOT run: the new base has 584 test files, and
  a full run takes hours and risks a VM restart mid-run. This
  deviation is declared here and in the PR body.

## Next question

Packet #329 decodes 0x63e94a0..0x63e9bf2 (1,874 bytes, 396 strict, 3
calls — all lu-miss, at 0x63e9b6c, 0x63e9bac and 0x63e9be8 — 0
bin_table_init sites, 0 second-handler sites, 2 rets at 0x63e96b1
and 0x63e97a6, bsr 0 — the next and LAST surviving lu-miss caller
after this packet; a lu-miss-ONLY survivor, not shared, like this
packet).
