# RE-001: lu-miss caller 3site prefetch

Sixteenth and LAST packet of the lu-miss-caller frontier (callers of
the lu-miss handler 0x63d9700 that do not call bin_table_init): a
1,874-byte FDE with three calls — all lu-miss sites — a pair-unrolled
lookup loop, an odd-count single-element path, and a post-lookup
normalize+prefetch pass. Its scans are the first on the frontier that
are majority-reversed: 24 slot compares, 21 reversed-operand, 3
normal.

## Window

| Field | Value |
| --- | --- |
| FDE | 0x63e94a0..0x63e9bf2 |
| Size | 1,874 bytes |
| Strict instructions | 396 |
| Calls | 3 (1 distinct direct, 0 indirect) |
| lu-miss sites | 3 (0x63e9b6c, 0x63e9bac, 0x63e9be8) |
| bin_table_init sites | 0 |
| second-handler sites | 0 |
| Ret | 2 (0x63e96b1, 0x63e97a6) |
| bsr | 0 |
| lock sub / lock add | 0 / 0 |
| Jumps | 55 (0 outside) |
| endbr64 | 0 (entry is `test %rdx,%rdx`) |
| Canary | none (no `%fs:0x28`, no `__stack_chk_fail` call) |
| TLS flag check | none |

## Shape

The entry takes four inputs: rdi is the table base (saved to rbp at
0x63e94c7; the top-table base rdi+0x1b0 is in r15 from 0x63e94ae),
rsi is the input struct (saved to r14 at 0x63e94b7; the element array
is at 0x8(%rsi)), rdx is the element count (rdx==0 returns early at
0x63e97a6), and rcx is the output array (saved to rbx at 0x63e94cb).
The frame pushes r15/r14/r13/r12/rbp/rbx and subtracts $0x18 from
rsp. There is NO size-class computation for the lookup: no byte
table (0x67277c0), no size table (0x6727a00), no $0x3fff cap, no
fallback table (0x6728140), no bsr arms, no resolver call
(0x6365150). The lookup indexes the table directly from the entry
key: top index `(key >> 0x1a) & 0xf0`, second level `(key >> 0x9) &
0x1ffff8`. The count%4 dispatch at 0x63e958d only unrolls the
prefetch pass; it is not size-class computation.

The lookup is pair-unrolled: each iteration resolves two elements
(chain A = first element, chain B = second element). An odd count
takes the single-element path at 0x63e96b2 (chain C), which resolves
element 0 and then rejoins the pair loop (r10=8) unless the count
was 1, in which case it goes straight to the prefetch dispatch at
0x63e9581. Each element is a top-index lookup plus one 8-slot
move-to-front scan over 0x2b0..0x320:

- Top index: `(key >> 0x1a) & 0xf0`, added to the table base; the top
  slot's high bits are compared against `key &
  0xffffffffc0000000` (chain A `cmp %rdi,%rsi` at 0x63e9509, chain
  B `cmp %r11,%rdx` at 0x63e9556, chain C `cmp %r8,%r11` at
  0x63e96da — all register-first operand order, table compares,
  not slot compares).
- Top match: second-level extract `(key >> 0x9) & 0x1ffff8` plus
  the top slot's low pointer, then the resolved pointer is stored
  to the output array.
- Scan: three 8-slot move-to-front scans over 0x2b0..0x320 (slot 0
  checked directly, slots 1–7 in a per-slot chain of blocks). A hit
  swaps the top value into the slot (bubble-up-by-one). Slot 7 is
  checked with a direct memory-first compare in each chain.
- Exhaustion falls through to the chain's miss block.

After the lookup loop, a count%4 dispatch (0x63e958d–0x63e95a2)
selects the prefetch remainder (case 3 at 0x63e95a4, case 2 at
0x63e95c9, case 1 at 0x63e95ed, case 0 straight to the 4-loop at
0x63e9617). Each resolved pointer p is normalized — `p[0] =
sign_extend_16(p[0]) & ~0x7f` written back — and prefetched with
`prefetcht0 (%reg)` and `prefetcht0 0x40(%reg)`. The 4-loop at
0x63e9617 normalizes and prefetches four pointers per iteration
(rbx advances $0x20) until rbx reaches the end pointer in rbp.

## Slot compares

| Chain | Slot | Address | Operands | Reversed? |
| --- | --- | --- | --- | --- |
| A | 0 | 0x63e9761 | `cmp %r8,%rsi` | yes |
| A | 1 | 0x63e9882 | `cmp %r13,%rsi` | yes |
| A | 2 | 0x63e998f | `cmp %r8,%rsi` | yes |
| A | 3 | 0x63e9a1b | `cmp %r9,%rsi` | yes |
| A | 4 | 0x63e9a2b | `cmp %r8,%rsi` | yes |
| A | 5 | 0x63e9ad5 | `cmp %r13,%rsi` | yes |
| A | 6 | 0x63e9ae5 | `cmp %r8,%rsi` | yes |
| A | 7 | 0x63e9b84 | `cmp 0x320(%rbp),%rsi` | no (memory-first) |
| B | 0 | 0x63e9715 | `cmp %rdi,%rdx` | yes |
| B | 1 | 0x63e9805 | `cmp %r10,%rdx` | yes |
| B | 2 | 0x63e996f | `cmp %rdi,%rdx` | yes |
| B | 3 | 0x63e99dc | `cmp %rsi,%rdx` | yes |
| B | 4 | 0x63e99ec | `cmp %rdi,%rdx` | yes |
| B | 5 | 0x63e9a96 | `cmp %r10,%rdx` | yes |
| B | 6 | 0x63e9aa6 | `cmp %rdi,%rdx` | yes |
| B | 7 | 0x63e9b49 | `cmp 0x320(%rbp),%rdx` | no (memory-first) |
| C | 0 | 0x63e97ae | `cmp %r9,%r11` | yes |
| C | 1 | 0x63e98fe | `cmp %r10,%r11` | yes |
| C | 2 | 0x63e99ae | `cmp %r9,%r11` | yes |
| C | 3 | 0x63e9a58 | `cmp %r13,%r11` | yes |
| C | 4 | 0x63e9a68 | `cmp %r9,%r11` | yes |
| C | 5 | 0x63e9b12 | `cmp %rax,%r11` | yes |
| C | 6 | 0x63e9b22 | `cmp %r9,%r11` | yes |
| C | 7 | 0x63e9bc5 | `cmp 0x320(%rbp),%r11` | no (memory-first) |

24 slot-compare instructions, 21 reversed-operand, 3 normal (slot 7
of each chain). (Convention: a compare is reversed when the register
comes first, e.g. `cmp %r11,0x2b0(%rbx)`; memory-first is normal.)
Chain A scans in rbp with key rsi, chain B scans in rbp with key
rdx, chain C scans in rdi for slots 0–1 and in rbp for slots 2–7
with key r11 (rdi is reused as the slot counter after slot 1).

## The three lu-miss sites

| Field | Site 1 | Site 2 | Site 3 |
| --- | --- | --- | --- |
| Site | 0x63e9b6c | 0x63e9bac | 0x63e9be8 |
| Block | 0x63e9b56 | 0x63e9b91 | 0x63e9bd2 |
| Scan | chain B | chain A | chain C |
| rdi | rbp (entry rdi) | rbp (entry rdi) | rbp (entry rdi) |
| rsi | .bss 0x6511a00 | .bss 0x6511a00 | .bss 0x6511a00 |
| rdx | r15 (entry rdi+0x1b0) | r15 (entry rdi+0x1b0) | r15 (entry rdi+0x1b0) |
| rcx | second element key (0x63e9531) | first element key (0x63e94e4) | single element key (0x63e96b6) |
| r8d | 1 | 1 | 1 |
| r9d | 0 | 0 | 0 |
| Rejoin | 0x63e9570 (pair loop) | 0x63e9525 (second-element block) | 0x63e96f6 (odd-path store) |

All three sites share the frontier argument pattern (rdi = table
base, rsi = .bss 0x6511a00, rdx = top-table base, rcx = key, r8d =
1, r9d = 0), with rdx coming from r15 (the entry
`lea 0x1b0(%rdi),%r15` at 0x63e94ae is the only reaching def at all
three sites). The rcx provenance is proven per site by
reaching-definitions: site 1's rcx is the second element key (only
def `mov 0x8(%rsi,%r10,1),%rcx` at 0x63e9531), site 2's rcx is the
first element key (only def `mov (%rcx,%r10,1),%rcx` at 0x63e94e4),
site 3's rcx is the single element key (only def
`mov (%rax),%rcx` at 0x63e96b6). Site 2 spills r10 to 0x8(%rsp)
before the call and restores it after, because the handler clobbers
r10. The rax def at each site is also a single reaching def: site 1
`add %rbp,%rax` at 0x63e954c, site 2 `mov $0x7,%eax` at 0x63e9b7f
(the slot-7 index), site 3 `mov 0x300(%rbp),%rax` at 0x63e9b01
(the slot-5 load).

## Calls

| Target | Count | Sites |
| --- | --- | --- |
| 0x63d9700 (lu-miss handler) | 3 | 0x63e9b6c, 0x63e9bac, 0x63e9be8 |

No other calls: no bin_table_init, no second handler (0x634ebb0), no
lock-wait helper (0x63bf680), no key resolver (0x6365150), no
#314–#328 window calls, no PLT calls, no indirect calls.

## Exit

Two rets, no constant exit value at either:

- Ret 1 at 0x63e96b1 (the normal exit, after the prefetch pass and
  the epilogue) has a 7-def may-analysis rax set:
  `CALL(0x63e9b6c)`, `CALL(0x63e9be8)`, `0x63e954c`, `0x63e95ff`,
  `0x63e96ef`, `0x63e97ed`, `0x63e994b` — none of them a
  constant-setting instruction (`mov $imm` / `xor self`). This is a
  may-analysis over-approximation: `CALL(0x63e9be8)`, `0x63e96ef`,
  `0x63e97ed` and `0x63e994b` are likely infeasible on the ret path
  (after the odd path, the pair loop or the case-1 block rewrites
  rax before the ret), while `CALL(0x63e9b6c)`, `0x63e954c` and
  `0x63e95ff` are feasible.
- Ret 2 at 0x63e97a6 (the rdx==0 early exit, reached directly from
  the entry `je`) has ENTRY only as its reaching rax def — again no
  constant.

The window has no constant exit value; the exit value is
data-dependent on the resolved pointers and the miss-handler
returns.

## Frontier position

This is the sixteenth and LAST packet of the lu-miss-caller frontier
(16 survivors): #314 on 0x63495b0, #315 on 0x6353a70, #316 on
0x6355900, #317 on 0x63577f0, #318 on 0x635a7a0, #319 on 0x635c6d0,
#320 on 0x635e2e0, #321 on 0x63c9650, #322 on 0x63ccd60, #323 on
0x63cddd0, #324 on 0x63d03a0, #325 on 0x63d17e0, #326 on 0x63d2a80,
#327 on 0x63d3f0e, #328 on 0x63d4048, and this packet on 0x63e94a0.

This window is a **lu-miss-ONLY survivor (NOT shared)**: it is in the
16-FDE lu-miss survivor list but NOT in the 18-FDE second-handler
survivor list, so claiming it consumes one slot of the combined
25-FDE miss-handler pool without double-counting a shared FDE.

It is the FIRST frontier window with three lu-miss sites, two rets,
an early rdx==0 exit, an odd-count single-element path, a
pair-unrolled lookup loop, and a post-lookup normalize+prefetch
pass — and the first whose scans are majority-reversed (21 of 24
slot compares reversed, vs 0 reversed in #327 and #328).

## Disjointness

The claimed set is this FDE only (0x63e94a0..0x63e9bf2). The verifier
scans every prior records.json exhibit range in the tree (81,606 priors
scanned, 0 skipped) and reports NONE overlapping. Cited, not claimed:
the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init
0x63d9880..0x63d9a64 (#262), the second miss handler 0x634ebb0, the
lock-wait helper 0x63bf680 (#251), the key resolver 0x6365150, the
prev FDE 0x63e91c0..0x63e9491, the next FDE 0x63e9c00..0x63e9c0c, and
the #314–#328 windows. The next candidate 0x6362190..0x6362901 is
likewise disjoint from all priors.

Raw 0xe8 census (own .eh_frame parse, 135,313 FDEs): lu-miss 168
sites / 53 FDEs (this FDE 3); bin_table_init 108 / 42 (this FDE 0);
second-handler 64 / 28 (this FDE 0).

## Verification

- Static verifier `tools/node115_lu_miss_caller_3site_prefetch.py`:
  exit 0 (380 checks, 0 failures).
- Unit tests `tests/test_node115_lu_miss_caller_3site_prefetch.py`:
  exit 0 (12 checks, 0 failures). Tamper controls first: a hex flip,
  a strict-count change, a call-site change, and an injected overlap
  of #328's window each make the temp-copy verifier fail; the clean
  temp copy passes; byte-exact revert passes again.
- `make verify`: exit 0 (559 manifests / 7159 entries).
- `make catalogue-check`: exit 2 (pre-existing `Stale catalogue:
  README.md`, also present on a pristine checkout — not a
  regression).
- Full `make test` is NOT run: the new base has 584 test files, and
  a full run takes hours and risks a VM restart mid-run. This
  deviation is declared here and in the PR body.

## Next question

The lu-miss frontier is exhausted with this packet (16 of 16
survivors claimed). The follow-on frontier is the lock-wait helper
0x63bf680 callers (344 survivors). The largest 1-site disjoint
candidate is 0x6362190..0x6362901 (1,905 bytes, 446 strict, 13 calls,
1 lock-wait site at 0x636286f, 0 lu-miss / 0 bin_table_init / 0
second-handler sites, 1 ret at 0x636282d, bsr 0, endbr64 1, canary
present, 49 jumps with 1 tail jump to 0x6360ed0, itself a lock-wait
survivor).
