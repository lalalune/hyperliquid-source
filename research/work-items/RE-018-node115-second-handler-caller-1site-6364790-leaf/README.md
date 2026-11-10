# RE-018: second handler caller 1site 6364790 leaf

Fourth packet of the second-miss-handler-caller series (RE-018; the handler 0x634ebb0 has 64 call sites across 28 FDEs in the 11-05 frontier census, 10 windows free in the current tree, 8 of them under the 2000B cap, planned as 8 stages; the lu-miss frontier is exhausted 16/16 (all 16 caller variants in the merged tree); the lock-wait series is finished at #507). FDE 0x6364790..0x6364877 (231 B, 54 strict) is the smallest caller: a single-slot table lookup that calls the second handler ONCE (0x636485c), with no second call and no tail-jump, unlike stages 1–3. It has endbr64, 3 calls, 1 ret, 7 jumps, and returns a table entry — not 0/1, unlike stage 3. The next FDE starts at 0x6364880, nine padding bytes below this window's end (gap 9, 0xcc at 0x6364877..0x636487f); the previous FDE ends at 0x636478c, four padding bytes above this window's start (gap 4, 0xcc at 0x636478c..0x636478f).

Thin packet: no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`. Every claim below is a direct check over the window disassembly and bytes, quoted with addresses.

## Window

| Field | Value |
|---|---|
| FDE | 0x6364790..0x6364877 |
| Bytes | 231 |
| Strict | 54 (52 instructions + 2 continuation lines: the split `nopl` at 0x63647b8/0x63647bf and the split `nopw` at 0x6364847/0x636484e) |
| Second-handler call site | 0x636485c |
| Second-handler tail-jump | none |
| Rets | 1 (0x63647b7) |
| bsr | 0 |
| shr | 0 |
| shl | 0 |
| endbr64 | 1 (0x6364790) |
| Canary | absent (0 %fs:0x28 lines; no __stack_chk_fail call) |
| Jumps | 7 (0 outside) |
| PLT | 0 |
| Prefetch/tzcnt/btc | 0 / 0 / 0 |

## Second-handler site

| Field | Value |
|---|---|
| Call site | 0x636485c |
| Setup | lea 0x175c59(%rip),%rdx at 0x6364850 (# 0x64da4b0); mov %rdi,0x8(%rsp) at 0x6364857 (save entry rdi); call 0x634ebb0 at 0x636485c |
| Arguments | rdi = entry rdi, esi = index (mov %rcx,%rsi at 0x63647ca, rcx = *(0x6511760)), rdx = 0x64da4b0 |
| Result | mov 0x8(%rsp),%rdi at 0x6364861 (restore entry rdi); test %rax,%rax at 0x6364866; mov %rax,%rbx at 0x6364869 (the handler's result becomes the table entry); jne 0x63647d2 at 0x636486c when non-null — the 0x63c03f0 blocks; jmp 0x63647af at 0x6364872 when null — return rbx (null) via the epilogue |
| Predecessor | the null table slot on the re-read at 0x63647c6/0x63647cd/0x63647d0 (mov (%rax,%rcx,8),%rbx at 0x63647c6; mov %rcx,%rsi at 0x63647ca; test %rbx,%rbx at 0x63647cd; je 0x6364850 at 0x63647d0 when the slot is still null) |
| Target | 0x634ebb0 (FDE 0x634ebb0..0x634eccd, 285 B, 78 strict) |

The single site needs no second call and no tail-jump: the window has one index and one table slot, so one null path (the slot is read twice — first at 0x63647a6, again at 0x63647c6 — and the handler is called only if both reads are null). Stages 1–3 had two distinct null paths (table-first-qword vs table-slot) and needed a handler call on each; stage 4 has one slot, one null path, one call. There is no tail-jump because the handler's result must be post-processed inside the window (the 0x63c03f0 blocks at 0x63647d2/0x636481b run when the result is non-null) and the exit is a single shared epilogue returning rbx.

## Handler (0x634ebb0, cited context)

| Field | Value |
|---|---|
| FDE | 0x634ebb0..0x634eccd (285 B, 78 strict, endbr64 1 at 0x634ebb0) |
| Trylock | pthread_mutex_trylock@plt at 0x634ebce on mutex 0x6511700 (lea at 0x634ebb6) |
| Trylock failure | jne 0x634ec90 at 0x634ebd5; lea rdi,[r14-0x40] at 0x634ec90; call lock-wait 0x63bf680 at 0x634ec94; movb $0x1,0x6511728 at 0x634ec99; jmp 0x634ebdb (back to the counter increment — retry) |
| Counters | add QWORD [0x65116f8],0x1 at 0x634ebdb; cmp rbp,[0x65116f0] at 0x634ebe3; add QWORD [0x65116e8],0x1 at 0x634ebec; mov [0x65116f0],rbp at 0x634ebf4 |
| Bound | cmp ebx,0xffe at 0x634ebfb; ja 0x634ec50 (out-of-range path: movb $0x0,0x6511728 at 0x634ec50; unlock at 0x634ec5d; xor r12d,r12d at 0x634ec5a) |
| Count | mov eax,[0x65096b0] at 0x634ec03; lock add [0x65096b0],0x1 at 0x634ecc0 (when ebx == count, je 0x634ecc0 at 0x634ec0b) |
| Table | lea rdx,0x65096c0 at 0x634ec13; mov r12,[rdx+rcx*8] at 0x634ec1a (rcx = ebx) |
| Null slot | je 0x634eca8 at 0x634ec21; call 0x6364430 at 0x634ecb0; mov r12,rax at 0x634ecb5 |
| Unlock | pthread_mutex_unlock@plt at 0x634ec31 (and at 0x634ec5d on the out-of-range path) |
| Return | test ebx,ebx at 0x634ec36; ebx == 0 returns r12 (mov rax,r12 at 0x634ec3b; ret at 0x634ec45); else 0x6367450 at 0x634ec64 and 0x6368e40 at 0x634ec72 are checked, then the abort path (call 0x63bf5b6 at 0x634ec86; call abort@plt (0x63f0bf0) at 0x634ec8b) |
| Calls | 9 (trylock, unlock x2, 0x6367450, 0x6368e40, 0x63bf5b6, abort, lock-wait 0x63bf680, 0x6364430) |

The handler is already claimed as a window by RE-001-node115-lu-value-leaves-bin — it is cited context only, never a stage. It links back to the finished lock-wait series: on trylock failure it falls back to the lock-wait helper 0x63bf680.

## Calls

| Target | Site | PLT |
|---|---|---|
| 0x63c03f0 | 0x6364805 | no |
| 0x63c03f0 | 0x636483d | no |
| 0x634ebb0 (second miss handler) | 0x636485c | no |

No lu-miss, bin_table_init, key-resolver (0x6365150), count call, loader call, sched_getcpu, 0x6352fc0, 0x63644xx trio, or #314–#510 window calls. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x63c03f0, 0x634ebb0) are NOT PLT stubs. (The `@plt` substring also appears in lea/mov symbol annotations such as `__register_atfork@plt+0x11fbd0` for the .bss/.data addresses; those are not PLT calls.)

## Shape

Entry: endbr64 at 0x6364790; push %rbx at 0x6364794; sub $0x10,%rsp at 0x6364795. The index is read (`mov 0x1acfc1(%rip),%edx` at 0x6364799, # 0x6511760); the table base is loaded (`lea 0x1a4f1a(%rip),%rax` at 0x636479f, # 0x65096c0); the slot is read (`mov (%rax,%rdx,8),%rbx` at 0x63647a6); if non-null the window returns it immediately (`test %rbx,%rbx` at 0x63647aa; je 0x63647c0 at 0x63647ad only when null; else add $0x10,%rsp at 0x63647af, mov %rbx,%rax at 0x63647b3, pop %rbx at 0x63647b6, ret at 0x63647b7). The `nopl` at 0x63647b8/0x63647bf is padding between the fast-return epilogue and the handler path.

Handler path (0x63647c0, taken when the first read is null): the index is re-read (`mov 0x1acf9a(%rip),%ecx` at 0x63647c0, # 0x6511760); the slot is re-read (`mov (%rax,%rcx,8),%rbx` at 0x63647c6); esi is set to the index (`mov %rcx,%rsi` at 0x63647ca); if the slot is still null (`test %rbx,%rbx` at 0x63647cd; je 0x6364850 at 0x63647d0), the handler call below runs. Otherwise the 0x63c03f0 blocks run.

The 0x63c03f0 blocks (0x63647d2/0x636481b): gate 1 — `mov 0x3ad2a7(%rip),%rsi` at 0x63647d2 (# 0x6711a80); `test %rsi,%rsi` at 0x63647d9; if *(0x6711a80) <= 0, jle 0x636480f at 0x63647dc skips the first call. Call 1 (0x63647de): `lea 0x3ad2d3(%rip),%r8` at 0x63647de (# 0x6711ab8); `lea 0x2998(%rbx),%rsi` at 0x63647e5; `xor %ecx,%ecx` at 0x63647ec; `mov $0x1,%edx` at 0x63647ee; `movzbl (%r8),%r9d` at 0x63647f3; `mov $0x2,%r8d` at 0x63647f7; `mov %rdi,0x8(%rsp)` at 0x63647fd (save entry rdi); `sub %r9d,%r8d` at 0x6364802 (r8 = 2 − byte at 0x6711ab8); call 0x63c03f0 at 0x6364805; `mov 0x8(%rsp),%rdi` at 0x636480a (restore entry rdi). Gate 2 — `mov 0x3ad262(%rip),%r10` at 0x636480f (# 0x6711a78); `test %r10,%r10` at 0x6364816; if *(0x6711a78) <= 0, jle 0x63647af at 0x6364819 returns rbx. Call 2 (0x636481b): `lea 0x3ad296(%rip),%r11` at 0x636481b (# 0x6711ab8); `mov $0x2,%r8d` at 0x6364822; `lea 0x2998(%rbx),%rsi` at 0x6364828; `xor %ecx,%ecx` at 0x636482f; `movzbl (%r11),%edx` at 0x6364831; `sub %edx,%r8d` at 0x6364835 (r8 = 2 − byte at 0x6711ab8); `mov $0x2,%edx` at 0x6364838; call 0x63c03f0 at 0x636483d; jmp 0x63647af at 0x6364842 returns rbx. The `nopw` at 0x6364847/0x636484e is padding between the second call block and the handler call.

The handler call (0x6364850, taken when the slot is null on the re-read): `lea 0x175c59(%rip),%rdx` at 0x6364850 (# 0x64da4b0); `mov %rdi,0x8(%rsp)` at 0x6364857 (save entry rdi); call 0x634ebb0 at 0x636485c — the single handler call site (rdi = entry rdi, esi = index, rdx = 0x64da4b0). `mov 0x8(%rsp),%rdi` at 0x6364861 (restore entry rdi); `test %rax,%rax` at 0x6364866; `mov %rax,%rbx` at 0x6364869 (the handler's result becomes the table entry); jne 0x63647d2 at 0x636486c — if non-null, run the 0x63c03f0 blocks; jmp 0x63647af at 0x6364872 — if null, return rbx (null) via the epilogue.

Exit: the single ret at 0x63647b7 returns rax via the single epilogue at 0x63647af; rbx's reaching defs are exactly {0x63647a6 (table slot, first read), 0x63647c6 (table slot, re-read), 0x6364869 (handler result)} — so the window returns either the cached table entry or the handler's fresh entry (or null if the handler returns null). The window has four backward jumps: jle @0x6364819, jmp @0x6364842, jne @0x636486c and jmp @0x6364872.

## Stage 3 (prior packet #510, cited not claimed)

The stage-3 window is FDE 0x6378120..0x6378364 (580 B, 150 strict, sha256 ef3f718eea8e415993da716c95f520d8f53194e073edffa92b84b869ef188103; first bytes `f3 0f 1e fa`, last 5 bytes `e9 b8 fe ff ff`), the first handler-twice caller. It has 10 calls (handler ×2 at 0x63782c3 and 0x6378357, 0x63ec600 at 0x6378148, sched_getcpu@plt at 0x63781cb), 1 ret at 0x6378171, endbr64 1, 30 jumps / 0 outside, and returns 0/1 (rax reaching defs {0x6378126, 0x6378165, 0x637826a, 0x637829b}) — unlike this window, which returns a table entry.

## Verification (direct checks only — thin packet)

- Window bytes: 231 B extracted from `artifacts/node/115/hl-node` at file offset 0x6363790 (VA 0x6364790, delta 0x1000, verified against four spot bytes: `e8 e6 bb 05 00` at 0x6364805, `e8 ae bb 05 00` at 0x636483d, `e8 4f a3 fe ff` at 0x636485c, `c3` at 0x63647b7); first bytes `f3 0f 1e fa 53 48 83 ec` (endbr64; push %rbx; sub $0x10,%rsp), last 5 bytes `e9 38 ff ff ff` (jmp 0x63647af); sha256 `64e99af4201feae077947d97646f41c94d994f0a03fd490b58cdc2de26af0572`. The `.hex` exhibit is byte-identical to the binary slice. The delta is 0x1000, NOT 0x10000: the binary slice at file offset 0x6354790 (VA − 0x10000) does not start `f3 0f 1e fa` — it does not match. File offset is VA − 0x1000 by direct subtraction.
- Objdump census over the window disassembly (objdump -d of the binary .text, window slice; 54 strict lines): 3 calls, 1 ret, bsr 0, shr 0, shl 0, endbr64 1, canary 0, 7 jumps / 0 outside, 0 PLT calls by `@plt` suffix.
- FDE bounds: `readelf --debug-dump=frames` returns FDE pc=0x6364790..0x6364877 directly; the window ends at 0x6364877, gap 9 to the next FDE pc=0x6364880..0x6365142 — the bytes at VA 0x6364877..0x636487f (file offsets 0x6363877..0x636387f) are all 0xcc, nine padding bytes. Gap 4 above: the previous FDE is pc=0x6364430..0x636478c — the bytes at VA 0x636478c..0x636478f (file offsets 0x636378c..0x636378f) are all 0xcc, four padding bytes.
- Handler shape copied from #508's verified handler census (FDE 0x634ebb0..0x634eccd, 285 B, 78 strict, 9 calls, 1 ret at 0x634ec45): trylock on mutex 0x6511700, lock-wait fallback 0x63bf680, counters 0x65116f8/0x65116e8/0x65116f0, cmp ebx,0xffe, table 0x65096c0.
- Exit reaching-definitions read straight from the disassembly: rbx defs {0x63647a6, 0x63647c6, 0x6364869} reach `mov %rbx,%rax` at 0x63647b3; the window returns a table entry (or null).
- Stage 5 NQ pointer censused directly: readelf FDE pc=0x63a5550..0x63a56a5 (341 B); objdump slice 99 strict (97 instructions + 2 continuation lines, the split movq at 0x63a5679/0x63a5680 and the split nopl at 0x63a5688/0x63a568f), 3 calls, handler call at 0x63a55df, 3 rets at 0x63a55ff, 0x63a560e and 0x63a569b, endbr64 0, 14 jumps / 0 outside. Gap 0 above (the previous FDE pc=0x63a5290..0x63a5550 ends exactly at this window's start) and gap 11 below (the next FDE pc=0x63a56b0..0x63a594f — the bytes at VA 0x63a56a5..0x63a56af, file offsets 0x63a46a5..0x63a46af, are all 0xcc, eleven padding bytes).
- Duplicate check: live upstream main a8616af9 (verified 2026-11-10 22:04 UTC, 2026-11-11 07:04 KST; this packet was built against a8616af9) — the slug path returns 404; GitHub issue search over open PR titles+bodies: `6364790` 0 hits; `6364877` 0 hits; `636485c` 0 hits; `634ebb0` 3 hits (#6572, #6573, #6574) in repo-scoped search (index false negative — the direct pulls scan below finds 106 citations, and the 28 lock-wait family PRs cite it 2 times each); `RE-018` 12 search hits = #6574, #6573, #6572, #408, #465, #1041, #1035, #550, #3375, #3369, #1267, #1265 (open #6574, #6573 and #6572, the rest closed; none about this series except #6574, #6573 and #6572); not a claim; a direct pulls scan of all 587 open PRs finds no other citation: `6364790` 5 (3 in #6574, 1 in #6573, 1 in #6572), `6364877` 4 (2 in #6574, 1 in #6573, 1 in #6572), `636485c` 3 (all in #6574), `634ebb0` 106 (15 in #6574 #510 + 17 in #6573 #509 + 18 in #6572 #508 + 2 each in the author's own 28 open lock-wait PRs #5996 #480 + #6000 #481 + #6007 #482 + #6017 #483 + #6025 #484 + #6035 #485 + #6043 #486 + #6050 #487 + #6055 #488 + #6063 #489 + #6072 #490 + #6078 #491 + #6084 #492 + #6087 #493 + #6092 #494 + #6096 #495 + #6156 #496 + #6209 #497 + #6220 #498 + #6227 #499 + #6231 #500 + #6336 #501 + #6339 #502 + #6345 #503 + #6450 #504 + #6455 #505 + #6464 #506 + #6567 #507), `RE-018` 16 (5 in #6574, 5 in #6573, 6 in #6572) — the citations live in the author's own prior PRs as cited context; no other PR claims this window; the author-scoped search returns 31 open and 478 closed PRs in this repo; local work-items tree: no other packet claims this window (0 records.json with window fde `0x6364790..0x6364877` besides this one; the FDE range appears only as a survey entry in the lock-wait family records' /survey/second_handler_survivors list — citations, not claims — and the address 6364790 appears in 44 other records.json survey tables).

- NOT run (declared): no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`.

## Results and limitations

- This is the FOURTH packet of the RE-018 series (second miss handler 0x634ebb0 callers; 8 planned stages). It establishes the smallest caller: a single-slot table lookup that reads its slot twice, calls the handler once when both reads are null, and returns the entry — with no sched_getcpu, no 0x6352fc0, no trio, and no second handler call.
- Corrections to #510: NONE — #510's claims about stage 4 verified in full against the stage-4 disassembly and bytes: FDE 0x6364790..0x6364877, 231 B, 54 strict (52 instructions + 2 continuation lines, the split nopl at 0x63647b8/0x63647bf and the split nopw at 0x6364847/0x636484e), 3 calls, handler call at 0x636485c, 1 ret at 0x63647b7, endbr64 1 at 0x6364790, 7 jumps / 0 outside, sha256 64e99af4201feae077947d97646f41c94d994f0a03fd490b58cdc2de26af0572.
- Unknown: entry inputs' caller-side meaning (rdi's role beyond being passed through to the handler and the 0x63c03f0 calls; the index at 0x6511760 beyond the observed table-index reads); field semantics beyond observed reads/writes (including the meaning of the table at 0x65096c0, the gates at 0x6711a80 and 0x6711a78, and the byte at 0x6711ab8); the 0x63c03f0's semantics beyond its call-site contracts (rsi = entry+0x2998, rcx = 0, r8 = 2 − table byte, edx = 1 then 2); the second handler's semantics beyond its observed body (its table at 0x65096c0, the count at 0x65096b0, the meaning of the 0xffe bound, and the abort path via 0x63bf5b6); what varies across the caller family, and why stage 5 returns a count instead of an entry (the stage-5 question).
- Next question: Stage 5 is FDE 0x63a5550..0x63a56a5 (341 B, 99 strict), with ONE second-handler call site (0x63a55df), 3 calls total (handler at 0x63a55df, 0x636b0a0 at 0x63a5610, 0x636b370 at 0x63a5625), 3 rets at 0x63a55ff, 0x63a560e and 0x63a569b, endbr64 0, 14 jumps / 0 outside — no sched_getcpu, no 0x6352fc0, no trio, and it returns ebx (a 32-bit value; -1 when the handler returns null), not a table entry and not 0/1. What varies across the caller family, and why does stage 5 return a count instead of an entry?
