# RE-018: second handler caller 1site 63a5550 count

Fifth packet of the second-miss-handler-caller series (RE-018; the handler 0x634ebb0 has 64 call sites across 28 FDEs in the 11-05 frontier census, 10 windows free in the current tree, 8 of them under the 2000B cap, planned as 8 stages; the lu-miss frontier is exhausted 16/16 (all 16 caller variants in the merged tree); the lock-wait series is finished at #507). FDE 0x63a5550..0x63a56a5 (341 B, 99 strict) is the first caller with no endbr64 and three rets: a single-slot index lookup that calls the second handler ONCE (0x63a55df) and returns the resolved index ebx — not a table entry, unlike stage 4, and not 0/1, unlike stage 3. The next FDE starts at 0x63a56b0, eleven padding bytes below this window's end (gap 11, 0xcc at 0x63a56a5..0x63a56af); the previous FDE ends at 0x63a5550, exactly at this window's start (gap 0, no padding above).

Thin packet: no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`. Every claim below is a direct check over the window disassembly and bytes, quoted with addresses.

## Window

| Field | Value |
|---|---|
| FDE | 0x63a5550..0x63a56a5 |
| Bytes | 341 |
| Strict | 99 (97 instructions + 2 continuation lines: the split `movq` at 0x63a5679/0x63a5680 and the split `nopl` at 0x63a5688/0x63a568f) |
| Second-handler call site | 0x63a55df |
| Second-handler tail-jump | none |
| Rets | 3 (0x63a55ff, 0x63a560e, 0x63a569b) |
| bsr | 0 |
| shr | 0 |
| shl | 0 |
| endbr64 | 0 |
| Canary | absent (0 %fs:0x28 lines; no __stack_chk_fail call) |
| Jumps | 14 (0 outside) |
| PLT | 0 |
| Prefetch/tzcnt/btc | 0 / 0 / 0 |

## Second-handler site

| Field | Value |
|---|---|
| Call site | 0x63a55df |
| Setup | mov %r12,%rdx at 0x63a55d7 (rdx = entry rsi); mov %ebx,%esi at 0x63a55da (esi = the resolved index); mov %rbp,%rdi at 0x63a55dc (rdi = entry rdi); call 0x634ebb0 at 0x63a55df |
| Arguments | rdi = entry rdi, esi = ebx (the resolved index), rdx = entry rsi — unlike stages 1–4, rdx is the entry's rsi, not the constant 0x64da4b0 |
| Result | test %rax,%rax at 0x63a55e4; je 0x63a5690 at 0x63a55e7 when null — return -1; else the context is reloaded and the +8 field is compared with ebx (see Shape) |
| Predecessor | the non-null table slot at 0x63a55cf/0x63a55d5 (cmpq $0x0,0x18(%rdx,%rax,8) at 0x63a55cf; je 0x63a5610 at 0x63a55d5 when null — the allocate path; fall through to the handler call when the slot is non-null), or the allocate path's jmp 0x63a55d7 at 0x63a5664 after storing a fresh entry in the slot |
| Target | 0x634ebb0 (FDE 0x634ebb0..0x634eccd, 285 B, 78 strict) |

The single site needs no second call and no tail-jump: the window has one index and one table slot, so one null path (the slot is checked once at 0x63a55cf — if null the allocate path fills it and jumps back to the handler call; if non-null the handler is called directly). The site executes exactly once per invocation. There is no tail-jump because the handler's result must be post-processed inside the window (the null test at 0x63a55e4 and the +8 counter bump at 0x63a55f4–0x63a5606) and the exit is one of three rets returning ebx.

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
| 0x634ebb0 (second miss handler) | 0x63a55df | no |
| 0x636b0a0 | 0x63a5610 | no |
| 0x636b370 | 0x63a5625 | no |

No lu-miss, bin_table_init, key-resolver (0x6365150), count call, loader call, sched_getcpu, 0x6352fc0, 0x63644xx trio, or #314–#511 window calls. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x634ebb0, 0x636b0a0, 0x636b370) are NOT PLT stubs. (The `@plt` substring also appears in lea/mov symbol annotations such as `__register_atfork@plt+0x3205a0` for the .bss/.data addresses; those are not PLT calls.)

## Shape

Entry: no endbr64. The context pointer is loaded (`mov 0x36cbd9(%rip),%rdx` at 0x63a5550, # 0x6712130); push %r12 at 0x63a5557, `mov %rsi,%r12` at 0x63a5559 (save entry rsi), push %rbp at 0x63a555c, `mov %rdi,%rbp` at 0x63a555d (save entry rdi), push %rbx at 0x63a5560. The head walk: `mov 0x10(%rdx),%rcx` at 0x63a5561; `test %rcx,%rcx` at 0x63a5565; `je 0x63a55b0` at 0x63a5568 when the head is null; `mov 0x10(%rcx),%rax` at 0x63a556a; `test %rax,%rax` at 0x63a556e; `je 0x63a55b0` at 0x63a5571 when the next link is null; `cmp %rax,%rcx` at 0x63a5573; `je 0x63a5670` at 0x63a5576 when the next link points back to the head (the singleton case).

Fallback (0x63a55b0, head or next null): `mov 0x8(%rdx),%ebx` — ebx = the context's +8 field.

Unlink block (0x63a557c–0x63a55ae): splices %rax out of the +8/+0x10 doubly-linked list — `mov 0x8(%rax),%r8` at 0x63a557c; `mov 0x10(%rax),%rdi` at 0x63a5580; `mov 0x10(%r8),%r9` at 0x63a5584; `mov %r9,0x8(%rdi)` at 0x63a5588; `mov 0x8(%rax),%r10` at 0x63a558c; `mov %rdi,0x10(%r10)` at 0x63a5590; `mov 0x10(%rax),%r11` at 0x63a5594; `mov 0x8(%r11),%rcx` at 0x63a5598; `mov %rcx,0x10(%rax)` at 0x63a559c; `mov 0x10(%r10),%rbx` at 0x63a55a0; `mov %r10,0x8(%rbx)` at 0x63a55a4; `mov (%rax),%ebx` at 0x63a55a8 (ebx = the unlinked node's first field); `mov %rax,0x8(%rcx)` at 0x63a55aa; `jmp 0x63a55b3` at 0x63a55ae.

Singleton block (0x63a5670, taken when the next link points back to the head): `mov 0x8(%rax),%rsi` at 0x63a5670; `cmp %rax,%rsi` at 0x63a5674; `jne 0x63a569c` at 0x63a5677; else `movq $0x0,0x10(%rdx)` at 0x63a5679/0x63a5680 (clear the head), `mov (%rax),%ebx` at 0x63a5681, `jmp 0x63a55b3` at 0x63a5683. At 0x63a569c: `mov %rsi,0x10(%rdx)` at 0x63a569c (head = the next link), `jmp 0x63a557c` at 0x63a56a0 (run the unlink block). The `nopl` at 0x63a5688/0x63a568f is padding between the singleton block and the failure return.

Slot-index computation (0x63a55b3): `xor %eax,%eax` at 0x63a55b3; `cmp $0x1000,%ebx` at 0x63a55b5; `je 0x63a55cf` at 0x63a55bb when ebx == 0x1000 (slot 0); `lea 0x2(%rbx),%eax` at 0x63a55bd; `cmp $0x1001,%ebx` at 0x63a55c0; `mov $0x1,%esi` at 0x63a55c6; `cmove %rsi,%rax` at 0x63a55cb (ebx == 0x1001 → slot 1; otherwise slot = ebx+2).

Slot check (0x63a55cf): `cmpq $0x0,0x18(%rdx,%rax,8)` at 0x63a55cf; `je 0x63a5610` at 0x63a55d5 when the slot is null (the allocate path below); otherwise fall through to the handler call.

The handler call (0x63a55d7): `mov %r12,%rdx` at 0x63a55d7 (rdx = entry rsi); `mov %ebx,%esi` at 0x63a55da (esi = the resolved index); `mov %rbp,%rdi` at 0x63a55dc (rdi = entry rdi); call 0x634ebb0 at 0x63a55df — the single handler call site. `test %rax,%rax` at 0x63a55e4; `je 0x63a5690` at 0x63a55e7 when the handler returns null (return -1). Otherwise the context is reloaded (`mov 0x36cb3c(%rip),%rbp` at 0x63a55ed, # 0x6712130); `cmp %ebx,0x8(%rbp)` at 0x63a55f4; `je 0x63a5600` at 0x63a55f7 when ebx equals the stored +8 field; else `mov %ebx,%eax` at 0x63a55f9 and return ebx via the pops and ret at 0x63a55ff. At 0x63a5600: `lea 0x1(%rbx),%r12d` at 0x63a5600; `mov %ebx,%eax` at 0x63a5604; `mov %r12d,0x8(%rbp)` at 0x63a5606 (store ebx+1 into the +8 field); return ebx via the pops and ret at 0x63a560e. The `nop` at 0x63a560f is padding between the second ret and the allocate path.

The allocate path (0x63a5610, taken when the table slot is null): call 0x636b0a0 at 0x63a5610 (no argument setup in this window; its return in rax feeds the next call); `mov $0x10,%ecx` at 0x63a5615; `mov $0x93e0,%edx` at 0x63a561a; `mov %rbp,%rdi` at 0x63a561f (rdi = entry rdi); `mov %rax,%rsi` at 0x63a5622 (rsi = 0x636b0a0's return); call 0x636b370 at 0x63a5625. `test %rax,%rax` at 0x63a562a; `je 0x63a5690` at 0x63a562d when 0x636b370 returns null (return -1). Otherwise `lea 0x58(%rax),%rdx` at 0x63a562f; `mov %ebx,(%rax)` at 0x63a5633 (store the index in the new entry); `mov 0x36caf4(%rip),%rdi` at 0x63a5635 (# 0x6712130, reload the context); `xor %r8d,%r8d` at 0x63a563c; `mov %rdx,0x50(%rax)` at 0x63a563f; the slot-index computation again into r8 (`cmp $0x1000,%ebx` at 0x63a5643; `je 0x63a565f` at 0x63a5649; `lea 0x2(%rbx),%r8d` at 0x63a564b; `cmp $0x1001,%ebx` at 0x63a564f; `mov $0x1,%r9d` at 0x63a5655; `cmove %r9,%r8` at 0x63a565b); `mov %rax,0x18(%rdi,%r8,8)` at 0x63a565f (store the new entry in the table slot); `jmp 0x63a55d7` at 0x63a5664 (back to the handler call). The `nopl` at 0x63a5669 is padding between the allocate path and the singleton block.

Failure return (0x63a5690): `mov $0xffffffff,%ebx` at 0x63a5690; `mov %ebx,%eax` at 0x63a5695; pops; `ret` at 0x63a569b — returns -1.

Exit: three rets (0x63a55ff, 0x63a560e, 0x63a569b), each preceded by `mov %ebx,%eax` (0x63a55f9, 0x63a5604, 0x63a5695) and the same pop sequence (pop %rbx at 0x63a55fb/0x63a560a/0x63a5697, pop %rbp at 0x63a55fc/0x63a560b/0x63a5698, pop %r12 at 0x63a55fd/0x63a560c/0x63a5699); ebx's reaching defs are exactly {0x63a55a8 (unlinked node's first field), 0x63a55b0 (context +8 field), 0x63a5681 (singleton node's first field), 0x63a5690 (mov $0xffffffff,%ebx — the failure sentinel)} — so the window returns the resolved index ebx, or -1 on failure. The window has three backward jumps: jmp @0x63a5664, jmp @0x63a5683 and jmp @0x63a56a0.

Why a count, not an entry: the handler's entry pointer never escapes the window — it is only null-tested at 0x63a55e4. The entry itself is already in the table slot on the direct path (the slot was non-null at 0x63a55cf), and on the allocate path the fresh entry is stored into the slot at 0x63a565f before the handler is even called. What the caller needs back is *which* index was resolved: ebx, the index that selected the slot, with -1 as the failure sentinel. The +8 field of the context confirms ebx is a counter, not a pointer: when the resolved ebx equals the stored +8 value, the window stores ebx+1 back (0x63a5600–0x63a5606) — the counter advances past the index just resolved. Stages 1–2 and 4 return the entry pointer because their callers consume the entry; stage 3 returns 0/1 because its caller only needs success; stage 5 returns the index because its caller tracks entries by index.

## Stage 4 (prior packet #511, cited not claimed)

The stage-4 window is FDE 0x6364790..0x6364877 (231 B, 54 strict, sha256 64e99af4201feae077947d97646f41c94d994f0a03fd490b58cdc2de26af0572; first bytes `f3 0f 1e fa 53 48 83 ec`, last 5 bytes `e9 38 ff ff ff`), the smallest caller. It has 3 calls (0x63c03f0 at 0x6364805 and 0x636483d, handler at 0x636485c), 1 ret at 0x63647b7, endbr64 1, 7 jumps / 0 outside, and returns a table entry (rbx reaching defs {0x63647a6, 0x63647c6, 0x6364869}) — unlike this window, which returns ebx.

## Verification (direct checks only — thin packet)

- Window bytes: 341 B extracted from `artifacts/node/115/hl-node` at file offset 0x63a4550 (VA 0x63a5550, delta 0x1000, verified against six spot bytes: `e8 cc 95 fa ff` at 0x63a55df, `e8 8b 5a fc ff` at 0x63a5610, `e8 46 5d fc ff` at 0x63a5625, `c3` at 0x63a55ff, `c3` at 0x63a560e, `c3` at 0x63a569b); first bytes `48 8b 15 d9 cb 36 00 41` (mov from 0x6712130; push %r12), last 5 bytes `e9 d7 fe ff ff` (jmp 0x63a557c); sha256 `0f7ad46aba50388d5db422a641c9b12dde1857eb780a946323626a41f19b070d`. The `.hex` exhibit is byte-identical to the binary slice. The delta is 0x1000, NOT 0x10000: the binary slice at file offset 0x6395550 (VA − 0x10000) does not start `48 8b 15 d9 cb 36 00 41` — it does not match. File offset is VA − 0x1000 by direct subtraction.
- Objdump census over the window disassembly (objdump -d of the binary .text, window slice; 99 strict lines): 3 calls, 3 rets, bsr 0, shr 0, shl 0, endbr64 0, canary 0, 14 jumps / 0 outside, 0 PLT calls by `@plt` suffix.
- FDE bounds: `readelf --debug-dump=frames` returns FDE pc=0x63a5550..0x63a56a5 directly; the window ends at 0x63a56a5, gap 11 to the next FDE pc=0x63a56b0..0x63a594f — the bytes at VA 0x63a56a5..0x63a56af (file offsets 0x63a46a5..0x63a46af) are all 0xcc, eleven padding bytes. Gap 0 above: the previous FDE is pc=0x63a5290..0x63a5550, ending exactly at this window's start — there is no padding above (the byte at VA 0x63a554f is 0x00, the last byte of the previous FDE).
- Handler shape copied from #508's verified handler census (FDE 0x634ebb0..0x634eccd, 285 B, 78 strict, 9 calls, 1 ret at 0x634ec45): trylock on mutex 0x6511700, lock-wait fallback 0x63bf680, counters 0x65116f8/0x65116e8/0x65116f0, cmp ebx,0xffe, table 0x65096c0.
- Exit reaching-definitions read straight from the disassembly: ebx defs {0x63a55a8, 0x63a55b0, 0x63a5681, 0x63a5690} reach `mov %ebx,%eax` at 0x63a55f9, 0x63a5604 and 0x63a5695; the window returns the resolved index ebx, or -1 on failure.
- Stage 6 NQ pointer censused directly: readelf FDE pc=0x6379310..0x6379804 (1268 B); objdump slice 320 strict, 13 calls, handler x3 at 0x63797a1, 0x63797bd and 0x63797f2, 1 ret at 0x6379617, endbr64 1, 59 jumps / 0 outside. Gap 5 above (the previous FDE pc=0x6379270..0x637930b — the bytes at VA 0x637930b..0x637930f, file offsets 0x637830b..0x637830f, are all 0xcc, five padding bytes) and gap 12 below (the next FDE pc=0x6379810..0x63798ee — the bytes at VA 0x6379804..0x637980f, file offsets 0x6378804..0x637880f, are all 0xcc, twelve padding bytes).
- Duplicate check: live upstream main a8616af9 (verified 2026-11-10 22:35 UTC, 2026-11-11 07:35 KST; this packet was built against a8616af9) — the slug path returns 404; GitHub issue search over open PR titles+bodies: `63a5550` 0 hits; `63a56a5` 0 hits; `63a55df` 0 hits; `634ebb0` 4 hits (#6572, #6573, #6574, #6578) in repo-scoped search (index false negative — the direct pulls scan below finds 120 citations, and the 28 lock-wait family PRs cite it 2 times each); `RE-018` 13 search hits = #6574, #6578, #6573, #6572, #408, #465, #1041, #1035, #550, #3375, #3369, #1267, #1265 (open #6574, #6578, #6573 and #6572, the rest closed; none about this series except #6574, #6578, #6573 and #6572); not a claim; a direct pulls scan of all 592 open PRs finds no other citation: `63a5550` 5 (2 in #6578, 1 in #6574, 1 in #6573, 1 in #6572), `63a56a5` 5 (2 in #6578, 1 in #6574, 1 in #6573, 1 in #6572), `63a55df` 3 (all in #6578), `634ebb0` 120 (14 in #6578 #511 + 15 in #6574 #510 + 17 in #6573 #509 + 18 in #6572 #508 + 2 each in the author's own 28 open lock-wait PRs #5996 #480 + #6000 #481 + #6007 #482 + #6017 #483 + #6025 #484 + #6035 #485 + #6043 #486 + #6050 #487 + #6055 #488 + #6063 #489 + #6072 #490 + #6078 #491 + #6084 #492 + #6087 #493 + #6092 #494 + #6096 #495 + #6156 #496 + #6209 #497 + #6220 #498 + #6227 #499 + #6231 #500 + #6336 #501 + #6339 #502 + #6345 #503 + #6450 #504 + #6455 #505 + #6464 #506 + #6567 #507), `RE-018` 21 (5 in #6578, 5 in #6574, 5 in #6573, 6 in #6572) — the citations live in the author's own prior PRs as cited context; no other PR claims this window; the author-scoped search returns 32 open and 478 closed PRs in this repo; local work-items tree: no other packet claims this window (0 records.json with window fde `0x63a5550..0x63a56a5` besides this one; the FDE range appears only as a survey entry in the lock-wait family records' /survey/second_handler_survivors list — citations, not claims — and the address 63a5550 appears in 44 other records.json survey tables).

- NOT run (declared): no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`.

## Results and limitations

- This is the FIFTH packet of the RE-018 series (second miss handler 0x634ebb0 callers; 8 planned stages). It establishes the first caller with no endbr64 and three rets: a single-slot index lookup that resolves an index to an entry via the handler once, returns the index (ebx) or -1, and advances the context's +8 counter past the resolved index.
- Corrections to #511: NONE — #511's claims about stage 5 verified in full against the stage-5 disassembly and bytes: FDE 0x63a5550..0x63a56a5, 341 B, 99 strict (97 instructions + 2 continuation lines, the split movq at 0x63a5679/0x63a5680 and the split nopl at 0x63a5688/0x63a568f), 3 calls, handler call at 0x63a55df, 3 rets at 0x63a55ff, 0x63a560e and 0x63a569b, endbr64 0, 14 jumps / 0 outside, sha256 0f7ad46aba50388d5db422a641c9b12dde1857eb780a946323626a41f19b070d.
- Unknown: entry inputs' caller-side meaning (rdi's role beyond being passed through to the handler and the 0x636b370 call; rsi's role beyond being passed to the handler as rdx); field semantics of the context at 0x6712130 beyond observed reads/writes (the +8 counter bumped to ebx+1, the +0x10 list head, the +0x18 slot table); the 0x636b0a0's and 0x636b370's semantics beyond their call-site contracts (0x636b370: rdi = entry rdi, rsi = 0x636b0a0's return, edx = 0x93e0, ecx = 0x10); the second handler's semantics beyond its observed body (its table at 0x65096c0, the count at 0x65096b0, the meaning of the 0xffe bound, and the abort path via 0x63bf5b6); what varies across the caller family, and why stage 6 needs three handler calls (the stage-6 question).
- Next question: Stage 6 is FDE 0x6379310..0x6379804 (1268 B, 320 strict), with THREE second-handler call sites (0x63797a1, 0x63797bd, 0x63797f2), 13 calls total, 1 ret at 0x6379617, endbr64 1, 59 jumps / 0 outside — it has a canary (__stack_chk_fail@plt at 0x63797ff) and sched_getcpu@plt at 0x637962a, unlike stages 4–5. What varies across the caller family, and why does stage 6 need three handler calls?

## Integration review qualification

The target was independently authenticated as node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The exact FDE [0x63a5550, 0x63a56a5) and all 341 exported bytes match that artifact. The recorded `strict` value of 99 counts address-bearing disassembly rows, including 2 byte-continuation rows; independent decoding yields 97 actual instructions. Neighboring padding and cited windows are not included in that instruction count. Direct call targets and returns were independently checked. This preserves the original records and raw export, and does not establish a full-component denominator or acceptance gate.
