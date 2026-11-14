# RE-018: second handler caller 1site twin 63537f0

Second packet of the second-miss-handler-caller series (RE-018; the handler 0x634ebb0 has 64 call sites across 28 FDEs in the 11-05 frontier census, 10 windows free in the current tree, 8 of them under the 2000B cap, planned as 8 stages; the lu-miss frontier is exhausted 16/16 (all 16 caller variants in the merged tree); the lock-wait series is finished at #507). FDE 0x63537f0..0x63539cf (479 B, 124 strict) is an identical copy of the stage-1 window 0x6353610..0x63537ef, one padding byte below it (gap 1, 0xcc at 0x63537ef). It has the same 10 calls shifted +0x1e0, 1 ret, 25 jumps, no endbr64, no canary. The duplication is flagged honestly here: this is NOT a distinct function — it is the same code at a different address, and it is stage 2, not a separate claim. The next FDE starts at 0x63539d0, one padding byte below this window's end (gap 1, 0xcc at 0x63539cf).

Thin packet: no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`. Every claim below is a direct check over the window disassembly and bytes, quoted with addresses.

## Window

| Field | Value |
|---|---|
| FDE | 0x63537f0..0x63539cf |
| Bytes | 479 |
| Strict | 124 (123 instructions + 1 continuation line: the split `cs nop` at 0x6353896/0x635389d, bytes `66 2e 0f 1f 84 00 00 00 00 00`) |
| Second-handler call site | 0x63539c2 |
| Second-handler tail-jump | 0x635393d |
| Rets | 1 (0x6353803) |
| bsr | 0 |
| shr | 2 (shr $1 at 0x635384d, shr $1 at 0x6353878) |
| shl | 0 |
| endbr64 | 0 |
| Canary | absent (0 %fs:0x28 lines; no __stack_chk_fail call) |
| Jumps | 25 (1 outside) |
| PLT | 1 |
| Prefetch/tzcnt/btc | 0 / 0 / 0 |

## Second-handler site

| Field | Value |
|---|---|
| Call site | 0x63539c2 |
| Setup | lea 0x186af3(%rip),%rdx at 0x63539b6 (# 0x64da4b0); mov %eax,%esi at 0x63539bd; mov %rbp,%rdi at 0x63539bf |
| Target | 0x634ebb0 (FDE 0x634ebb0..0x634eccd, 285 B, 78 strict) |
| Predecessor | the null table slot at 0x63538bd/0x63538c0 (je 0x63539b6 at 0x63538c0) |
| Tail-jump | jmp 0x634ebb0 at 0x635393d (after lea 0x186b79(%rip),%rdx at 0x6353930 and pops at 0x6353937/0x635393a/0x635393b; never returns) |
| Tail-jump predecessor | the table-first-qword check at 0x6353920/0x635392a (je 0x63537fc at 0x635392a when the first qword is non-null) |

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
| 0x63f1ad0 (sched_getcpu) | 0x6353862 | yes |
| 0x6364420 | 0x63538cb | no |
| 0x6364410 | 0x63538d5 | no |
| 0x6364400 | 0x63538e6 | no |
| 0x63edf10 | 0x635390d | no |
| 0x6352fc0 | 0x635394a | no |
| 0x63edf10 | 0x6353985 | no |
| 0x63ec4c0 | 0x6353995 | no |
| 0x6360ed0 | 0x63539ac | no |
| 0x634ebb0 (second miss handler) | 0x63539c2 | no |

No lu-miss, bin_table_init, key-resolver (0x6365150), count call, loader call, or #314–#507 window calls. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x6364420, 0x6364410, 0x6364400, 0x63edf10, 0x6352fc0, 0x63ec4c0, 0x6360ed0, 0x634ebb0) are NOT PLT stubs. (The `@plt` substring also appears in lea/mov symbol annotations such as `__register_atfork@plt+0x10dff0` for the .bss/.data addresses; those are not PLT calls.)

## Shape

Entry: push %r12 at 0x63537f0, push %rbp at 0x63537f2, push %rbx at 0x63537f3; rbx = entry rsi (`mov %rsi,%rbx` at 0x63537f4); rbp = entry rdi (`mov %rdi,%rbp` at 0x635380c). If rsi != 0 the window returns rsi immediately (`mov %rbx,%rax` at 0x63537fc; ret at 0x6353803). Otherwise the byte at rdi+1 selects the path (`cmpb $0x0,0x1(%rdi)` at 0x6353808; jg 0x6353920 at 0x635380f).

Main path (byte at rdi+1 == 0): the qword at +0x90 of the entry struct is loaded (`mov 0x90(%rdi),%rbx` at 0x6353815); if null, je 0x6353948 at 0x635381f takes the 0x6352fc0 path below. Otherwise the count global is read (`lea 0x1ac354(%rip),%r12` at 0x6353825, # 0x64ffb80; `mov (%r12),%esi` at 0x635382c); if the count is <= 2 the window returns early (`cmp $0x2,%esi` at 0x6353830; jbe 0x63537fc at 0x6353833). The field at +0x13450 of the struct is read (`mov 0x13450(%rbx),%ecx` at 0x6353835) and the counter at 0x6511730 is read (`mov 0x1bdeef(%rip),%edx` at 0x635383b). If the count is exactly 4 and the counter is > 1, the counter is halved (`cmp $0x4,%esi` at 0x6353841; jne 0x6353858 at 0x6353844; `cmp $0x1,%edx` at 0x6353846; jbe 0x6353858 at 0x6353849; `mov %edx,%edi` at 0x635384b; `shr $1,%edx` at 0x635384d; `and $0x1,%edi` at 0x635384f; `cmp $0x1,%edi` at 0x6353852; `sbb $0xffffffff,%edx` at 0x6353855). Then `cmp %edx,%ecx` at 0x6353858 (jae 0x63537fc at 0x635385a — early return) and `cmp 0x10(%rbx),%rbp` at 0x635385c (je 0x63537fc at 0x6353860 — early return).

sched_getcpu: call at 0x6353862 returns the cpu in eax. If the count is not 3 (`cmpl $0x3,(%r12)` at 0x6353867; je 0x6353885 at 0x635386c), the cpu is adjusted by the halved counter (`mov 0x1bdebb(%rip),%r8d` at 0x635386e, # 0x6511730; `mov %eax,%r9d` at 0x6353875; `shr $1,%r8d` at 0x6353878; `sub %r8d,%r9d` at 0x635387b; `cmp %r8d,%eax` at 0x635387e; `cmovae %r9d,%eax` at 0x6353881). Then `cmp %eax,0x13450(%rbx)` at 0x6353885; if the adjusted cpu differs from the stored field, jne 0x63538a0 at 0x635388b takes the table-lookup path; if equal, `mov %rbp,0x10(%rbx)` at 0x635388d stores rbp into the struct and the window returns early (jmp 0x63537fc at 0x6353891).

Table lookup (0x63538a0): the qword at +0x90 of the rbp struct is loaded (`mov 0x90(%rbp),%rbx` at 0x63538a0); `cmp 0x13450(%rbx),%eax` at 0x63538a7; if equal, je 0x635388d at 0x63538ad stores rbp and returns early. Otherwise the table at 0x65096c0 is indexed by the adjusted cpu (`mov %eax,%r10d` at 0x63538af; `lea 0x1b5e07(%rip),%r11` at 0x63538b2, # 0x65096c0; `mov (%r11,%r10,8),%r12` at 0x63538b9); if the slot is null (`test %r12,%r12` at 0x63538bd; je 0x63539b6 at 0x63538c0), the handler path below runs.

The 0x63644xx trio (0x63538c6): `xor %esi,%esi` at 0x63538c6; `mov %rbx,%rdi` at 0x63538c8; call 0x6364420 at 0x63538cb; `xor %esi,%esi` at 0x63538d0; `mov %r12,%rdi` at 0x63538d2; call 0x6364410 at 0x63538d5; `mov %r12,0x90(%rbp)` at 0x63538da (the table entry is stored into the rbp struct); `xor %esi,%esi` at 0x63538e1; `mov %rbx,%rdi` at 0x63538e3; call 0x6364400 at 0x63538e6; `test %eax,%eax` at 0x63538eb; if the third call returns 0, je 0x635399f at 0x63538ed takes the 0x6360ed0 path (`mov $0x1,%ecx` at 0x635399f; `xor %edx,%edx` at 0x63539a4; `mov %rbx,%rsi` at 0x63539a6; `mov %rbp,%rdi` at 0x63539a9; call 0x6360ed0 at 0x63539ac; jmp 0x63538f3 at 0x63539b1). Otherwise `cmpb $0x0,0x0(%rbp)` at 0x63538f3; if the byte is 0, je 0x6353912 at 0x63538f7 skips the 0x63edf10 call; else `lea 0x358(%rbp),%rdx` at 0x63538f9, `lea 0x100(%rbp),%rsi` at 0x6353900, `mov %r12,%rcx` at 0x6353907, `mov %rbp,%rdi` at 0x635390a, call 0x63edf10 at 0x635390d. At 0x6353912 the qword at +0x90 of the rbp struct is re-loaded (`mov 0x90(%rbp),%rbx` at 0x6353912) and the window stores rbp and returns early (`jmp 0x635388d` at 0x6353919).

The 0x6352fc0 path (0x6353948, taken when the +0x90 qword of the entry struct is null): `xor %esi,%esi` at 0x6353948; call 0x6352fc0 at 0x635394a (rdi = entry rdi); `mov %rax,%rbx` at 0x6353953; `cmpb $0x0,0x0(%rbp)` at 0x635394f; if the byte is 0, je 0x6353825 at 0x6353956 loops back to the count read. Otherwise `mov 0x128(%rbp),%rax` at 0x635395c; `lea 0x100(%rbp),%rsi` at 0x6353963; `lea 0x358(%rbp),%rdx` at 0x635396a; `test %rax,%rax` at 0x6353971; if the +0x128 qword is null, je 0x635398f at 0x6353974 takes the 0x63ec4c0 call (`mov %rbx,%rcx` at 0x635398f; `mov %rbp,%rdi` at 0x6353992; call 0x63ec4c0 at 0x6353995; jmp 0x6353825 at 0x635399a — loop back); if it equals rbx, je 0x6353825 at 0x6353979 loops back; else `mov %rbx,%rcx` at 0x635397f, `mov %rbp,%rdi` at 0x6353982, call 0x63edf10 at 0x6353985, jmp 0x6353825 at 0x635398a — loop back. So the 0x6352fc0 path retries the count/table lookup at 0x6353825 (four backward jumps: je @0x6353956, je @0x6353979, jmp @0x635398a, jmp @0x635399a).

The tail-jump path (0x6353920, taken when the byte at rdi+1 is > 0): the first qword of the table at 0x65096c0 is loaded (`mov 0x1b5d99(%rip),%rbx` at 0x6353920); if non-null, jne 0x63537fc at 0x635392a returns it; if null, `lea 0x186b79(%rip),%rdx` at 0x6353930 (# 0x64da4b0), pops at 0x6353937/0x635393a/0x635393b, and `jmp 0x634ebb0` at 0x635393d jumps to the second handler and never returns.

The null-slot handler path (0x63539b6, taken when the table slot is null): `lea 0x186af3(%rip),%rdx` at 0x63539b6 (# 0x64da4b0); `mov %eax,%esi` at 0x63539bd; `mov %rbp,%rdi` at 0x63539bf; call 0x634ebb0 at 0x63539c2; `mov %rax,%r12` at 0x63539c7 (the handler's result becomes the table entry); `jmp 0x63538c6` at 0x63539ca enters the trio.

Exit: the single ret at 0x6353803 returns rax via a single reaching def, `mov %rbx,%rax` at 0x63537fc; rbx's reaching defs are exactly {0x63537f4 (entry rsi), 0x6353815 (qword at +0x90 of the entry struct), 0x63538a0 (qword at +0x90 of the rbp struct), 0x6353912 (qword at +0x90 of the rbp struct), 0x6353920 (first qword of table 0x65096c0), 0x6353953 (result of the 0x6352fc0 call)} — so the window returns either its entry rsi, a +0x90 struct qword, the table's first qword, or the 0x6352fc0 result. The tail-jump path at 0x635393d never returns. The window has fourteen backward jumps: jbe @0x6353833, jae @0x635385a, je @0x6353860, jmp @0x6353891, je @0x63538ad, jmp @0x6353919, jne @0x635392a, jmp @0x635393d (outside, to the handler), je @0x6353956, je @0x6353979, jmp @0x635398a, jmp @0x635399a, jmp @0x63539b1 and jmp @0x63539ca.

## Stage 1 (prior packet #508, cited not claimed)

The stage-1 window is FDE 0x6353610..0x63537ef (479 B, 124 strict, sha256 ba90394dd608d031d2d3b3b5b034915a422635a97048899cae8eb6f827fcd344; first bytes `41 54 55 53`, last 5 bytes `e9 f7 fe ff ff` — the same as this window), one padding byte above this window (gap 1, 0xcc at 0x63537ef, file offset 0x63527ef). A direct byte comparison finds 36 raw byte diffs at 18 offset pairs, ALL position-dependent (7 RIP-relative disp32 pairs and 11 rel32 call/jmp pairs), 0 other diffs, and 0 instruction-stream mismatches modulo immediates. The pairs, by instruction (twin addresses):

| Offset pair | Instruction |
|---|---|
| 0x38–0x39 | lea 0x64ffb80 at 0x6353825 (RIP-relative) |
| 0x4d–0x4e | mov 0x6511730 at 0x635383b (RIP-relative) |
| 0x73–0x74 | call sched_getcpu at 0x6353862 (rel32) |
| 0x81–0x82 | mov 0x6511730 at 0x635386e (RIP-relative) |
| 0xc5–0xc6 | lea 0x65096c0 at 0x63538b2 (RIP-relative) |
| 0xdc–0xdd | call 0x6364420 at 0x63538cb (rel32) |
| 0xe6–0xe7 | call 0x6364410 at 0x63538d5 (rel32) |
| 0xf7–0xf8 | call 0x6364400 at 0x63538e6 (rel32) |
| 0x11e–0x11f | call 0x63edf10 at 0x635390d (rel32) |
| 0x133–0x134 | mov 0x65096c0 at 0x6353920 (RIP-relative) |
| 0x143–0x144 | lea 0x64da4b0 at 0x6353930 (RIP-relative) |
| 0x14e–0x14f | jmp 0x634ebb0 at 0x635393d (rel32) |
| 0x15b–0x15c | call 0x6352fc0 at 0x635394a (rel32) |
| 0x196–0x197 | call 0x63edf10 at 0x6353985 (rel32) |
| 0x1a6–0x1a7 | call 0x63ec4c0 at 0x6353995 (rel32) |
| 0x1bd–0x1be | call 0x6360ed0 at 0x63539ac (rel32) |
| 0x1c9–0x1ca | lea 0x64da4b0 at 0x63539b6 (RIP-relative) |
| 0x1d3–0x1d4 | call 0x634ebb0 at 0x63539c2 (rel32) |

Stage 1 has the same 10 calls (sched_getcpu at 0x6353682, 0x6364420 at 0x63536eb, 0x6364410 at 0x63536f5, 0x6364400 at 0x6353706, 0x63edf10 at 0x635372d, 0x6352fc0 at 0x635376a, 0x63edf10 at 0x63537a5, 0x63ec4c0 at 0x63537b5, 0x6360ed0 at 0x63537cc, handler at 0x63537e2), 1 ret at 0x6353623 and 25 jumps. The duplication is flagged honestly here: stage 1 and this window are NOT distinct functions — they are the same code at two addresses.

## Verification (direct checks only — thin packet)

- Window bytes: 479 B extracted from `artifacts/node/115/hl-node` at file offset 0x63527f0 (VA 0x63537f0, delta 0x1000, verified against four spot bytes: `e8 69 e2 09 00` at 0x6353862, `c3` at 0x6353803, `e9 6e b2 ff ff` at 0x635393d, `e8 e9 b1 ff ff` at 0x63539c2); first bytes `41 54 55 53` (push %r12; push %rbp; push %rbx), last 5 bytes `e9 f7 fe ff ff` (jmp 0x63538c6); sha256 `20aa03a8dacc897627c0a8b2d07d127bd5a04aef37b60cf947788edca9b34a97`. The `.hex` exhibit is byte-identical to the binary slice. The delta is 0x1000, NOT 0x10000: the binary slice at file offset 0x63437f0 (VA − 0x10000) does not start `41 54 55 53` — it does not match. File offset is VA − 0x1000 by direct subtraction.
- Objdump census over the window disassembly (objdump -d of the binary .text, window slice; 124 strict lines): 10 calls, 1 ret, bsr 0, shr 2 (`shr $1,%edx` at 0x635384d, `shr $1,%r8d` at 0x6353878), shl 0, endbr64 0, canary 0, 25 jumps / 1 outside, 1 PLT call by `@plt` suffix.
- FDE bounds: `readelf --debug-dump=frames` returns FDE pc=0x63537f0..0x63539cf directly; the window ends at 0x63539cf, gap 1 to the next FDE pc=0x63539d0..0x6353a11 — the byte at VA 0x63539cf (file offset 0x63529cf) is 0xcc, one padding byte. Gap 1 to stage 1 above: the byte at VA 0x63537ef (file offset 0x63527ef) is 0xcc, one padding byte.
- Byte comparison vs stage 1 (36 raw byte diffs at 18 offset pairs, all position-dependent; 0 other diffs; 0 instruction-stream mismatches modulo immediates; same 10 calls shifted +0x1e0, 1 ret at 0x6353803, 25 jumps).
- Handler shape copied from #508's verified handler census (FDE 0x634ebb0..0x634eccd, 285 B, 78 strict, 9 calls, 1 ret at 0x634ec45): trylock on mutex 0x6511700, lock-wait fallback 0x63bf680, counters 0x65116f8/0x65116e8/0x65116f0, cmp ebx,0xffe, table 0x65096c0.
- Exit reaching-definitions read straight from the disassembly: rbx defs {0x63537f4, 0x6353815, 0x63538a0, 0x6353912, 0x6353920, 0x6353953} reach `mov %rbx,%rax` at 0x63537fc; the tail-jump path at 0x635393d never returns.
- Stage 3 NQ pointer censused directly: readelf FDE pc=0x6378120..0x6378364 (580 B); objdump slice 150 strict (147 instructions + 3 continuation lines, split 0x13450-field accesses at 0x63781a6/0x63781ad, 0x63781eb/0x63781f2, 0x63781fc/0x6378203), 10 calls, handler calls at 0x63782c3 and 0x6378357, 1 ret at 0x6378171, endbr64 1 at 0x6378120, 30 jumps / 0 outside.
- Duplicate check: live upstream main a8616af9 (verified 2026-11-10 20:57 UTC, 2026-11-11 05:57 KST; this packet was built against a8616af9) — the slug path returns 404; GitHub issue search over open PR titles+bodies: `63537f0` 1 hit (#6572, the prior stage-1 packet); `63539cf` 1 hit (#6572); `6353610` 1 hit (#6572); `634ebb0` 1 hit (#6572) in repo-scoped search (index false negative — the 28 lock-wait family PRs verified directly below cite it 2 times each); `RE-018` 10 search hits = #6572, #408, #465, #550, #1035, #1041, #1265, #1267, #3369, #3375 (open #6572, the rest closed; none about this series except #6572); not a claim; a direct pulls scan of all 582 open PRs finds no other citation: `63537f0` 11 (all in #6572), `63539cf` 5 (all in #6572), `6353610` 9 (all in #6572), `63537ef` 11 (all in #6572), `634ebb0` 74 (18 in #6572 #508 + 2 each in the author's own 28 open lock-wait PRs #5996 #480 + #6000 #481 + #6007 #482 + #6017 #483 + #6025 #484 + #6035 #485 + #6043 #486 + #6050 #487 + #6055 #488 + #6063 #489 + #6072 #490 + #6078 #491 + #6084 #492 + #6087 #493 + #6092 #494 + #6096 #495 + #6156 #496 + #6209 #497 + #6220 #498 + #6227 #499 + #6231 #500 + #6336 #501 + #6339 #502 + #6345 #503 + #6450 #504 + #6455 #505 + #6464 #506 + #6567 #507), `RE-018` 6 (all in #6572) — the citations live in the author's own prior PRs as cited context; no other PR claims this window; the author-scoped search returns 29 open and 478 closed PRs in this repo; local work-items tree: no other packet claims this window (0 records.json with window fde `0x63537f0..0x63539cf` besides this one; the FDE range appears only as a caller entry in RE-001-node115-lu-opt-leaves-bin-cleanup's bin_setup_52fc0 callers census, site 0x635394a — a citation, not a claim — and the address 63537f0 appears in 48 other records.json census/survey tables; the stage-1 window appears the same way, caller entry site 0x635376a).
- NOT run (declared): no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`.

## Results and limitations

- This is the SECOND packet of the RE-018 series (second miss handler 0x634ebb0 callers; 8 planned stages). It establishes the twin: the stage-1 code exists twice, byte-identical modulo position-dependent immediates only, at 0x6353610 and 0x63537f0.
- Corrections to #508: NONE — #508's claims about the twin verified in full against the twin disassembly and bytes: FDE 0x63537f0..0x63539cf, 479 B, 124 strict, sha256 20aa03a8dacc897627c0a8b2d07d127bd5a04aef37b60cf947788edca9b34a97, first bytes 41 54 55 53, last 5 bytes e9 f7 fe ff ff, 36 raw byte diffs at the 18 offset pairs (all position-dependent, 0 other diffs, 0 instruction-stream mismatches modulo immediates), same 10 calls at the listed sites shifted +0x1e0, 1 ret at 0x6353803, 25 jumps.
- Unknown: entry inputs' caller-side meaning (rdi struct layout beyond the observed +0x1, +0x90, +0x10, +0x100, +0x128, +0x358 reads; rsi's role beyond the non-zero early return); field semantics beyond observed reads/writes (including the meaning of the count at 0x64ffb80, the counter at 0x6511730, and the table at 0x65096c0); the 0x63644xx trio's, 0x63edf10's, 0x6352fc0's, 0x63ec4c0's and 0x6360ed0's semantics beyond their call-site contracts; the second handler's semantics beyond its observed body (its table at 0x65096c0, the count at 0x65096b0, the meaning of the 0xffe bound, and the abort path via 0x63bf5b6); why this function exists twice (stage 1's question, answered only as a claim: it is the same code at a different address, not a distinct function); what varies across the caller family, and why stage 3 calls the handler twice instead of once plus a tail-jump (the stage-3 question).
- Next question: Stage 3 is FDE 0x6378120..0x6378364 (580 B, 150 strict), with TWO second-handler call sites (0x63782c3 and 0x6378357), 1 ret at 0x6378171, endbr64 1 at 0x6378120, 10 calls (including 0x63ec600 at 0x6378148 and sched_getcpu@plt at 0x63781cb), 30 jumps / 0 outside — no tail-jump to the handler, unlike stages 1–2. What varies across the caller family, and why does stage 3 call the handler twice instead of once plus a tail-jump?

## Integration review qualification

The target was independently authenticated as node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The exact FDE [0x63537f0, 0x63539cf) and all 479 exported bytes match that artifact. The recorded `strict` value of 124 counts address-bearing disassembly rows, including 1 byte-continuation rows; independent decoding yields 123 actual instructions. Neighboring padding and cited windows are not included in that instruction count. Direct call targets and returns were independently checked. This preserves the original records and raw export, and does not establish a full-component denominator or acceptance gate.
