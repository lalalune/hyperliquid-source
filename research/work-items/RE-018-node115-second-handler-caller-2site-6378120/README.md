# RE-018: second handler caller 2site 6378120

Third packet of the second-miss-handler-caller series (RE-018; the handler 0x634ebb0 has 64 call sites across 28 FDEs in the 11-05 frontier census, 10 windows free in the current tree, 8 of them under the 2000B cap, planned as 8 stages; the lu-miss frontier is exhausted 16/16 (all 16 caller variants in the merged tree); the lock-wait series is finished at #507). FDE 0x6378120..0x6378364 (580 B, 150 strict) calls the second handler TWICE (0x63782c3 and 0x6378357), with no tail-jump to the handler, unlike stages 1–2. It has endbr64, 10 calls, 1 ret, 30 jumps, and returns 0/1 — not a pointer, unlike stages 1–2 and stage 4. The next FDE starts at 0x6378370, twelve padding bytes below this window's end (gap 12, 0xcc at 0x6378364..0x637836f); the previous FDE ends at 0x637811e, two padding bytes above this window's start (gap 2, 0xcc at 0x637811e..0x637811f).

Thin packet: no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`. Every claim below is a direct check over the window disassembly and bytes, quoted with addresses.

## Window

| Field | Value |
|---|---|
| FDE | 0x6378120..0x6378364 |
| Bytes | 580 |
| Strict | 150 (147 instructions + 3 continuation lines: the split `0x13450`-field accesses at 0x63781a6/0x63781ad, 0x63781eb/0x63781f2, 0x63781fc/0x6378203) |
| Second-handler call sites | 0x63782c3 and 0x6378357 |
| Second-handler tail-jump | none |
| Rets | 1 (0x6378171) |
| bsr | 0 |
| shr | 2 (shr $1 at 0x63781de, shr $1 at 0x6378287) |
| shl | 0 |
| endbr64 | 1 (0x6378120) |
| Canary | absent (0 %fs:0x28 lines; no __stack_chk_fail call) |
| Jumps | 30 (0 outside) |
| PLT | 1 |
| Prefetch/tzcnt/btc | 0 / 0 / 0 |

## Second-handler sites

| Field | Value |
|---|---|
| Call site 1 | 0x63782c3 |
| Setup 1 | lea 0x1621f2(%rip),%rdx at 0x63782b7 (# 0x64da4b0); xor %esi,%esi at 0x63782be; mov %rbx,%rdi at 0x63782c0 |
| Result 1 | mov %rax,%r12 at 0x63782c8; jmp 0x6378296 at 0x63782cb (test %r12,%r12 at 0x6378296; jne 0x6378258 at 0x6378299 when non-null — the 0x6360ed0 path; else xor %eax,%eax at 0x637829b and return 0) |
| Predecessor 1 | the table-first-qword check at 0x63782a8/0x63782b5 (lea 0x65096c0 at 0x63782a8; mov (%rdx),%r12 at 0x63782af; test %r12,%r12 at 0x63782b2; jne 0x6378258 at 0x63782b5 when the first qword is non-null) |
| Call site 2 | 0x6378357 |
| Setup 2 | lea 0x16215e(%rip),%rdx at 0x637834b (# 0x64da4b0); mov %eax,%esi at 0x6378352; mov %rbx,%rdi at 0x6378354 |
| Result 2 | mov %rax,%r13 at 0x637835c; jmp 0x637821c at 0x637835f (the 0x6352f60 call: mov %r13,%rdx at 0x637821c; mov %r12,%rsi at 0x637821f; mov %rbx,%rdi at 0x6378222; call 0x6352f60 at 0x6378225) |
| Predecessor 2 | the null table slot at 0x6378213/0x6378216 (test %r13,%r13 at 0x6378213; je 0x637834b at 0x6378216) |
| Target | 0x634ebb0 (FDE 0x634ebb0..0x634eccd, 285 B, 78 strict) |

The two sites differ in their arguments and continuations: site 1 passes esi = 0 (the table-first-qword-null path) and its result is checked for null before the 0x6360ed0 path; site 2 passes esi = eax (the adjusted cpu, the table-slot-null path) and its result feeds the 0x6352f60 call. Both calls return — there is no tail-jump, because this window's exit is a 0/1 return through the single epilogue at 0x6378167 and both paths must continue inside the window after the handler returns.

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
| 0x63ec600 | 0x6378148 | no |
| 0x63f1ad0 (sched_getcpu) | 0x63781cb | yes |
| 0x6352f60 | 0x6378225 | no |
| 0x63edf10 | 0x6378243 | no |
| 0x6360ed0 | 0x6378265 | no |
| 0x634ebb0 (second miss handler) | 0x63782c3 | no |
| 0x6352fc0 | 0x63782d5 | no |
| 0x63edf10 | 0x6378307 | no |
| 0x63ec4c0 | 0x6378344 | no |
| 0x634ebb0 (second miss handler) | 0x6378357 | no |

No lu-miss, bin_table_init, key-resolver (0x6365150), count call, loader call, 0x63644xx trio, or #314–#509 window calls. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x63ec600, 0x6352f60, 0x63edf10, 0x6360ed0, 0x634ebb0, 0x6352fc0, 0x63ec4c0) are NOT PLT stubs. (The `@plt` substring also appears in lea/mov symbol annotations such as `__register_atfork@plt+0x11fba0` for the .bss/.data addresses; those are not PLT calls.)

## Shape

Entry: endbr64 at 0x6378120; push %r13 at 0x6378124, mov $0x1,%eax at 0x6378126, push %r12 at 0x637812b, push %rbp at 0x637812d, push %rbx at 0x637812e, sub $0x8,%rsp at 0x637812f. The OR gate: `or 0x30(%rsp),%r9` at 0x6378133 (the 7th stack argument), `or %r9,%r8` at 0x6378138, `or %r8,%rcx` at 0x637813b; if any of rcx/r8/r9/the 7th argument is non-zero, jne 0x6378167 at 0x637813e returns 1 immediately (the epilogue at 0x6378167: add $0x8,%rsp; pops; ret at 0x6378171).

The 0x63ec600 gate: `cmpb $0x0,(%rdi)` at 0x6378140; `mov %rdi,%rbx` at 0x6378143; if the byte at rdi is 0, je 0x637814d at 0x6378146 skips the call; else call 0x63ec600 at 0x6378148 (rdi = entry rdi).

Counter pre-check: `lea 0x1995dc(%rip),%rbp` at 0x637814d (# 0x6511730); `lea 0x1995d9(%rip),%rdx` at 0x6378154 (# 0x6511734); `mov 0x0(%rbp),%edi` at 0x637815b; `lea (%rdi,%rdi,1),%ecx` at 0x637815e (ecx = 2*edi); `cmp (%rdx),%ecx` at 0x6378161; if 2*edi < *(0x6511734), jb 0x6378178 at 0x6378163 enters the main body; otherwise `xor %eax,%eax` at 0x6378165 and the epilogue returns 0.

Main path (0x6378178): the byte at rdi+1 selects the path (`cmpb $0x0,0x1(%rbx)` at 0x6378178; jg 0x63782a8 at 0x637817c — byte > 0 takes the table-first-qword path below). Otherwise the qword at +0x90 of the entry struct is loaded (`mov 0x90(%rbx),%r12` at 0x6378182); if null, je 0x63782d0 at 0x637818c takes the 0x6352fc0 path below. Otherwise the count global is read (`lea 0x1879e7(%rip),%r13` at 0x6378192, # 0x64ffb80; `mov 0x0(%r13),%esi` at 0x6378199); if the count is <= 2 the window takes the 0x6360ed0 path (`cmp $0x2,%esi` at 0x637819d; jbe 0x6378258 at 0x63781a0). The field at +0x13450 of the struct is read (`mov 0x13450(%r12),%r8d` at 0x63781a6); if the count is exactly 4, je 0x6378278 at 0x63781b1 takes the count==4 path below. Then `cmp %edi,%r8d` at 0x63781b7 (jae 0x6378258 at 0x63781ba — the 0x6360ed0 path) and `cmp 0x10(%r12),%rbx` at 0x63781c0 (je 0x6378258 at 0x63781c5 — the 0x6360ed0 path).

sched_getcpu: call at 0x63781cb returns the cpu in eax. If the count is not 3 (`cmpl $0x3,0x0(%r13)` at 0x63781d0; je 0x63781eb at 0x63781d5), the cpu is adjusted by the halved counter (`mov 0x0(%rbp),%r10d` at 0x63781d7, # 0x6511730; `mov %eax,%r11d` at 0x63781db; `shr $1,%r10d` at 0x63781de; `sub %r10d,%r11d` at 0x63781e1; `cmp %r10d,%eax` at 0x63781e4; `cmovae %r11d,%eax` at 0x63781e7). Then `cmp %eax,0x13450(%r12)` at 0x63781eb; if the adjusted cpu equals the stored field, je 0x637824f at 0x63781f3 stores rbp into the struct (`mov %rbx,0x10(%r12)` at 0x637824f) and falls into the 0x6360ed0 path.

Table lookup (0x63781f5): the qword at +0x90 of the rbx struct is loaded (`mov 0x90(%rbx),%r12` at 0x63781f5); `cmp 0x13450(%r12),%eax` at 0x63781fc; if equal, je 0x637824f at 0x6378204 stores rbx and takes the 0x6360ed0 path. Otherwise the table at 0x65096c0 is indexed by the adjusted cpu (`lea 0x1914b3(%rip),%rcx` at 0x6378206, # 0x65096c0; `mov %eax,%ebp` at 0x637820d; `mov (%rcx,%rbp,8),%r13` at 0x637820f); if the slot is null (`test %r13,%r13` at 0x6378213; je 0x637834b at 0x6378216), the handler path below runs.

The 0x6352f60 call (0x637821c): `mov %r13,%rdx` at 0x637821c; `mov %r12,%rsi` at 0x637821f; `mov %rbx,%rdi` at 0x6378222; call 0x6352f60 at 0x6378225. Then `cmpb $0x0,(%rbx)` at 0x637822a; if the byte is 0, je 0x6378248 at 0x637822d skips the 0x63edf10 call; else `lea 0x358(%rbx),%rdx` at 0x637822f, `lea 0x100(%rbx),%rsi` at 0x6378236, `mov %r13,%rcx` at 0x637823d, `mov %rbx,%rdi` at 0x6378240, call 0x63edf10 at 0x6378243. At 0x6378248 the qword at +0x90 of the rbx struct is re-loaded (`mov 0x90(%rbx),%r12` at 0x6378248) and the window stores rbx and falls through to 0x637824f, then takes the 0x6360ed0 path at 0x6378258.

The 0x6360ed0 path (0x6378258, the common exit funnel): `mov $0x1,%ecx` at 0x6378258; `xor %edx,%edx` at 0x637825d; `mov %r12,%rsi` at 0x637825f; `mov %rbx,%rdi` at 0x6378262; call 0x6360ed0 at 0x6378265; `xor %eax,%eax` at 0x637826a; `jmp 0x6378167` at 0x637826c — the epilogue returns 0.

The count==4 path (0x6378278): `cmp $0x1,%edi` at 0x6378278; if the counter is <= 1, jbe 0x63781b7 at 0x637827b goes back to the `cmp %edi,%r8d` check. Otherwise the counter is halved, rounding up (`mov %edi,%r9d` at 0x6378281; `and $0x1,%edi` at 0x6378284; `shr $1,%r9d` at 0x6378287; `add %r9d,%edi` at 0x637828a — edi = (counter>>1) + (counter&1) = ceil(counter/2), the same ceil stages 1–2 computed with shr + sbb); `cmp %r8d,%edi` at 0x637828d; if the halved counter exceeds the stored field, ja 0x63781c0 at 0x6378290 goes back to the `cmp 0x10(%r12),%rbx` check. At 0x6378296 the qword at +0x90 is tested (`test %r12,%r12` at 0x6378296); if non-null, jne 0x6378258 at 0x6378299 takes the 0x6360ed0 path; if null, `xor %eax,%eax` at 0x637829b and `jmp 0x6378167` at 0x637829d return 0.

The table-first-qword path (0x63782a8, taken when the byte at rdi+1 is > 0): the first qword of the table at 0x65096c0 is loaded (`lea 0x191411(%rip),%rdx` at 0x63782a8; `mov (%rdx),%r12` at 0x63782af); if non-null, jne 0x6378258 at 0x63782b5 takes the 0x6360ed0 path; if null, `lea 0x1621f2(%rip),%rdx` at 0x63782b7 (# 0x64da4b0), `xor %esi,%esi` at 0x63782be, `mov %rbx,%rdi` at 0x63782c0, and call 0x634ebb0 at 0x63782c3 — handler call site 1 (esi = 0). The handler's result becomes the table entry (`mov %rax,%r12` at 0x63782c8) and `jmp 0x6378296` at 0x63782cb re-enters the count==4 path's tail (test r12; non-null → 0x6360ed0 path; null → return 0).

The 0x6352fc0 path (0x63782d0, taken when the +0x90 qword of the entry struct is null): `xor %esi,%esi` at 0x63782d0; `mov %rbx,%rdi` at 0x63782d2; call 0x6352fc0 at 0x63782d5 (rdi = entry rdi); `cmpb $0x0,(%rbx)` at 0x63782da; `mov %rax,%r12` at 0x63782dd; if the byte is 0, je 0x637830c at 0x63782e0 takes the count re-read block A below. Otherwise `mov 0x128(%rbx),%rax` at 0x63782e2; `lea 0x100(%rbx),%rsi` at 0x63782e9; `lea 0x358(%rbx),%rdx` at 0x63782f0; `test %rax,%rax` at 0x63782f7; if the +0x128 qword is null, je 0x637833e at 0x63782fa takes the 0x63ec4c0 call (`mov %r12,%rcx` at 0x637833e; `mov %rbx,%rdi` at 0x6378341; call 0x63ec4c0 at 0x6378344; jmp 0x637830c at 0x6378349 — loop back to re-read A); if it equals r12, je 0x6378328 at 0x63782ff takes re-read block B; else `mov %r12,%rcx` at 0x6378301, `mov %rbx,%rdi` at 0x6378304, call 0x63edf10 at 0x6378307, and fall through to re-read A. Re-read A (0x637830c): `lea 0x18786d(%rip),%r13` at 0x637830c (# 0x64ffb80); `mov 0x0(%r13),%esi` at 0x6378313; `cmp $0x2,%esi` at 0x6378317; if the count is <= 2, jbe 0x6378296 at 0x637831a goes to the test-r12/return-0 tail; `mov 0x0(%rbp),%edi` at 0x6378320; `jmp 0x63781a6` at 0x6378323 loops back to the 0x13450 read. Re-read B (0x6378328): `lea 0x187851(%rip),%r13` at 0x6378328 (# 0x64ffb80); `mov 0x0(%r13),%esi` at 0x637832f; `cmp $0x2,%esi` at 0x6378333; if the count is <= 2, jbe 0x6378258 at 0x6378336 takes the 0x6360ed0 path; `jmp 0x6378320` at 0x637833c joins re-read A.

The null-slot handler path (0x637834b, taken when the table slot is null): `lea 0x16215e(%rip),%rdx` at 0x637834b (# 0x64da4b0); `mov %eax,%esi` at 0x6378352; `mov %rbx,%rdi` at 0x6378354; call 0x634ebb0 at 0x6378357 — handler call site 2 (esi = the adjusted cpu); `mov %rax,%r13` at 0x637835c (the handler's result becomes the table entry); `jmp 0x637821c` at 0x637835f enters the 0x6352f60 call.

Exit: the single ret at 0x6378171 returns rax via the single epilogue at 0x6378167; rax's reaching defs are exactly {0x6378126 (mov $0x1,%eax — the OR-gate early return), 0x6378165 (xor %eax,%eax — the counter pre-check), 0x637826a (xor %eax,%eax — the 0x6360ed0 path), 0x637829b (xor %eax,%eax — the count==4 tail)} — so the window returns 1 only when an entry argument is non-zero, and 0 on every other path. The window has thirteen backward jumps: jmp @0x637826c, jbe @0x637827b, ja @0x6378290, jne @0x6378299, jmp @0x637829d, jne @0x63782b5, jmp @0x63782cb, jbe @0x637831a, jmp @0x6378323, jbe @0x6378336, jmp @0x637833c, jmp @0x6378349 and jmp @0x637835f.

## Stage 2 (prior packet #509, cited not claimed)

The stage-2 window is FDE 0x63537f0..0x63539cf (479 B, 124 strict, sha256 20aa03a8dacc897627c0a8b2d07d127bd5a04aef37b60cf947788edca9b34a97; first bytes `41 54 55 53`, last 5 bytes `e9 f7 fe ff ff`), the identical twin of the stage-1 window 0x6353610..0x63537ef. It has the same 10 calls shifted +0x1e0 (sched_getcpu at 0x6353862, 0x6364420 at 0x63538cb, 0x6364410 at 0x63538d5, 0x6364400 at 0x63538e6, 0x63edf10 at 0x635390d, 0x6352fc0 at 0x635394a, 0x63edf10 at 0x6353985, 0x63ec4c0 at 0x6353995, 0x6360ed0 at 0x63539ac, handler at 0x63539c2), 1 ret at 0x6353803 and 25 jumps, and returns a pointer (rbx reaching defs {0x63537f4, 0x6353815, 0x63538a0, 0x6353912, 0x6353920, 0x6353953}) — unlike this window, which returns 0/1.

## Verification (direct checks only — thin packet)

- Window bytes: 580 B extracted from `artifacts/node/115/hl-node` at file offset 0x6377120 (VA 0x6378120, delta 0x1000, verified against five spot bytes: `e8 b3 44 07 00` at 0x6378148, `e8 00 99 07 00` at 0x63781cb, `c3` at 0x6378171, `e8 e8 68 fd ff` at 0x63782c3, `e8 54 68 fd ff` at 0x6378357); first bytes `f3 0f 1e fa` (endbr64), last 5 bytes `e9 b8 fe ff ff` (jmp 0x637821c); sha256 `ef3f718eea8e415993da716c95f520d8f53194e073edffa92b84b869ef188103`. The `.hex` exhibit is byte-identical to the binary slice. The delta is 0x1000, NOT 0x10000: the binary slice at file offset 0x6368120 (VA − 0x10000) does not start `f3 0f 1e fa` — it does not match. File offset is VA − 0x1000 by direct subtraction.
- Objdump census over the window disassembly (objdump -d of the binary .text, window slice; 150 strict lines): 10 calls, 1 ret, bsr 0, shr 2 (`shr $1,%r10d` at 0x63781de, `shr $1,%r9d` at 0x6378287), shl 0, endbr64 1, canary 0, 30 jumps / 0 outside, 1 PLT call by `@plt` suffix.
- FDE bounds: `readelf --debug-dump=frames` returns FDE pc=0x6378120..0x6378364 directly; the window ends at 0x6378364, gap 12 to the next FDE pc=0x6378370..0x63783ee — the bytes at VA 0x6378364..0x637836f (file offsets 0x6377364..0x637736f) are all 0xcc, twelve padding bytes. Gap 2 above: the previous FDE is pc=0x63780a0..0x637811e — the bytes at VA 0x637811e..0x637811f (file offsets 0x637711e..0x637711f) are both 0xcc, two padding bytes.
- Handler shape copied from #508's verified handler census (FDE 0x634ebb0..0x634eccd, 285 B, 78 strict, 9 calls, 1 ret at 0x634ec45): trylock on mutex 0x6511700, lock-wait fallback 0x63bf680, counters 0x65116f8/0x65116e8/0x65116f0, cmp ebx,0xffe, table 0x65096c0.
- Exit reaching-definitions read straight from the disassembly: rax defs {0x6378126, 0x6378165, 0x637826a, 0x637829b} reach the single ret at 0x6378171 via the epilogue at 0x6378167; the window returns 1 only on the OR-gate early return and 0 on every other path.
- Stage 4 NQ pointer censused directly: readelf FDE pc=0x6364790..0x6364877 (231 B); objdump slice 54 strict (52 instructions + 2 continuation lines, the split nopl at 0x63647b8/0x63647bf and the split nopw at 0x6364847/0x636484e), 3 calls, handler call at 0x636485c, 1 ret at 0x63647b7, endbr64 1 at 0x6364790, 7 jumps / 0 outside, 4 backward jumps.
- Duplicate check: live upstream main a8616af9 (verified 2026-11-10 21:29 UTC, 2026-11-11 06:29 KST; this packet was built against a8616af9) — the slug path returns 404; GitHub issue search over open PR titles+bodies: `6378120` 0 hits; `6378364` 0 hits; `63782c3` 0 hits; `6378357` 0 hits; `634ebb0` 2 hits (#6572, #6573) in repo-scoped search (index false negative — the direct pulls scan below finds 91 citations, and the 28 lock-wait family PRs cite it 2 times each); `RE-018` 11 search hits = #6573, #6572, #408, #465, #1041, #1035, #550, #3375, #3369, #1267, #1265 (open #6573 and #6572, the rest closed; none about this series except #6573 and #6572); not a claim; a direct pulls scan of all 583 open PRs finds no other citation: `6378120` 4 (3 in #6573, 1 in #6572), `6378364` 3 (2 in #6573, 1 in #6572), `63782c3` 2 (all in #6573), `6378357` 2 (all in #6573), `634ebb0` 91 (17 in #6573 #509 + 18 in #6572 #508 + 2 each in the author's own 28 open lock-wait PRs #5996 #480 + #6000 #481 + #6007 #482 + #6017 #483 + #6025 #484 + #6035 #485 + #6043 #486 + #6050 #487 + #6055 #488 + #6063 #489 + #6072 #490 + #6078 #491 + #6084 #492 + #6087 #493 + #6092 #494 + #6096 #495 + #6156 #496 + #6209 #497 + #6220 #498 + #6227 #499 + #6231 #500 + #6336 #501 + #6339 #502 + #6345 #503 + #6450 #504 + #6455 #505 + #6464 #506 + #6567 #507), `RE-018` 11 (5 in #6573, 6 in #6572) — the citations live in the author's own prior PRs as cited context; no other PR claims this window; the author-scoped search returns 30 open and 478 closed PRs in this repo; local work-items tree: no other packet claims this window (0 records.json with window fde `0x6378120..0x6378364` besides this one; the FDE range appears only as caller entries in RE-001-node115-lu-opt-leaves-bin-cleanup's callees censuses — site 0x63782d5 in bin_setup_52fc0 and site 0x6378225 in bin_setup_52f60 — citations, not claims — and the address 6378120 appears in 45 other records.json census/survey tables; the stage-2 window appears the same way, caller entry site 0x635394a).

- NOT run (declared): no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`.

## Results and limitations

- This is the THIRD packet of the RE-018 series (second miss handler 0x634ebb0 callers; 8 planned stages). It establishes the first handler-twice caller: stage 3 calls the handler from two distinct control-flow positions with different arguments (esi = 0 at 0x63782c3, esi = the adjusted cpu at 0x6378357) and different continuations — and, unlike stages 1–2, both calls return, because the window's exit is a 0/1 return through one epilogue and both paths must continue inside the window.
- Corrections to #509: NONE — #509's claims about stage 3 verified in full against the stage-3 disassembly and bytes: FDE 0x6378120..0x6378364, 580 B, 150 strict (147 instructions + 3 continuation lines, the split 0x13450-field accesses at 0x63781a6/0x63781ad, 0x63781eb/0x63781f2, 0x63781fc/0x6378203), 10 calls, handler calls at 0x63782c3 and 0x6378357, 1 ret at 0x6378171, endbr64 1 at 0x6378120, 30 jumps / 0 outside, 0x63ec600 at 0x6378148 and sched_getcpu@plt at 0x63781cb.
- Unknown: entry inputs' caller-side meaning (rdi struct layout beyond the observed +0x1, +0x90, +0x10, +0x100, +0x128, +0x358 reads; the roles of rcx/r8/r9 and the 7th stack argument beyond the OR-gate early return); field semantics beyond observed reads/writes (including the meaning of the count at 0x64ffb80, the counter pair at 0x6511730/0x6511734, and the table at 0x65096c0); the 0x63ec600's, 0x6352f60's, 0x63edf10's, 0x6352fc0's, 0x63ec4c0's and 0x6360ed0's semantics beyond their call-site contracts; the second handler's semantics beyond its observed body (its table at 0x65096c0, the count at 0x65096b0, the meaning of the 0xffe bound, and the abort path via 0x63bf5b6); what varies across the caller family, and why stage 4 needs only one handler call (the stage-4 question).
- Next question: Stage 4 is FDE 0x6364790..0x6364877 (231 B, 54 strict), with ONE second-handler call site (0x636485c), 3 calls total (0x63c03f0 at 0x6364805 and 0x636483d, handler at 0x636485c), 1 ret at 0x63647b7, endbr64 1 at 0x6364790, 7 jumps / 0 outside — no sched_getcpu, no 0x6352fc0, no trio, and it returns a table entry (mov %rbx,%rax at 0x63647b3), not 0/1. What varies across the caller family, and why does the smallest caller need only one handler call?
