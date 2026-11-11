# RE-001: lockwait caller 1site resolver noloader dead duff q50x2898

Target identity: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Review correction: the selected FDE `0x639ba40..0x639bd00` contains **186 decoded instructions**; only those instructions are claimed. The retained bytes, FDE boundaries and bounded claims were independently rechecked.

Sixty-fourth packet of the lock-wait-helper-caller frontier (344 survivors; the lu-miss frontier is exhausted 16/16 with #314–#329). FDE 0x639ba40..0x639bd00 (704 B, 186 strict) has one lock-wait site, resolves its entry through a separate resolver callee (0x6388310) WITHOUT loading the entry through the trivial 8-byte load helper (0x63bfb90 is NOT called) and WITHOUT a fixed inline adjust (the resolver-fixed chain, adjusts +0xb8 through +0x380 over #341–#364, ENDS at #364; #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388/#389/#390/#391/#392/#393 add no adjust entry), a 3-value exit 0/1/22, and a Duff's-device copy loop that is FULLY DEAD (its dispatch tail and its 8-at-a-time body are never entered). It rejoins at the trylock-SUCCESS block after lock-wait (like #332/#333/#334/#336/#338/#339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388/#389/#390/#391/#392, unlike #330/#331/#335/#337).

Thin packet: no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`. Every claim below is a direct check over the window disassembly and bytes, quoted with addresses.

## Window

| Field | Value |
|---|---|
| FDE | 0x639ba40..0x639bd00 |
| Bytes | 704 |
| Strict | 186 |
| Lock-wait site | 0x639bb2c |
| Rets | 1 (0x639bae7) |
| bsr | 0 |
| shr | 1 (shr $0x3 at 0x639bb97) |
| shl | 0 |
| endbr64 | 1 (entry at 0x639ba40) |
| Canary | present (2 %fs:0x28 lines; __stack_chk_fail@plt at 0x639bcfb) |
| Jumps | 28 (0 outside) |
| PLT | 3 |
| Prefetch/tzcnt/btc | 0 / 0 / 0 |

## Lock-wait site

| Field | Value |
|---|---|
| Site | 0x639bb2c |
| Setup | lea -0x40(%r15),%rdi at 0x639bb28 |
| rdi def | {0x639bb28} (mutex node 0x6712160 = 0x67121a0 - 0x40) |
| Other argument registers | rsi/rdx/rcx/r8/r9/r10/r11/rax = {CALL(0x639ba7b)} (the trylock clobber); rbx = {0x639ba64} (entry r9 save); rbp = {0x639ba5d} (entry rdi save); r12 = {0x639ba59} (entry rcx save); r13 = {0x639ba54} (entry r8 save); r14 = {0x639ba4f} (entry rsi save); r15 = {0x639ba46} (mutex lea) |
| Predecessors | {0x639ba82} (trylock failed; the nopl at 0x639bb24 is padding after the jmp at 0x639bb22, not a real path) |
| After the call | movb $0x1,0x67121c8 at 0x639bb31 (waited flag set); jmp 0x639ba88 (trylock-SUCCESS block; trylock NOT re-run) |
| Flag clear | movb $0x0,0x67121c8 at 0x639bab4 (while lock held, before unlock) |
| Unlock | pthread_mutex_unlock@plt at 0x639babe |
| Rejoin | trylock-SUCCESS block at 0x639ba88 |

## Resolver

| Field | Value |
|---|---|
| Callee | 0x6388310 (#338's next FDE, 0x6388310..0x6388372, 98 B) |
| Call site | 0x639baf4 |
| Input | *(entry rsi + 0x10) (mov 0x10(%r14),%rdi at 0x639baf0) |
| Result | two-step read: qword at +0x50 (mov 0x50(%rax),%rax at 0x639baf9), then qword at +0x2898 of that entry (mov 0x2898(%rax),%rsi at 0x639bafd), stored to (%rsp) at 0x639bb04 |
| Loader | NONE — 0x63bfb90 is NOT called |
| Adjust | NONE — no fixed inline adjust (no add $imm,%rdi anywhere; shl 0) |
| Count call | NONE — 0x634eba0 is NOT called; the count logic lives inside the resolver |
| Resolver internals | Per #373's read of the resolver body: TLS check at 0x638831b (init via 0x63ef8e0 if unset); reads count struct 0x6712130; returns table[index] where index is 0 for rbx == 0x1000 or rbx == 0x1001 or rbx == count, else rbx+2 |

The stored value is the double-dereferenced entry, not a single direct read: the second load (`mov 0x2898(%rax),%rsi` at 0x639bafd) dereferences the pointer produced by the first load (`mov 0x50(%rax),%rax` at 0x639baf9). The second offset +0x2898 is confirmed by direct census — the slug q50x2898 is correct. It is a disp32 load (`48 8b b0 98 28 00 00`), the fifth large disp32 second load after #389's +0x9380, #390's +0x2880, #391's +0x2888 and #392's +0x2890; unlike the disp8 second loads of #373–#388, the offset is far outside the small-offset range of the earlier packets, but the read is the same two-step shape.

## Selector and copy

The copy IS a Duff's-device loop (0x639bb88..0x639bca7), but it is FULLY DEAD. The length is *r8 (`mov 0x0(%r13),%rdx` at 0x639bb12, r13 = entry r8); if the length is exactly 8, the qword from the stack temp (%rsp) is stored whole to *rcx (`mov %rsi,(%r12)` at 0x639bb1c) and the window exits 0 (`xor %ebp,%ebp` at 0x639bb20). A null dest or null length pointer also exits 0 (`je 0x639bb20` at 0x639bb0b / 0x639bb10). Otherwise n = min(len,8) (`mov $0x8,%ecx` at 0x639bb40, `mov %rsp,%r9` at 0x639bb45, `cmp %rcx,%rdx` at 0x639bb48, `cmova %rcx,%rdx` at 0x639bb4b); len < 8 goes to the small tail (`jb 0x639bcb0` at 0x639bb52), which copies n = len bytes by 4/2/1-byte decomposition (0x639bcb0..0x639bcf9) and exits 22 with *r8 = n. Len > 8 reaches the n == 8 path: `mov %edx,%eax` at 0x639bb58 sets eax = 8; the first qword is stored to dest+0 (`mov %rsi,(%r12)` at 0x639bb5a), `lea 0x8(%r12),%rcx` at 0x639bb5e, re-loaded from src+0 (`mov -0x8(%r9,%rax,1),%rsi` at 0x639bb63 — with eax == 8 reads src+0, not src+8), `and $~7,%rcx` at 0x639bb68, and stored AGAIN to dest+0 (`mov %rsi,-0x8(%r12,%rax,1)` at 0x639bb6c), then r12d = (dest - ((dest+8)&~7) + 8) & ~7 = 0 (`sub %rcx,%r12` at 0x639bb71, `sub %r12,%r9` at 0x639bb74, `add %edx,%r12d` at 0x639bb77, `and $~7,%r12d` at 0x639bb7a), so `cmp $0x8,%r12d` at 0x639bb7e leaves r12d < 8 and the loop-entry jb (`jb 0x639bcc7` at 0x639bb82) is ALWAYS taken to the writeback. The dispatch tail (0x639bb88..0x639bc41, `shr $0x3,%edi` at 0x639bb97 + `and $0x7,%edi` at 0x639bb9e, seven je tail entries for edi 0..6) and the 8-at-a-time body (0x639bc41..0x639bca7, back-edge `jb 0x639bc41` at 0x639bca7) are never entered — the loop's only CFG entry is the fall-through from 0x639bb82 (no jump in the window targets 0x639bb88; the body entry 0x639bc41 is reached only from `je 0x639bc41` at 0x639bbac, the fall-through from 0x639bc3b, and the back-edge at 0x639bca7, all inside the dead region). The writeback stores *r8 = n (`mov %rdx,0x0(%r13)` at 0x639bcc7) and exits 22 (`mov $0x16,%ebp` at 0x639bccb).

## Calls

| Target | Site | PLT |
|---|---|---|
| 0x63f17b0 (pthread_mutex_trylock) | 0x639ba7b | yes |
| 0x6388310 (index resolver) | 0x639baf4 | no |
| 0x63f0b70 (pthread_mutex_unlock) | 0x639babe | yes |
| 0x63bf680 (lock-wait helper) | 0x639bb2c | no |
| 0x63f0d70 (__stack_chk_fail) | 0x639bcfb | yes |

No lu-miss, bin_table_init, second-handler, resolver (0x6365150), count call, loader call, or #314–#392 window calls. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x6388310, 0x63bf680) are NOT PLT stubs. (The `@plt` substring also appears in lea/addq/cmp/mov symbol annotations such as `__register_atfork@plt+0x320610` for the .bss mutex addresses; those are not PLT calls.)

## Shape

The single ret at 0x639bae7 returns eax via a single reaching def, `mov %ebp,%eax` at 0x639badb; ebp's reaching defs are exactly {0x639baa8 (1 — lock acquired, caller condition failed), 0x639bb20 (0 — success), 0x639bccb (22 — copy with length writeback)}, so the three exit values are 0 (success), 1 (lock acquired, caller-side condition failed) and 22 (copy of n = min(len,8) bytes with *r8 = n writeback: len > 8 copies only the first qword twice, n = 8; len < 8 copies via the small tail, n = len). The `mov %edx,%ebp` at 0x639bceb is killed by `mov $0x16,%ebp` at 0x639bccb on its only path (jmp 0x639bcc7 at 0x639bcf9 then the writeback). All paths converge on the flag-clear at 0x639bab4 and the canary-check epilogue at 0x639bac3. This is the TWENTY-SEVENTH frontier window with a FULLY DEAD Duff's-device loop (after #392, the twenty-sixth; 26 windows with unreachable Duff loops #339–#364, #365 with no loop at all, and #366 with a reachable dispatch tail but a value-dead 8-at-a-time body), and like #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388/#389/#390/#391/#392 it resolves its entry through a separate resolver callee (0x6388310) WITHOUT loading the entry through a trivial 8-byte load helper (0x63bfb90 is NOT called) and WITHOUT a fixed inline adjust (the resolver-fixed chain, adjusts +0xb8 through +0x380 over #341–#364, ENDS at #364; #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388/#389/#390/#391/#392/#393 add no adjust entry). It rejoins at the trylock-SUCCESS block after lock-wait (like #332/#333/#334/#336/#338/#339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388/#389/#390/#391/#392, unlike #330/#331/#335/#337). The window has six backward jumps: the exit-0 jmp back to the flag-clear (`jmp 0x639bab4` at 0x639bb22), the lock-wait rejoin (`jmp 0x639ba88` at 0x639bb38), the 8x-body back-edge (`jb 0x639bc41` at 0x639bca7), the exit-22 jmp back to the flag-clear (`jmp 0x639bab4` at 0x639bcd0), and the two small-tail jmps to the writeback (`jmp 0x639bcc7` at 0x639bce9 and 0x639bcf9).

## Verification (direct checks only — thin packet)

- Window bytes: 704 B extracted from `artifacts/node/115/hl-node` at file offset 0x639aa40 (VA 0x639ba40, delta 0x1000, verified against three spot bytes: `e8 30 5d 05 00` at 0x639ba7b, `c3` at 0x639bae7, `e8 70 50 05 00` at 0x639bcfb); first bytes `f3 0f 1e fa` (endbr64), last 5 bytes `e8 70 50 05 00` (call __stack_chk_fail); sha256 `7dc9f8e030ec570b8314f5ba1cde481db8464d71962184b66c4f09bcf25629be`. The `.hex` exhibit is byte-identical to the binary slice.
- Objdump census over the window disassembly (objdump -d of the binary .text, window slice; 186 strict lines): 5 calls, 1 ret, bsr 0, shr 1 (`shr $0x3,%edi` at 0x639bb97), shl 0, endbr64 1, canary 2 %fs:0x28 lines, 28 jumps / 0 outside, 3 PLT calls by `@plt` suffix.
- FDE bounds: `readelf --debug-dump=frames` returns FDE pc=0x639ba40..0x639bd00 directly; the window ends at 0x639bd00, gap 0 to #392's FDE start 0x639bd00 — the 704B regularity holds after #382's 696B break. The window is disjoint from all prior windows: every cited prior range lies outside 0x639ba40..0x639bd00.
- Resolver two-step read verified from the disassembly (`mov 0x50(%rax),%rax` at 0x639baf9, `mov 0x2898(%rax),%rsi` at 0x639bafd, stored to (%rsp) at 0x639bb04) — the stored value is the double-dereferenced entry.
- Fully-dead Duff: r12d == 0 always (dest mod 8 is 0..7, so `(dest - ((dest+8)&~7) + 8) & ~7 == 0`) at the loop-entry jb 0x639bb82, plus the CFG entry check (no jump targets 0x639bb88; preds[0x639bc41] == {0x639bbac, fall-through 0x639bc3b, 0x639bca7}, all inside the dead region).
- Exit reaching-definitions read straight from the disassembly: ebp defs {0x639baa8, 0x639bb20, 0x639bccb} reach `mov %ebp,%eax` at 0x639badb; the `mov %edx,%ebp` at 0x639bceb is overwritten at 0x639bccb on its only path.
- Duplicate check: live upstream main 0781ce04 — the slug path returns 404; GitHub issue search over open PR titles+bodies: `q50x2898` 0 hits; `639ba40` 0 hits; `639bd00` 1 hit, in #4906's (#392's) own body citing this window as its UNCENSUSED next candidate, not a claim — no other PR claims this window; the family search returns 20 open PRs, all the author's own earlier packets (#4707 #373 q50x18, #4709 #374 q50x90, #4717 #375 q50x58, #4719 #376 q50x60, #4723 #377 q50x68, #4746 #378 q50x70, #4783 #379 q50x78, #4846 #380 q50x80, #4853 #381 q50x88, #4857 #382 q50x00, #4859 #383 q50x20, #4863 #384 q50x10, #4867 #385 q50xa8, #4874 #386 q50xb0, #4878 #387 q50x08, #4881 #388 q50xa0, #4885 #389 q50x9380, #4891 #390 q50x2880, #4896 #391 q50x2888, #4906 #392 q50x2890) on different windows; local work-items tree: no other packet claims this window (0 other dirs named `q50x2898`, 0 other records.json with window fde `0x639ba40..0x639bd00`); `639ba40` appears only in survey census tables (e.g. #314 census callers.tsv/lock-sites.tsv listing it as a 1-site survivor), not as a claimed packet window.
- NOT run (declared): no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`.

## Results and limitations

- This is the SIXTY-FOURTH packet of the lock-wait-helper-caller frontier (344 survivors; the lu-miss frontier is exhausted 16/16 with #314–#329). It is the TWENTY-SEVENTH lock-wait window with a FULLY DEAD Duff's-device loop (after #392, the twenty-sixth); like #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388/#389/#390/#391/#392 it resolves its entry through a separate resolver callee (0x6388310) WITHOUT loading the entry through a trivial 8-byte load helper (0x63bfb90 is NOT called) and WITHOUT a fixed inline adjust (the resolver-fixed chain, adjusts +0xb8 through +0x380 over #341–#364, ENDS at #364; #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388/#389/#390/#391/#392/#393 add no adjust entry). It has a 3-value exit 0/1/22. It rejoins at the trylock-SUCCESS block after lock-wait (like #332/#333/#334/#336/#338/#339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388/#389/#390/#391/#392, unlike #330/#331/#335/#337).
- Corrections to #392's pointer for this window: NONE (prior_pointer_verified). #392's pointer made no specific claims about this window — it only recorded the FDE ending at 0x639bd00 as UNCENSUSED (704 B per .eh_frame) and left strict count, calls, lock-wait sites, exit, and resolver offsets to this scout. All of those are now answered by direct census: the window is 0x639ba40..0x639bd00 (704 bytes, 186 strict, 5 calls — trylock, 0x6388310, unlock, lock-wait, stack_chk_fail — 1 lock-wait site at 0x639bb2c, 0 lu-miss / 0 bin_table_init / 0 second-handler sites, 1 ret at 0x639bae7, bsr 0, shr 1, shl 0, endbr64 1, canary present, 28 jumps, 0 outside, 3 PLT calls across 3 targets); the 0x6388310 callee is #338's next FDE; there is no 0x63bfb90 loader call and no fixed inline adjust; the copy loop uses shr $0x3 + and $0x7 dispatch; the exit is 3-valued 0/1/22 (ebp defs at 0x639baa8/0x639bb20/0x639bccb, returned via mov %ebp,%eax at 0x639badb); the Duff loop is FULLY DEAD (r12d == 0 always at the loop-entry jb 0x639bb82, so neither the dispatch tail nor the 8-at-a-time body is ever entered); and the resolver read is a TWO-STEP load (qword at +0x50, then qword at +0x2898 of that entry, stored to (%rsp) at 0x639bb04) — the stored value is the double-dereferenced entry, not a single direct read. The NOT-clean notes were also confirmed: 0x6387880 calls the second handler once (direct objdump call census, site 0x63879c0) and 0x63bcd20 twice (direct objdump call census, sites 0x63bd1e4 and 0x63bd2a2).
- Unknown: entry inputs' caller-side meaning; the field semantics beyond observed reads/writes (including the meaning of the *(entry rsi + 0x10) resolver input); the lock-wait helper's semantics beyond its call-site contract and the body read at 0x63bf680..0x63bf7ee; the contents of the .bss mutex fields; the resolver 0x6388310's semantics beyond its observed call-site contract (its table at 0x6712130+0x18 and the meaning of the 0x1000/0x1001 sentinels).
- Next question: the FDE ending at 0x639ba40 is UNCENSUSED — FDE 0x639b780..0x639ba40 (704 B per .eh_frame) — the #394 scout must census it directly (strict count, calls, lock-wait sites, exit, resolver offsets). The next-largest 1-site candidate 0x6387880 (1,900B) is NOT clean — it calls the second miss handler 0x634ebb0 at 0x63879c0, and 0x63bcd20 (1,428B) calls it twice (direct calls at 0x63bd1e4 and 0x63bd2a2). 0x63c9650 (1,584B) is #321's window (a shared lu-miss + lock-wait FDE, claimed once). Two larger 1-site disjoint survivors exist above the 2000B band (0x63b4b50, 2,770B; 0x63eb870, 2,408B), noted for a possible heavier packet.
