# RE-001: lockwait caller 1site resolver noloader dead duff q50xa0

Target identity: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

Review correction: the selected FDE `0x639c800..0x639cac0` contains **186 decoded instructions**; only those instructions are claimed. The retained bytes, FDE boundaries and bounded claims were independently rechecked.

Fifty-ninth packet of the lock-wait-helper-caller frontier (344 survivors; the lu-miss frontier is exhausted 16/16 with #314–#329). FDE 0x639c800..0x639cac0 (704 B, 186 strict) has one lock-wait site, resolves its entry through a separate resolver callee (0x6388310) WITHOUT loading the entry through the trivial 8-byte load helper (0x63bfb90 is NOT called) and WITHOUT a fixed inline adjust (the resolver-fixed chain, adjusts +0xb8 through +0x380 over #341–#364, ENDS at #364; #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388 add no adjust entry), a 3-value exit 0/1/22, and a Duff's-device copy loop that is FULLY DEAD (its dispatch tail and its 8-at-a-time body are never entered). It rejoins at the trylock-SUCCESS block after lock-wait (like #332/#333/#334/#336/#338/#339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387, unlike #330/#331/#335/#337).

Thin packet: no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`. Every claim below is a direct check over the window disassembly and bytes, quoted with addresses.

## Window

| Field | Value |
|---|---|
| FDE | 0x639c800..0x639cac0 |
| Bytes | 704 |
| Strict | 186 |
| Lock-wait site | 0x639c8ec |
| Rets | 1 (0x639c8a7) |
| bsr | 0 |
| shr | 1 (shr $0x3 at 0x639c957) |
| shl | 0 |
| endbr64 | 1 (entry at 0x639c800) |
| Canary | present (2 %fs:0x28 lines; __stack_chk_fail@plt at 0x639cabb) |
| Jumps | 28 (0 outside) |
| PLT | 3 |
| Prefetch/tzcnt/btc | 0 / 0 / 0 |

## Lock-wait site

| Field | Value |
|---|---|
| Site | 0x639c8ec |
| Setup | lea -0x40(%r15),%rdi at 0x639c8e8 |
| rdi def | {0x639c8e8} (mutex node 0x6712160 = 0x67121a0 - 0x40) |
| Other argument registers | rsi/rdx/rcx/r8/r9/r10/r11/rax = {CALL(0x639c83b)} (the trylock clobber); rbx = {0x639c824} (entry r9 save); rbp = {0x639c81d} (entry rdi save); r12 = {0x639c819} (entry rcx save); r13 = {0x639c814} (entry r8 save); r14 = {0x639c80f} (entry rsi save); r15 = {0x639c806} (mutex lea) |
| Predecessors | {0x639c842} (trylock failed; the nopl at 0x639c8fd is padding after the jmp at 0x639c8e2, not a real path) |
| After the call | movb $0x1,0x67121c8 at 0x639c8f1 (waited flag set); jmp 0x639c848 (trylock-SUCCESS block; trylock NOT re-run) |
| Flag clear | movb $0x0,0x67121c8 at 0x639c874 (while lock held, before unlock) |
| Unlock | pthread_mutex_unlock@plt at 0x639c87e |
| Rejoin | trylock-SUCCESS block at 0x639c848 |

## Resolver

| Field | Value |
|---|---|
| Callee | 0x6388310 (#338's next FDE, 0x6388310..0x6388372, 98 B) |
| Call site | 0x639c8b4 |
| Input | *(entry rsi + 0x10) (mov 0x10(%r14),%rdi at 0x639c8b0) |
| Result | two-step read: qword at +0x50 (mov 0x50(%rax),%rax at 0x639c8b9), then qword at +0xa0 of that entry (mov 0xa0(%rax),%rsi at 0x639c8bd), stored to (%rsp) at 0x639c8c4 |
| Loader | NONE — 0x63bfb90 is NOT called |
| Adjust | NONE — no fixed inline adjust (no add $imm,%rdi anywhere; shl 0) |
| Count call | NONE — 0x634eba0 is NOT called; the count logic lives inside the resolver |
| Resolver internals | Per #373's read of the resolver body: TLS check at 0x638831b (init via 0x63ef8e0 if unset); reads count struct 0x6712130; returns table[index] where index is 0 for rbx == 0x1000 or rbx == 0x1001 or rbx == count, else rbx+2 |

The stored value is the double-dereferenced entry, not a single direct read: the second load (`mov 0xa0(%rax),%rsi` at 0x639c8bd) dereferences the pointer produced by the first load (`mov 0x50(%rax),%rax` at 0x639c8b9). The second offset +0xa0 is confirmed by direct census — the slug q50xa0 is correct.

## Selector and copy

The copy IS a Duff's-device loop (0x639c948..0x639ca67), but it is FULLY DEAD. The length is *r8 (`mov 0x0(%r13),%rdx` at 0x639c8d2, r13 = entry r8); if the length is exactly 8, the qword from the stack temp (%rsp) is stored whole to *rcx (`mov %rsi,(%r12)` at 0x639c8dc) and the window exits 0 (`xor %ebp,%ebp` at 0x639c8e0). A null dest or null length pointer also exits 0 (`je 0x639c8e0` at 0x639c8c8 / 0x639c8d0). Otherwise n = min(len,8) (`mov $0x8,%ecx` at 0x639c900, `mov %rsp,%r9` at 0x639c905, `cmp %rcx,%rdx` at 0x639c908, `cmova %rcx,%rdx` at 0x639c90b); len < 8 goes to the small tail (`jb 0x639ca70` at 0x639c912), which copies n = len bytes by 4/2/1-byte decomposition (0x639ca70..0x639cab9) and exits 22 with *r8 = n. Len > 8 reaches the n == 8 path: the first qword is stored to dest+0 (`mov %rsi,(%r12)` at 0x639c91a), re-loaded from src+0 (`mov -0x8(%r9,%rax,1),%rsi` at 0x639c923 — with eax == 8 reads src+0, not src+8), and stored AGAIN to dest+0 (`mov %rsi,-0x8(%r12,%rax,1)` at 0x639c92c), then r12d = (dest - ((dest+8)&~7) + 8) & ~7 = 0 (`lea 0x8(%r12),%rcx` at 0x639c91e, `and $~7,%rcx` at 0x639c928, `sub %rcx,%r12` at 0x639c931, `sub %r12,%r9` at 0x639c934, `add %edx,%r12d` at 0x639c937, `and $~7,%r12d` at 0x639c93a), so `cmp $0x8,%r12d` at 0x639c93e leaves r12d < 8 and the loop-entry jb (`jb 0x639ca87` at 0x639c942) is ALWAYS taken to the writeback. The dispatch tail (0x639c948..0x639ca01, `shr $0x3,%edi` at 0x639c957 + `and $0x7,%edi` at 0x639c95e, seven je tail entries for edi 0..6) and the 8-at-a-time body (0x639ca01..0x639ca67, back-edge `jb 0x639ca01` at 0x639ca67) are never entered — the loop's only CFG entry is the fall-through from 0x639c942 (no jump in the window targets 0x639c948; the body entry 0x639ca01 is reached only from `je 0x639ca01` at 0x639c96c, the fall-through from 0x639c9fb, and the back-edge at 0x639ca67, all inside the dead region). The writeback stores *r8 = n (`mov %rdx,0x0(%r13)` at 0x639ca87) and exits 22 (`mov $0x16,%ebp` at 0x639ca8b).

## Calls

| Target | Site | PLT |
|---|---|---|
| 0x63f17b0 (pthread_mutex_trylock) | 0x639c83b | yes |
| 0x6388310 (index resolver) | 0x639c8b4 | no |
| 0x63f0b70 (pthread_mutex_unlock) | 0x639c87e | yes |
| 0x63bf680 (lock-wait helper) | 0x639c8ec | no |
| 0x63f0d70 (__stack_chk_fail) | 0x639cabb | yes |

No lu-miss, bin_table_init, second-handler, resolver (0x6365150), count call, loader call, or #314–#387 window calls. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x6388310, 0x63bf680) are NOT PLT stubs. (The `@plt` substring also appears in lea/addq/cmp/mov symbol annotations such as `__register_atfork@plt+0x320610` for the .bss mutex addresses; those are not PLT calls.)

## Shape

The single ret at 0x639c8a7 returns eax via a single reaching def, `mov %ebp,%eax` at 0x639c89b; ebp's reaching defs are exactly {0x639c868 (1 — lock acquired, caller condition failed), 0x639c8e0 (0 — success), 0x639ca8b (22 — copy with length writeback)}, so the three exit values are 0 (success), 1 (lock acquired, caller-side condition failed) and 22 (copy of n = min(len,8) bytes with *r8 = n writeback: len > 8 copies only the first qword twice, n = 8; len < 8 copies via the small tail, n = len). The `mov %edx,%ebp` at 0x639caab is killed by `mov $0x16,%ebp` at 0x639ca8b on its only path (jmp 0x639ca87 at 0x639cab9 then the writeback). All paths converge on the flag-clear at 0x639c874 and the canary-check epilogue at 0x639c883. This is the TWENTY-SECOND frontier window with a FULLY DEAD Duff's-device loop (after #387, the twenty-first; 26 windows with unreachable Duff loops #339–#364, #365 with no loop at all, and #366 with a reachable dispatch tail but a value-dead 8-at-a-time body), and like #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387 it resolves its entry through a separate resolver callee (0x6388310) WITHOUT loading the entry through a trivial 8-byte load helper (0x63bfb90 is NOT called) and WITHOUT a fixed inline adjust (the resolver-fixed chain, adjusts +0xb8 through +0x380 over #341–#364, ENDS at #364; #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388 add no adjust entry). It rejoins at the trylock-SUCCESS block after lock-wait (like #332/#333/#334/#336/#338/#339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387, unlike #330/#331/#335/#337). The window has six backward jumps: the exit-0 jmp back to the flag-clear (`jmp 0x639c874` at 0x639c8e2), the lock-wait rejoin (`jmp 0x639c848` at 0x639c8f8), the 8x-body back-edge (`jb 0x639ca01` at 0x639ca67), the exit-22 jmp back to the flag-clear (`jmp 0x639c874` at 0x639ca90), and the two small-tail jmps to the writeback (`jmp 0x639ca87` at 0x639caa9 and 0x639cab9).

## Verification (direct checks only — thin packet)

- Window bytes: 704 B extracted from `artifacts/node/115/hl-node` at file offset 0x639b800 (VA 0x639c800, delta 0x1000, verified against three spot bytes: `e8 70 4f 05 00` at 0x639c83b, `c3` at 0x639c8a7, `e8 b0 42 05 00` at 0x639cabb); first bytes `f3 0f 1e fa` (endbr64), last 5 bytes `e8 b0 42 05 00` (call __stack_chk_fail); sha256 `4f1c132eb64fe2bf043c684b18c9303a0a38537677bbdc8d17c1c0411cd71a87`. The `.hex` exhibit is byte-identical to the binary slice.
- Objdump census over the window disassembly (objdump -d of the binary .text, window slice; 186 strict lines): 5 calls, 1 ret, bsr 0, shr 1 (`shr $0x3,%edi` at 0x639c957), shl 0, endbr64 1, canary 2 %fs:0x28 lines, 28 jumps / 0 outside, 3 PLT calls by `@plt` suffix.
- FDE bounds: `readelf --debug-dump=frames` returns FDE pc=0x639c800..0x639cac0 directly; the window ends at 0x639cac0, gap 0 to #387's FDE start 0x639cac0 — the 704B regularity holds after #382's 696B break. The window is disjoint from all prior windows: every cited prior range lies outside 0x639c800..0x639cac0.
- Resolver two-step read verified from the disassembly (`mov 0x50(%rax),%rax` at 0x639c8b9, `mov 0xa0(%rax),%rsi` at 0x639c8bd, stored to (%rsp) at 0x639c8c4) — the stored value is the double-dereferenced entry.
- Fully-dead Duff: r12d == 0 always (dest mod 8 is 0..7, so `(dest - ((dest+8)&~7) + 8) & ~7 == 0`) at the loop-entry jb 0x639c942, plus the CFG entry check (no jump targets 0x639c948; preds[0x639ca01] == {0x639c96c, fall-through 0x639c9fb, 0x639ca67}, all inside the dead region).
- Exit reaching-definitions read straight from the disassembly: ebp defs {0x639c868, 0x639c8e0, 0x639ca8b} reach `mov %ebp,%eax` at 0x639c89b; the `mov %edx,%ebp` at 0x639caab is overwritten at 0x639ca8b on its only path.
- Duplicate check: live upstream main 0781ce04 — the slug path returns 404; GitHub search: 551 open PRs scanned, 0 hits for `q50xa0`, `639c800`, `639cac0`; the family search returns 15 open PRs, all the author's own earlier packets (#4707 #373 q50x18, #4709 #374 q50x90, #4717 #375 q50x58, #4719 #376 q50x60, #4723 #377 q50x68, #4746 #378 q50x70, #4783 #379 q50x78, #4846 #380 q50x80, #4853 #381 q50x88, #4857 #382 q50x00, #4859 #383 q50x20, #4863 #384 q50x10, #4867 #385 q50xa8, #4874 #386 q50xb0, #4878 #387 q50x08) on different windows; local work-items tree (`git ls-tree -r HEAD`) 0 hits for `q50xa0`/`639c800`.
- NOT run (declared): no verifier tool, no unit tests, no `make verify`, no `make catalogue`, no full `make test`.

## Results and limitations

- This is the FIFTY-NINTH packet of the lock-wait-helper-caller frontier (344 survivors; the lu-miss frontier is exhausted 16/16 with #314–#329). It is the TWENTY-SECOND lock-wait window with a FULLY DEAD Duff's-device loop (after #387, the twenty-first); like #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387 it resolves its entry through a separate resolver callee (0x6388310) WITHOUT loading the entry through a trivial 8-byte load helper (0x63bfb90 is NOT called) and WITHOUT a fixed inline adjust (the resolver-fixed chain, adjusts +0xb8 through +0x380 over #341–#364, ENDS at #364; #365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387/#388 add no adjust entry). It has a 3-value exit 0/1/22. It rejoins at the trylock-SUCCESS block after lock-wait (like #332/#333/#334/#336/#338/#339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365/#366/#367/#368/#369/#370/#371/#372/#373/#374/#375/#376/#377/#378/#379/#380/#381/#382/#383/#384/#385/#386/#387, unlike #330/#331/#335/#337).
- Corrections to #387's pointer for this window: NONE (prior_pointer_verified). #387's pointer made no specific claims about this window — it only recorded the FDE ending at 0x639cac0 as UNCENSUSED (704 B per .eh_frame) and left strict count, calls, lock-wait sites, exit, and resolver offsets to this scout. All of those are now answered by direct census: the window is 0x639c800..0x639cac0 (704 bytes, 186 strict, 5 calls — trylock, 0x6388310, unlock, lock-wait, stack_chk_fail — 1 lock-wait site at 0x639c8ec, 0 lu-miss / 0 bin_table_init / 0 second-handler sites, 1 ret at 0x639c8a7, bsr 0, shr 1, shl 0, endbr64 1, canary present, 28 jumps, 0 outside, 3 PLT calls across 3 targets); the 0x6388310 callee is #338's next FDE; there is no 0x63bfb90 loader call and no fixed inline adjust; the copy loop uses shr $0x3 + and $0x7 dispatch; the exit is 3-valued 0/1/22 (ebp defs at 0x639c868/0x639c8e0/0x639ca8b, returned via mov %ebp,%eax at 0x639c89b); the Duff loop is FULLY DEAD (r12d == 0 always at the loop-entry jb 0x639c942, so neither the dispatch tail nor the 8-at-a-time body is ever entered); and the resolver read is a TWO-STEP load (qword at +0x50, then qword at +0xa0 of that entry, stored to (%rsp) at 0x639c8c4) — the stored value is the double-dereferenced entry, not a single direct read. The NOT-clean notes were also confirmed: 0x6387880 calls the second handler once (direct objdump call census, site 0x63879c0) and 0x63bcd20 twice (direct objdump call census, sites 0x63bd1e4 and 0x63bd2a2).
- Unknown: entry inputs' caller-side meaning; the field semantics beyond observed reads/writes (including the meaning of the *(entry rsi + 0x10) resolver input); the lock-wait helper's semantics beyond its call-site contract and the body read at 0x63bf680..0x63bf7ee; the contents of the .bss mutex fields; the resolver 0x6388310's semantics beyond its observed call-site contract (its table at 0x6712130+0x18 and the meaning of the 0x1000/0x1001 sentinels).
- Next question: the FDE ending at 0x639c800 is UNCENSUSED — FDE 0x639c540..0x639c800 (704 B per .eh_frame) — the #389 scout must census it directly (strict count, calls, lock-wait sites, exit, resolver offsets). The next-largest 1-site candidate 0x6387880 (1,900B) is NOT clean — it calls the second miss handler 0x634ebb0 at 0x63879c0, and 0x63bcd20 (1,428B) calls it twice (direct calls at 0x63bd1e4 and 0x63bd2a2). 0x63c9650 (1,584B) is #321's window (a shared lu-miss + lock-wait FDE, claimed once). Two larger 1-site disjoint survivors exist above the 2000B band (0x63b4b50, 2,770B; 0x63eb870, 2,408B), noted for a possible heavier packet.
