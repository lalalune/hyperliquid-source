# RE-001-node115-lockwait-caller-1site-resolver-noloader-duff: one lock-wait site, resolver without loader or fixed adjust, 3-value exit, reachable Duff dispatch tail with value-dead 8-at-a-time body

- Component ID: RE-001-node115-lockwait-caller-1site-resolver-noloader-duff
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the lock-wait helper's semantics beyond its observed call-site contract are unresolved
- Scope included and excluded: included — FDE 0x63a0480..0x63a06d3 only (595 bytes, 154 strict lines). Excluded — the lock-wait helper 0x63bf680..0x63bf7ee (#251), the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), the second miss handler 0x634ebb0..0x634eccd, the key resolver 0x6365150..0x6365660, the 16-byte thunk callee 0x63643f0..0x6364400 (#337), the 11-byte count FDE 0x634eba0..0x634ebab (NOT called from this window), the index resolver 0x6388310..0x6388372 (#338's next FDE), the 8-byte load helper 0x63bfb90..0x63bfb98 (NOT called from this window), the prev FDE 0x63a01c0..0x63a0478 (#367's window, the next question), the next FDE 0x63a06e0..0x63a0803 (#365's window), and the #314–#365 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 7ff06a09 (branch codex/re-004-calls366-115). No node execution; static analysis only.

- `objdump -d --start-address=0x63a0480 --stop-address=0x63a06d3 artifacts/node/115/hl-node` (exhibit lockwait_caller_1site_resolver_noloader_duff.objdump.txt; 154 strict lines by regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lockwait_caller_1site_resolver_noloader_duff.py` (static verifier; exit 0; 560 checks)
- `python3 tests/test_node115_lockwait_caller_1site_resolver_noloader_duff.py` (tamper-first unit tests; exit 0; 13 checks)
- `make verify` (exit 0; 1754 manifests, 20576 entries)
- `make catalogue-check` (exit 0)
- Full `make test` is not run (1052 files on the build base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

Original addresses and coordinate system (VA/file offset): virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .data file offset = VA - 0x3000; .data.rel.ro file offset = VA - 0x2000; .bss 0x64ffe40..0x6728924 (NOBITS).

Validated boundaries (own .eh_frame parse, 135,313 FDEs total): window 0x63a0480..0x63a06d3 (595 B); prev FDE 0x63a01c0..0x63a0478 (#367's window; gap 8, 8 int3 padding bytes 0x63a0478..0x63a0480; starts with endbr64 at 0x63a01c0); next FDE 0x63a06e0..0x63a0803 (#365's window; gap 13, 13 int3 padding bytes 0x63a06d3..0x63a06e0; starts with `endbr64` at 0x63a06e0). The count FDE is 0x634eba0..0x634ebab (11 B, NOT called from this window); the lock-wait helper FDE is 0x63bf680..0x63bf7ee; the index resolver FDE is 0x6388310..0x6388372 (98 B); the load helper FDE is 0x63bfb90..0x63bfb98 (8 B, NOT called from this window).

Raw disassembly: exhibit lockwait_caller_1site_resolver_noloader_duff.objdump.txt (154 strict lines). Raw binary: exhibit lockwait_caller_1site_resolver_noloader_duff.hex (595 raw bytes, equal to the binary slice at file offset 0x63a0380).

Callers/callees/indirect calls: 5 calls (5 distinct direct targets, 0 indirect). Direct: 0x6388310 x1 (index resolver, 0x63a0534), trylock@plt x1 (0x63a04bb), unlock@plt x1 (0x63a04fe), lock-wait 0x63bf680 x1 (0x63a0564), stack_chk_fail@plt x1 (0x63a06ce). Indirect: none. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x6388310, 0x63bf680) are NOT PLT stubs. The 0x63bfb90 load helper is NOT called from this window.

Source mapping evidence: none — no source mapping is claimed; all claims are disassembly observations. ABI/layout observations: entry rdi -> rbp, rsi -> r14 (its field 0x10(%r14) is the resolver input), rcx -> r12 (destination pointer), r8 -> r13 (length pointer), r9 -> rbx (caller condition); frame sub $0x18, canary at 0x8(%rsp), 6 pushes (r15, r14, r13, r12, rbp, rbx), the mutex held in r15 (lea 0x67121a0 at 0x63a0486); NO entry gate byte in this window (unlike #334/#337) — the early exit is (r9 | 7th stack arg 0x50(%rsp)) != 0 (exit 1); the fast paths after the resolver are rcx==0, r8==0 (exit 0) and *(r8)==4 (whole-dword store + exit 0); the lock-wait node is 0x6712160 with mutex node+0x40 = 0x67121a0 and waited flag node+0x68 = 0x67121c8 (the SAME global .bss mutex object as #333/#335/#337/#338/#339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365); the resolver is called with rdi = *(entry rsi + 0x10) (`mov 0x10(%r14),%rdi` at 0x63a0530), the resolver result's dword at +0x18 is read directly (`mov 0x18(%rax),%eax` at 0x63a0539); there is NO table-base load, NO fixed inline adjust and NO loader call — the resolver-fixed chain ENDS at #364; (r9 | 7th stack arg 0x50(%rsp)) != 0 after lock acquisition exits 1; the copy is a Duff's-device loop (0x63a0578..0x63a06b9) whose dispatch tail is reachable for len 2..4 (n = min(len,4), dispatch on (n-1)&7) while its 8-at-a-time body (0x63a064b..0x63a06b9) is value-dead; the writeback stores *r8 = n (`mov %rdx,0x0(%r13)` at 0x63a06c0) and exits 22. The single ret at 0x63a0527 returns eax via `mov %ebp,%eax` at 0x63a051b with ebp reaching defs {0x63a04e8 (1), 0x63a0558 (0), 0x63a06c4 (22)}.

Analysis was complete over the window (all 154 strict lines classified). The `.bss` objects are referenced by address only; their runtime contents are not established.

Base field correction: #365's sealed docs carried records "base" = 05bc2de30 while the build base was 7ff06a09 (frozen since before #364). The verifier's only dependence on that value was its own "records base" check, so #366 sets records "base" and the README/EVIDENCE "Source commit" to the true build base 7ff06a09 and updates the verifier literal to match.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #333's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

Machine-readable metrics: verifier 560/0; unit tests 13/0; `make verify` 1754 manifests, 20576 entries; `make catalogue-check` exit 0. Disjointness: window 0x63a0480..0x63a06d3 overlaps no prior range (verifier: 117833 priors scanned, 0 skipped, NONE); next candidate 0x63a01c0..0x63a0478 likewise disjoint. Raw 0xe8 census: lock-wait 474 sites / 385 FDEs (this FDE 1); lu-miss 168 / 53 (this FDE 0); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0).

What passed/failed: all gates pass; nothing failed. What remains unknown: entry inputs' caller-side meaning; the field semantics beyond observed reads/writes (including the meaning of the *(entry rsi + 0x10) resolver input); the lock-wait helper's semantics beyond its call-site contract; the contents of the .bss mutex fields; the resolver 0x6388310's semantics beyond its observed call-site contract (its table at 0x6712130+0x18 and the meaning of the 0x1000/0x1001 sentinels).

Next question: 0x63a01c0..0x63a0478 (696 bytes, 185 strict, 5 calls, 1 lock-wait site at 0x63a02a4, 0/0/0, 1 ret at 0x63a0267, bsr 0, shr 1, shl 0, endbr64 1, canary present, 28 jumps, 0 outside, 3 PLT calls across 3 targets). No loader call and no fixed inline adjust; exit to be verified by the #367 scout. Its copy loop uses shr $0x3 + and $0x7 dispatch (0x63a0301..0x63a043f region) — the #367 scout must verify reachability and the exit reaching-definitions directly.

