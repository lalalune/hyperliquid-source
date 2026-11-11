# RE-001-node115-lockwait-caller-1site-resolver-noloader: one lock-wait site, resolver without loader or fixed adjust, 4-value exit, single-byte copy

- Component ID: RE-001-node115-lockwait-caller-1site-resolver-noloader
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the lock-wait helper's semantics beyond its observed call-site contract are unresolved
- Scope included and excluded: included — FDE 0x63a06e0..0x63a0803 only (291 bytes, 75 strict lines). Excluded — the lock-wait helper 0x63bf680..0x63bf7ee (#251), the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), the second miss handler 0x634ebb0..0x634eccd, the key resolver 0x6365150..0x6365660, the 16-byte thunk callee 0x63643f0..0x6364400 (#337), the 11-byte count FDE 0x634eba0..0x634ebab (NOT called from this window), the index resolver 0x6388310..0x6388372 (#338's next FDE), the 8-byte load helper 0x63bfb90..0x63bfb98 (NOT called from this window), the prev FDE 0x63a0480..0x63a06d3 (#366's window, the next question), the next FDE 0x63a0810..0x63a0ad0 (#364's window), and the #314–#364 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls365-115). No node execution; static analysis only.

- `objdump -d --start-address=0x63a06e0 --stop-address=0x63a0803 artifacts/node/115/hl-node` (exhibit lockwait_caller_1site_resolver_noloader.objdump.txt; 75 strict lines by regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lockwait_caller_1site_resolver_noloader.py` (static verifier; exit 0; 443 checks)
- `python3 tests/test_node115_lockwait_caller_1site_resolver_noloader.py` (tamper-first unit tests; exit 0; 13 checks)
- `make verify` (exit 0; 1754 manifests, 20576 entries)
- `make catalogue-check` (exit 0)
- Full `make test` is not run (1052 files on the build base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

Original addresses and coordinate system (VA/file offset): virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .data file offset = VA - 0x3000; .data.rel.ro file offset = VA - 0x2000; .bss 0x64ffe40..0x6728924 (NOBITS).

Validated boundaries (own .eh_frame parse, 135,313 FDEs total): window 0x63a06e0..0x63a0803 (291 B); prev FDE 0x63a0480..0x63a06d3 (#366's window; gap 13, 13 int3 padding bytes 0x63a06d3..0x63a06e0; starts with endbr64 at 0x63a0480); next FDE 0x63a0810..0x63a0ad0 (#364's window; gap 13, 13 int3 padding bytes 0x63a0803..0x63a0810; starts with `endbr64` at 0x63a0810). The count FDE is 0x634eba0..0x634ebab (11 B, NOT called from this window); the lock-wait helper FDE is 0x63bf680..0x63bf7ee; the index resolver FDE is 0x6388310..0x6388372 (98 B); the load helper FDE is 0x63bfb90..0x63bfb98 (8 B, NOT called from this window).

Raw disassembly: exhibit lockwait_caller_1site_resolver_noloader.objdump.txt (75 strict lines). Raw binary: exhibit lockwait_caller_1site_resolver_noloader.hex (291 raw bytes, equal to the binary slice at file offset 0x63a05e0).

Callers/callees/indirect calls: 5 calls (5 distinct direct targets, 0 indirect). Direct: 0x6388310 x1 (index resolver, 0x63a0763), trylock@plt x1 (0x63a0733), unlock@plt x1 (0x63a077a), lock-wait 0x63bf680 x1 (0x63a07c4), stack_chk_fail@plt x1 (0x63a07fe). Indirect: none. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x6388310, 0x63bf680) are NOT PLT stubs. The 0x63bfb90 load helper is NOT called from this window.

Source mapping evidence: none — no source mapping is claimed; all claims are disassembly observations. ABI/layout observations: entry rdi -> rbx, rsi field 0x8(%rsi) -> r13 (the resolver input), rcx -> rbp (destination pointer), r8 -> r12 (length pointer), r9 used in the caller condition; frame sub $0x10, canary at 0x8(%rsp), 5 pushes (r14, r13, r12, rbp, rbx), NO r15 in this window (the mutex is held in r14); NO entry gate byte in this window (unlike #334/#337) — the early exits are (r9 | 7th stack arg 0x40(%rsp)) != 0 (exit 1) and the high-32 check on *(entry rsi + 8) (exit 14); the fast paths after the lock are rcx==0, r8==0 (exit 0) and *(r8)==1 (single-byte store + exit 0); the lock-wait node is 0x6712160 with mutex node+0x40 = 0x67121a0 and waited flag node+0x68 = 0x67121c8 (the SAME global .bss mutex object as #333/#335/#337/#338/#339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364); the resolver is called with rdi = *(entry rsi + 8) (`mov %r13,%rdi` at 0x63a0760), the resolver result's byte 4 is read directly (`movzbl 0x4(%rax),%eax` at 0x63a076b); there is NO table-base load, NO fixed inline adjust and NO loader call — the resolver-fixed chain ENDS at #364; (r9 | 7th stack arg 0x40(%rsp)) != 0 after lock acquisition exits 1; the high-32 check exits 14; the copy is a single byte with no loop (len==1 stores the byte and exits 0; len!=1 copies one byte, writes back *r8 = (len != 0) and exits 22). The single ret at 0x63a07ba returns eax directly with reaching defs {0x63a06fe (1), 0x63a0712 (14), 0x63a079c (0), 0x63a07f7 (22)}.

Analysis was complete over the window (all 75 strict lines classified). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #333's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

Machine-readable metrics: verifier 443/0; unit tests 13/0; `make verify` 1754 manifests, 20576 entries; `make catalogue-check` exit 0. Disjointness: window 0x63a06e0..0x63a0803 overlaps no prior range (verifier: 116345 priors scanned, 0 skipped, NONE); next candidate 0x63a0480..0x63a06d3 likewise disjoint. Raw 0xe8 census: lock-wait 474 sites / 385 FDEs (this FDE 1); lu-miss 168 / 53 (this FDE 0); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0).

What passed/failed: all gates pass; nothing failed. What remains unknown: entry inputs' caller-side meaning; the field semantics beyond observed reads/writes (including the meaning of the high-32 field at entry rsi+8); the lock-wait helper's semantics beyond its call-site contract; the contents of the .bss mutex fields; the resolver 0x6388310's semantics beyond its observed call-site contract (its table at 0x6712130+0x18 and the meaning of the 0x1000/0x1001 sentinels).

Next question: 0x63a0480..0x63a06d3 (595 bytes, 154 strict, 5 calls, 1 lock-wait site at 0x63a0564, 0/0/0, 1 ret at 0x63a0527, bsr 0, shr 0, shl 0, endbr64 1, canary present, 21 jumps, 0 outside, 3 PLT calls across 3 targets). No loader call and no fixed inline adjust; 3-value exit 0/1/22 (to be re-verified). Its Duff's-device copy loop (0x63a0578..0x63a06b9) looks REACHABLE — the #366 scout must verify reachability and the exit reaching-definitions directly.
