# RE-001-node115-lockwait-caller-1site-resolver-fixed-138: one lock-wait site, fixed +0x138 resolver (no index stride), 3-value exit, dead Duff's loop

- Component ID: RE-001-node115-lockwait-caller-1site-resolver-fixed-138
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the lock-wait helper's semantics beyond its observed call-site contract are unresolved
- Scope included and excluded: included — FDE 0x63a3c50..0x63a3f10 only (704 bytes, 187 strict lines). Excluded — the lock-wait helper 0x63bf680..0x63bf7ee (#251), the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), the second miss handler 0x634ebb0..0x634eccd, the key resolver 0x6365150..0x6365660, the 16-byte thunk callee 0x63643f0..0x6364400 (#337), the 11-byte count FDE 0x634eba0..0x634ebab (NOT called from this window), the index resolver 0x6388310..0x6388372 (#338's next FDE), the 8-byte load helper 0x63bfb90..0x63bfb98, the prev FDE 0x63a3990..0x63a3c50 (#346's window, the next question), the next FDE 0x63a3f10..0x63a41d0 (#344's window), and the #314–#344 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls345-115). No node execution; static analysis only.

- `objdump -d --start-address=0x63a3c50 --stop-address=0x63a3f10 artifacts/node/115/hl-node` (exhibit lockwait_caller_1site_resolver_fixed_138.objdump.txt; 187 strict lines by regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lockwait_caller_1site_resolver_fixed_138.py` (static verifier; exit 0; 569 checks)
- `python3 tests/test_node115_lockwait_caller_1site_resolver_fixed_138.py` (tamper-first unit tests; exit 0; 13 checks)
- `make verify` (exit 0; 559/7159)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

Original addresses and coordinate system (VA/file offset): virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .data file offset = VA - 0x3000; .data.rel.ro file offset = VA - 0x2000; .bss 0x64ffe40..0x6728924 (NOBITS).

Validated boundaries (own .eh_frame parse, 135,313 FDEs total): window 0x63a3c50..0x63a3f10 (704 B); prev FDE 0x63a3990..0x63a3c50 (#346's window; gap 0, contiguous, no padding; starts with endbr64 at 0x63a3990); next FDE 0x63a3f10..0x63a41d0 (#344's window; gap 0, contiguous, no padding; starts with `endbr64` at 0x63a3f10). The count FDE is 0x634eba0..0x634ebab (11 B, NOT called from this window); the lock-wait helper FDE is 0x63bf680..0x63bf7ee; the index resolver FDE is 0x6388310..0x6388372 (98 B); the load helper FDE is 0x63bfb90..0x63bfb98 (8 B).

Raw disassembly: exhibit lockwait_caller_1site_resolver_fixed_138.objdump.txt (187 strict lines). Raw binary: exhibit lockwait_caller_1site_resolver_fixed_138.hex (704 raw bytes, equal to the binary slice at file offset 0x63a2c50).

Callers/callees/indirect calls: 6 calls (6 distinct direct targets, 0 indirect). Direct: 0x6388310 x1 (index resolver, 0x63a3d04), trylock@plt x1 (0x63a3c8b), unlock@plt x1 (0x63a3cce), 0x63bfb90 x1 (load helper, 0x63a3d14), lock-wait 0x63bf680 x1 (0x63a3d44), stack_chk_fail@plt x1 (0x63a3f0b). Indirect: none. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x6388310, 0x63bfb90, 0x63bf680) are NOT PLT stubs.

Source mapping evidence: none — no source mapping is claimed; all claims are disassembly observations. ABI/layout observations: entry rdi -> rbp, rsi -> r14 (entry pointer), rcx -> r12 (destination pointer), r8 -> r13 (length pointer), r9 -> rbx; frame sub $0x18, canary at 0x8(%rsp); NO entry gate byte in this window (unlike #334/#337) — the fast paths are rcx==0, r8==0 (exit 0) and *(r8)==8 (store + exit 0); the lock-wait node is 0x6712160 with mutex node+0x40 = 0x67121a0 and waited flag node+0x68 = 0x67121c8 (the SAME global .bss mutex object as #333/#335/#337/#338/#339/#340/#341/#342/#343/#344); the resolver is called with rdi = *(entry rsi + 0x10) (`mov 0x10(%r14),%rdi` at 0x63a3d00), the table base is *(resolver return + 0x50) (`mov 0x50(%rax),%rdi` at 0x63a3d09), there is NO index and NO stride — the entry address is the table base + a FIXED +0x138 (`add $0x138,%rdi` at 0x63a3d0d), the load helper 0x63bfb90 returns *(entry address); (r9 | 7th stack arg 0x50(%rsp)) != 0 after lock acquisition exits 1; the copy phase copies min(len, 8) bytes with a (len-1)>>3 & 7 remainder dispatch and an 8-at-a-time unrolled loop that is present but unreachable (the loop-guard r12d is always 0, so the jb at 0x63a3d9a is always taken), then writes back *r8 = copied length and exits 22; len == 8 copies the resolved value directly and exits 0. The single ret at 0x63a3cf7 returns ebp with reaching defs at the flag-clear block {0x63a3cb8 (1), 0x63a3d35 (0), 0x63a3edb (22)}.

Analysis was complete over the window (all 187 strict lines classified). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #333's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

Machine-readable metrics: verifier 569/0; unit tests 13/0; `make verify` 559/7159; `make catalogue-check` exit 2 (pre-existing). Disjointness: window 0x63a3c50..0x63a3f10 overlaps no prior range (verifier: 95094 priors scanned, 0 skipped, NONE); next candidate 0x63a3990..0x63a3c50 likewise disjoint. Raw 0xe8 census: lock-wait 474 sites / 385 FDEs (this FDE 1); lu-miss 168 / 53 (this FDE 0); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0).

What passed/failed: all gates pass; nothing failed. What remains unknown: entry inputs' caller-side meaning; the field semantics beyond observed reads/writes; the lock-wait helper's semantics beyond its call-site contract; the contents of the .bss mutex fields; the resolver 0x6388310's semantics beyond its observed call-site contract (its table at 0x6712130+0x18 and the meaning of the 0x1000/0x1001 sentinels); the load helper 0x63bfb90's caller-side meaning beyond the observed load.

Next question: 0x63a3990..0x63a3c50 (704 bytes, 187 strict, 6 calls, 1 lock-wait site at 0x63a3a84, 0 lu-miss / 0 bin_table_init / 0 second-handler sites, 1 ret at 0x63a3a37, bsr 0, shr 1, shl 0, endbr64 1, canary present, 28 jumps, 0 outside, 3 PLT calls across 3 targets).
