# RE-001-node115-lockwait-caller-1site-strcmp: one lock-wait site, strcmp name dispatch, 3-value exit

- Component ID: RE-001-node115-lockwait-caller-1site-strcmp
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the lock-wait helper's semantics beyond its observed call-site contract are unresolved and stated as such
- Scope included and excluded: included — FDE 0x6386540..0x638693a only (1,018 bytes, 256 strict lines). Excluded — the lock-wait helper 0x63bf680..0x63bf7ee (#251), the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), the second miss handler 0x634ebb0..0x634eccd, the key resolver 0x6365150..0x6365660, the call-target FDEs 0x634eba0..0x634ebab, 0x635f6a0..0x635f77c, 0x6364360..0x636436d, 0x6364350..0x636435b, 0x63b5b50..0x63b5b5d, 0x63b5b40..0x63b5b4b, the prev FDE 0x6386500..0x638653a, the next FDE 0x6386940..0x6386b54, and the #314–#332 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls333-115). Commands (no node execution; static analysis only):

- `objdump -d --start-address=0x6386540 --stop-address=0x638693a artifacts/node/115/hl-node` (exhibit lockwait_caller_1site_strcmp.objdump.txt; strict count uses regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lockwait_caller_1site_strcmp.py` (static verifier; exit 0)
- `python3 tests/test_node115_lockwait_caller_1site_strcmp.py` (tamper-first unit tests; exit 0)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

- Coordinates: virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .data file offset = VA - 0x3000; .data.rel.ro file offset = VA - 0x2000; .bss 0x64ffe40..0x6728924 (NOBITS, section size 0x228ae4).
- FDE bounds from own .eh_frame parse (135,313 FDEs total): window 0x6386540..0x638693a (1,018 B); prev FDE 0x6386500..0x638653a (gap 6 bytes, all 0xcc int3 padding); next FDE 0x6386940..0x6386b54 (gap 6 bytes, all 0xcc int3 padding; starts with endbr64).
- Window shape: endbr64 1 (entry), canary present (2 `%fs:0x28` lines; `__stack_chk_fail@plt` called at 0x6386935 on the canary-fail path), TLS flag check absent (0 `%fs:0x330` lines), bsr 0, NO prefetch instructions, lock sub 0 / lock add 0, tzcnt 0 / btc 0. 11 calls (9 distinct direct targets, 0 indirect); 6 PLT calls across 4 PLT targets (trylock, strcmp x3, unlock, stack_chk_fail).
- Shape: a named-entry lookup under a global mutex. The entry trylocks the global mutex at 0x67121a0 (r15 = lea 0x67121a0 at 0x6386546); on failure it calls the lock-wait helper 0x63bf680 at 0x6386664 with rdi = 0x6712160 (lea -0x40(%r15) at 0x6386660), sets the waited flag byte at 0x67121c8, and jumps straight to the critical section at 0x6386590 with the lock held — there is NO trylock retry (like #332, unlike #330/#331). On success the acquisition count at 0x6712198 is incremented and the owner at 0x6712190 is tracked against entry rdi. The name string (*r9, loaded to (%rsp)) is matched by strcmp against three .data strings — "disabled" (index 0), "primary" (index 1), "secondary" (index 2) — from the table at 0x64ffc00 (resolved via .rela.dyn RELATIVE addends, read from the file). A 32-bit selector ebx = (uint32_t)*(rsi+8) (high 32 bits nonzero -> exit 14) picks the resolution path: ebx == 0x1000 or *(0x6712130+8) == ebx takes the 0x63b5b50/0x63b5b40 predicate path; otherwise the runtime table 0x65096c0[ebx] (.bss, runtime-populated, not statically resolvable) is consulted with the 0x6364360 predicate and the 0x6364350 index call. The resolved 8-byte value (name_table[index]) is stored to the output buffer when *r8 == 8 (fast path, exit 0); otherwise a byte-copy loop copies min(*r8, 8) bytes and writes the clamped length back (exit 22). 46 jumps, 0 outside the window.
- Calls (11, 9 distinct direct targets, 0 indirect): 0x63f17b0 x1 (pthread_mutex_trylock@plt, 0x6386583), 0x63f0f20 x3 (strcmp@plt, 0x63865f1, 0x6386605, 0x6386615), 0x63f0b70 x1 (pthread_mutex_unlock@plt, 0x6386632), 0x63bf680 x1 (0x6386664, lock-wait helper), 0x63b5b50 x1 (0x6386693), 0x63b5b40 x1 (0x638669c), 0x6364360 x1 (0x63866e5), 0x6364350 x1 (0x638672e), 0x63f0d70 x1 (__stack_chk_fail@plt, 0x6386935). No lu-miss, no bin_table_init, no second-handler, no resolver, no #314–#332 window calls.
- Raw 0xe8 census (own .eh_frame parse): lock-wait 474 sites / 385 FDEs (this FDE 1; tiers {1: 348, 2: 19, 3: 9, 4: 4, 5: 1, 7: 2, 8: 1, 18: 1}); lu-miss 168 / 53 (this FDE 0); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0).
- .rela.dyn: 60,723 total, 59,534 RELATIVE. .rela.plt: 278. Referenced addresses: 0x67121a0, 0x6712198, 0x6712190, 0x6712188, 0x67121c8, 0x6712130 (all inside .bss); 0x64ffc00 (inside .data); 0x65096c0 (inside .bss, runtime table); 0x6511a00 (lu-miss .bss) is NOT referenced.
- Exits: a SINGLE ret at 0x638665c with exit value r13d in {0, 14, 22}. Rax is set by `mov %r13d,%eax` at 0x638664f. r13d has exactly three reaching defs: 0 (success), 14 (lookup/predicate failure), 22 (name not matched / 7th stack arg != 8 / partial copy).
- Analysis was complete over the window (all 256 strict lines classified). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #332's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

- Verifier exit 0 (517 checks, 0 failures); unit tests exit 0 (12 checks, 0 failures); `make verify` exit 0 (559/7159); `make catalogue-check` exit 2 (pre-existing, not a regression).
- Disjointness: window 0x6386540..0x638693a overlaps no prior range (verifier: 84978 priors scanned, 0 skipped, NONE); next candidate 0x635f780..0x635fb47 likewise disjoint.
- This is the FOURTH packet of the lock-wait-helper-caller frontier (344 survivors; the lu-miss frontier is exhausted 16/16 with #314–#329). It is the FIRST lock-wait window with a strcmp name dispatch (3 strcmp calls), a 3-value exit (0/14/22), a byte-copy loop, and a global .bss mutex (not a struct-field mutex).
- Corrections made during the build: NO correction to #332's pointer — all #332 pointer figures for this window (1,018 bytes, 256 strict, 11 calls, 1 lock-wait site at 0x6386664, 0 lu-miss / 0 bin_table_init / 0 second-handler sites, 1 ret at 0x638665c, bsr 0, endbr64 1, canary present, 46 jumps, 0 outside) were confirmed by targeted census (prior_pointer_verified).
- Unknown: entry inputs' caller-side meaning; the field semantics beyond observed reads/writes; the lock-wait helper's semantics beyond its call-site contract (single rdi argument, returns with the lock held per its body at 0x63bf680..0x63bf7ee, read directly); the contents of the runtime table 0x65096c0 and the meaning of the 0x6712130 check, the 0x1000 special value, and the 0x63b5b50/0x63b5b40/0x6364360/0x6364350 callees beyond the observed branches.
- Next question: 0x635f780..0x635fb47 (967 bytes, 240 strict, 26 calls, 1 lock-wait site at 0x635fb32, 0 lu-miss / 0 bin_table_init / 0 second-handler sites, 1 ret at 0x635f7d6, bsr 0, endbr64 0, canary present, 28 jumps, 0 outside). The next-largest 1-site candidate 0x6387880 (1,900B) is NOT clean: it calls the second miss handler 0x634ebb0 at 0x63879c0 (and is itself a second-handler survivor), so it is skipped for the light style; 0x63bcd20 (1,428B) is also NOT clean (calls the second handler twice). Two larger 1-site disjoint survivors exist above the 2000B band (0x63b4b50, 2,770B; 0x63eb870, 2,408B) and are noted for a possible heavier packet.
