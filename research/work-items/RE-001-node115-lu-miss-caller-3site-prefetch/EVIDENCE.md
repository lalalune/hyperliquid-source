# RE-001-node115-lu-miss-caller-3site-prefetch: three calls, three miss sites, pair-unrolled lookup, prefetch pass

- Component ID: RE-001-node115-lu-miss-caller-3site-prefetch
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the lu-miss handler's semantics are unresolved and stated as such
- Scope included and excluded: included — FDE 0x63e94a0..0x63e9bf2 only (1,874 bytes, 396 strict lines). Excluded — the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), second miss handler 0x634ebb0..0x634eccd, lock-wait helper 0x63bf680..0x63bf7ee (#251), the key resolver 0x6365150..0x6365660, the prev FDE 0x63e91c0..0x63e9491, the next FDE 0x63e9c00..0x63e9c0c, and the #314–#328 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls329-115). Commands (no node execution; static analysis only):

- `objdump -d --start-address=0x63e94a0 --stop-address=0x63e9bf2 artifacts/node/115/hl-node` (exhibit lu_miss_caller_3site_prefetch.objdump.txt; strict count uses regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_3site_prefetch.py` (static verifier; exit 0)
- `python3 tests/test_node115_lu_miss_caller_3site_prefetch.py` (tamper-first unit tests; exit 0)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

- Coordinates: virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .bss 0x64ffe40..0x6728924 (NOBITS, section size 0x228ae4).
- FDE bounds from own .eh_frame parse (135,313 FDEs total): window 0x63e94a0..0x63e9bf2 (1,874 B); prev FDE 0x63e91c0..0x63e9491 (gap 15 bytes, all 0xcc int3 padding); next FDE 0x63e9c00..0x63e9c0c (gap 14 bytes, all 0xcc int3 padding; 12-byte thunk starting with endbr64).
- Window shape: NO endbr64 (entry is test %rdx,%rdx), NO canary (no %fs:0x28, no __stack_chk_fail call), NO TLS flag check. NO size-class computation for the lookup at all — no byte table, no size table, no $0x3fff cap, no fallback table, no bsr arms, no resolver call: the lookup indexes the table directly from the entry key ((key >> 0x1a) & 0xf0 top index, (key >> 0x9) & 0x1ffff8 second level). The count%4 dispatch at 0x63e958d only unrolls the prefetch pass. A pair-unrolled lookup loop (chain A = first element, chain B = second element) plus an odd-count single-element path (chain C at 0x63e96b2) plus a post-lookup normalize+prefetch pass (count%4 dispatch, 4-at-a-time loop at 0x63e9617, remainder blocks): 24 slot-compare instructions, 21 reversed-operand, 3 normal (slot 7 of each chain, memory-first). The three top compares are register-first (cmp %rdi,%rsi at 0x63e9509, cmp %r11,%rdx at 0x63e9556, cmp %r8,%r11 at 0x63e96da) but are table compares, not slot compares. The three lu-miss sites share the frontier argument pattern (rdi = table base, rsi = .bss 0x6511a00, rdx = top-table base via r15, rcx = key, r8d = 1, r9d = 0); rcx provenance is proven per site by reaching-definitions (site 1 second element key, only def 0x63e9531; site 2 first element key, only def 0x63e94e4; site 3 single element key, only def 0x63e96b6). Site 2 spills r10 to 0x8(%rsp) across the call. TWO rets: ret 1 at 0x63e96b1 has a 7-def may-analysis rax set with no constant-setting def (over-approximation: CALL(0x63e9be8), 0x63e96ef, 0x63e97ed, 0x63e994b are likely infeasible on the ret path); ret 2 at 0x63e97a6 (rdx==0 early exit) has ENTRY only. No constant exit value at either ret.
- Calls (3, 1 distinct direct, 0 indirect): 0x63d9700 x3 (the three lu-miss sites — the window's ONLY calls). No bin_table_init, no second-handler, no lock-wait helper, no resolver, no #314–#328 window calls, no PLT calls.
- Raw 0xe8 census (own .eh_frame parse): lu-miss 168 sites / 53 FDEs (this FDE 3); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0; next candidate holds 0).
- .rela.dyn: 60,723 total, 59,534 RELATIVE. .rela.plt: 278. Referenced addresses: 0x6511a00 (inside .bss).
- Analysis was complete over the window (all 396 strict lines classified; 55 jumps, 0 outside). The `.bss` object is referenced by address only; its runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #328's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

- Verifier exit 0 (380 checks, 0 failures); unit tests exit 0 (12 checks, 0 failures); `make verify` exit 0 (559/7159); `make catalogue-check` exit 2 (pre-existing, not a regression).
- Disjointness: window 0x63e94a0..0x63e9bf2 overlaps no prior range (verifier: 81,606 priors scanned, 0 skipped, NONE); next candidate 0x6362190..0x6362901 likewise disjoint.
- Corrections made during the build: none to #328's pointer (verified correct, prior_pointer_verified). The pre-build handoff draft's figures for this window (1,874 bytes, 396 strict, 3 calls — all lu-miss at 0x63e9b6c/0x63e9bac/0x63e9be8, 0 bin_table_init sites, 0 second-handler sites, 2 rets at 0x63e96b1 and 0x63e97a6, bsr 0) were all confirmed by targeted census; the draft did not state endbr64/canary/lock/TLS/jump figures, which this packet establishes by direct census (no endbr64, no canary, lock sub 0 / lock add 0, no TLS flag check, 55 jumps 0 outside). One draft-adjacent correction from the #328 build: the next candidate's FDE end was first read as 0x63e97f2 from a misread decimal — the .eh_frame parse gives 0x63e9bf2 (verified). During this build, a first reaching-definitions run reported site 1's rcx def as 0x63e94e4; two independent re-runs plus an instrumented trace showed the correct def is 0x63e9531 (0x63e94e4 is the first element key load, site 2's def) — the verifier asserts 0x63e9531.
- Unknown: entry inputs' caller-side meaning; the table layout beyond the observed offsets (top index at table+0x0..0xf0, scan slots at 0x2b0..0x320); field semantics beyond observed reads/writes; the lu-miss handler's semantics beyond the call sites; the exit value's meaning beyond its may-analysis reaching-def set (no constant exit value).
- Next question: the lu-miss frontier is exhausted with this packet (16 of 16 survivors claimed). The follow-on frontier is the lock-wait helper 0x63bf680 callers (344 survivors); the largest 1-site disjoint candidate is 0x6362190..0x6362901 (1,905 bytes, 446 strict, 13 calls, 1 lock-wait site at 0x636286f, 0 lu-miss / 0 bin_table_init / 0 second-handler sites, 1 ret at 0x636282d, bsr 0, endbr64 1, canary present, 49 jumps with 1 tail jump to 0x6360ed0).
