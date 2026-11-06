# RE-001-node115-lu-miss-caller-1site-direct: one call, one miss site, no size class, output-struct return

- Component ID: RE-001-node115-lu-miss-caller-1site-direct
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the lu-miss handler's semantics are unresolved and stated as such
- Scope included and excluded: included — FDE 0x63d4048..0x63d4171 only (297 bytes, 76 strict lines). Excluded — the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), second miss handler 0x634ebb0..0x634eccd, lock-wait helper 0x63bf680..0x63bf7ee (#251), the key resolver 0x6365150..0x6365660, the prev FDE 0x63d3f0e..0x63d4048 (#327 window), the next FDE 0x63d4171..0x63d4289, and the #314–#327 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls328-115). Commands (no node execution; static analysis only):

- `objdump -d --start-address=0x63d4048 --stop-address=0x63d4171 artifacts/node/115/hl-node` (exhibit lu_miss_caller_1site_direct.objdump.txt; strict count uses regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_1site_direct.py` (static verifier; exit 0)
- `python3 tests/test_node115_lu_miss_caller_1site_direct.py` (tamper-first unit tests; exit 0)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

- Coordinates: virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .bss 0x64ffe40..0x6728924 (NOBITS, section size 0x228ae4).
- FDE bounds from own .eh_frame parse (135,313 FDEs total): window 0x63d4048..0x63d4171 (297 B); prev FDE 0x63d3f0e..0x63d4048 (gap 0, directly adjacent; the #327 window); next FDE 0x63d4171..0x63d4289 (gap 0, directly adjacent; starts with push %r12, NO endbr64).
- Window shape: NO endbr64 (entry is mov %rsi,%rax), NO canary (no %fs:0x28, no __stack_chk_fail call), NO TLS flag check. NO size-class computation at all — no byte table, no size table, no $0x3fff cap, no fallback table, no bsr arms, no resolver call, no count rounding: the lookup indexes the table directly from the entry key ((key >> 0x1a) & 0xf0 top index, (key >> 0x9) & 0x1ffff8 second level). A single top-index lookup plus one 8-slot move-to-front scan over 0x100..0x180 in rsi (slot 0 checked directly, slots 1–7 in a counter loop): 2 slot-compare instructions, ZERO reversed-operand, 0 of 8 slot positions reversed; the top compare itself is register-first (cmp %r10,%r9) but is a table compare, not a slot compare. The single lu-miss site shares the frontier argument pattern (rdi = context, rsi = .bss 0x6511a00, rdx = table pointer, rcx = key, r8d = 1, r9d = 0) with the context coming from entry rsi (via rax) while entry rdi is the output struct (saved to rbx); rcx provenance proven by reaching-definitions (rcx has NO reaching def at the site other than the entry value — no write to rcx on the walk→scan→miss path). A SINGLE ret at 0x63d4170 with ONE reaching rax definition (mov %rbx,%rax at 0x63d4166) — the exit value is the entry rdi (output struct pointer), after the resolve tail writes five fields into (%rbx) from node[0] extracts. No walk A/B/C split, no element loop, no prev-FDE call, no deep-resolution tail, no tail jumps. No stack frame adjustment (no sub/add rsp; only push/pop %rbx).
- Calls (1, 1 distinct direct, 0 indirect): 0x63d9700 x1 (the lu-miss site itself — the window's ONLY call). No bin_table_init, no second-handler, no lock-wait helper, no resolver, no #314–#327 window calls, no PLT calls.
- Raw 0xe8 census (own .eh_frame parse): lu-miss 168 sites / 53 FDEs (this FDE 1); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0; next candidate holds 0).
- .rela.dyn: 60,723 total, 59,534 RELATIVE. .rela.plt: 278. Referenced addresses: 0x6511a00 (inside .bss).
- Analysis was complete over the window (all 76 strict lines classified; 7 jumps, 0 outside). The `.bss` object is referenced by address only; its runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #327's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

- Verifier exit 0 (228 checks, 0 failures); unit tests exit 0 (12 checks, 0 failures); `make verify` exit 0 (559/7159); `make catalogue-check` exit 2 (pre-existing, not a regression).
- Disjointness: window 0x63d4048..0x63d4171 overlaps no prior range (verifier: 80,763 priors scanned, 0 skipped, NONE); next candidate 0x63e94a0..0x63e9bf2 likewise disjoint.
- Corrections made during the build: none to #327's pointer (verified correct, prior_pointer_verified). The pre-build handoff draft's figures for this window (297 bytes, 76 strict, 1 call, 1 lu-miss at 0x63d4127, 0 bti, 0 second-handler, 1 ret at 0x63d4170, bsr 0) were all confirmed by targeted census; the draft did not state endbr64/canary/lock/TLS figures, which this packet establishes by direct census (no endbr64, no canary, lock sub 0 / lock add 0, no TLS flag check). One draft-adjacent correction: the next candidate's FDE end was first read as 0x63e97f2 from a misread decimal — the .eh_frame parse gives 0x63e9bf2 (1,874 bytes, 396 strict, 3 lu-miss sites at 0x63e9b6c/0x63e9bac/0x63e9be8, 2 rets), verified by targeted objdump census and a fresh full raw-e8 scan (3 sites in that FDE, 168 total).
- Unknown: entry inputs' caller-side meaning; the table layout beyond the observed offsets (top index at table+0x0..0xf0, scan slots at 0x100..0x180); field semantics beyond observed reads/writes; the lu-miss handler's semantics beyond the call site; the exit value's meaning beyond its single data-dependent definition (the output pointer identity).
- Next question: packet #329 decodes 0x63e94a0..0x63e9bf2 (1,874 bytes, 396 strict, 3 calls — all lu-miss, at 0x63e9b6c, 0x63e9bac and 0x63e9be8 — 0 bin_table_init sites, 0 second-handler sites, 2 rets at 0x63e96b1 and 0x63e97a6, bsr 0 — the next and LAST surviving lu-miss caller after this packet; a lu-miss-ONLY survivor, not shared, like this packet).
