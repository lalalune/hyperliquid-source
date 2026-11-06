# RE-001-node115-lu-miss-caller-2site-singlewalk: one walk, two miss sites, 0-or-1 exit

- Component ID: RE-001-node115-lu-miss-caller-2site-singlewalk
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the dispatcher callees' semantics are unresolved and stated as such
- Scope included and excluded: included — FDE 0x63d2a80..0x63d3071 only (1521 bytes, 313 strict lines). Excluded — the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), second miss handler 0x634ebb0..0x634eccd, lock-wait helper 0x63bf680..0x63bf7ee (#251), all dispatcher callees, the prev FDE 0x63d17e0..0x63d2a80 (#325), the next FDE 0x63d3080..0x63d379c, and the #314–#325 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls326-115). Commands (no node execution; static analysis only):

- `objdump -d --start-address=0x63d2a80 --stop-address=0x63d3071 artifacts/node/115/hl-node` (exhibit lu_miss_caller_2site_singlewalk.objdump.txt; strict count uses regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_2site_singlewalk.py` (static verifier; exit 0)
- `python3 tests/test_node115_lu_miss_caller_2site_singlewalk.py` (tamper-first unit tests; exit 0)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

- Coordinates: virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .bss 0x64ffe40..0x6728924 (NOBITS, section size 0x228ae4).
- FDE bounds from own .eh_frame parse (135,313 FDEs total): window 0x63d2a80..0x63d3071 (1521 B); prev FDE 0x63d17e0..0x63d2a80 (gap 0, directly adjacent); next FDE 0x63d3080..0x63d379c (padding 15, all 0xcc; starts with endbr64).
- Window shape: endbr64 present (first instruction), NO canary (no %fs:0x28, no __stack_chk_fail call), NO TLS flag check. Single walk (walk A only): the size class is computed once at entry from the input count (divide-by-3 prologue via mul by 0xaaaaaaaaaaaaaaab, power-of-two r8 via a log2 loop, $0x3800 / $0x1000 / $0x4000 thresholds, byte table 0x67277c0, size table 0x6727a00, $0x3fff cap, 0x6728140 fallback, $0x4000 cap, two bsr overflow arms); the rsi struct is initialized at entry (16-byte constant from 0x454c10 via movups, then fields 0x10/0x18/0x20/0x28); cmpb $0x0,0x1(%rbp) gates the second-handler path; key resolver 0x6365150 returns the walk key; walk A (key = resolver return, lock add) with inline shr $0x30 extract + size table 0x6727a00 and shl/sar $0x10 extract + node table 0x65096c0; two 8-slot MTF scans (16 slot-compare instructions, 6 reversed-operand, 6 of 16 slot positions reversed; slot 0 and slot 1 checked directly, slots 2–7 unrolled chain); 2 lu-miss sites sharing one argument pattern with rcx provenance proven by reaching-definitions; 1 second-handler site; a SINGLE ret with two reaching rax definitions (0 or 1). No walk B/C, no element loop, no prev-FDE call, no deep-resolution tail, no tail jumps.
- Calls (7, 6 distinct direct, 0 indirect): 0x6365150 x1, 0x634ebb0 x1, 0x6352fc0 x1, 0x63edf10 x1, 0x63ec4c0 x1, 0x63d9700 x2. No bin_table_init, no lock-wait helper, no #314–#325 window calls, no PLT calls.
- Raw 0xe8 census (own .eh_frame parse): lu-miss 168 sites / 53 FDEs (this FDE 2); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 1; next candidate holds 0).
- .rela.dyn: 60,723 total, 59,534 RELATIVE. .rela.plt: 278. Referenced addresses: 0x65096c0, 0x6511a00, 0x67277c0, 0x6727a00, 0x6728140 (all inside .bss); 0x64da4b0 (inside .data.rel.ro).
- Analysis was complete over the window (all 313 strict lines classified; 51 jumps, 0 outside). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #325's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

- Verifier exit 0 (375 checks, 0 failures); unit tests exit 0 (12 checks, 0 failures); `make verify` exit 0 (559/7159); `make catalogue-check` exit 2 (pre-existing, not a regression).
- Disjointness: window 0x63d2a80..0x63d3071 overlaps no prior range (verifier: 79,077 priors scanned, 0 skipped, NONE); next candidate 0x63d3f0e..0x63d4048 likewise disjoint.
- Corrections made during the build: none to #325's pointer (verified correct, prior_pointer_verified). The pre-build handoff draft's figures for this window (1521 bytes, 313 strict, 7 calls, 2 lu-miss, 0 bti, 1 second-handler, 1 ret, bsr 2) were all confirmed by targeted census; the draft did not state canary/lock/TLS figures, which this packet establishes by direct census (no canary, lock add 1 / lock sub 0, no TLS flag check).
- Unknown: entry inputs' caller-side meaning; the count-rounding arithmetic's caller-side meaning beyond the observed operations; field (0x14/0x88/0x1) semantics beyond observed reads/writes; dispatcher callees' semantics beyond call sites; the exit values' meaning beyond their two distinct paths.
- Next question: packet #327 decodes 0x63d3f0e..0x63d4048 (314 bytes, 75 strict, 1 call, 1 lu-miss site at 0x63d4003, 0 bin_table_init sites, 0 second-handler sites, 1 ret at 0x63d4047, bsr 0 — the next surviving lu-miss caller after this packet; a lu-miss-ONLY survivor, not shared, unlike this packet).
