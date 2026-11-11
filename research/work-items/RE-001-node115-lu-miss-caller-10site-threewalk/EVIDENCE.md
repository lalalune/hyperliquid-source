# RE-001-node115-lu-miss-caller-10site-threewalk: three walks, outer size-class loop, ten miss sites

- Component ID: RE-001-node115-lu-miss-caller-10site-threewalk
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the dispatcher callees' semantics are unresolved and stated as such
- Scope included and excluded: included — FDE 0x63d03a0..0x63d17d7 only (5175 bytes, 1037 strict lines). Excluded — the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), second miss handler 0x634ebb0..0x634eccd, lock-wait helper 0x63bf680..0x63bf7ee (#251), all dispatcher callees, the prev FDE 0x63d0080..0x63d0398, the next FDE 0x63d17e0..0x63d2a80, and the #314–#323 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls324-115). Commands (no node execution; static analysis only):

- `objdump -d --start-address=0x63d03a0 --stop-address=0x63d17d7 artifacts/node/115/hl-node` (exhibit lu_miss_caller_10site_threewalk.objdump.txt; strict count uses regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_10site_threewalk.py` (static verifier; exit 0)
- `python3 tests/test_node115_lu_miss_caller_10site_threewalk.py` (tamper-first unit tests; exit 0)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

- Coordinates: virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .bss 0x64ffe40..0x6728924 (NOBITS, section size 0x228ae4).
- FDE bounds from own .eh_frame parse (135,313 FDEs total): window 0x63d03a0..0x63d17d7 (5175 B); prev FDE 0x63d0080..0x63d0398 (gap 8, all 0xcc); next FDE 0x63d17e0..0x63d2a80 (padding 9, all 0xcc; starts with push %r15, NO endbr64).
- Window shape: NO endbr64 (first instruction push %r15), canary present, NO TLS flag check. An outer loop recomputes the size class each iteration from the remaining count (shl, $0x3800 / $0x1000 thresholds, byte table 0x67277c0, size table 0x6727a00, $0x3fff cap, 0x6728140 fallback, $0x4000 cap, two bsr paths); cmpb $0x0,0x1(%r15) gates the second-handler path; key resolver 0x6365150 returns the walk-A key; three context-table walks (A key r14 lock add, B key r10 lock sub, C key r12 lock sub) with inline shr $0x30 extracts + size table 0x6727a00 and shl/sar $0x10 extracts + node table 0x65096c0; an element loop calling prev FDE 0x63d0080 once per element; a deep-resolution tail (0x63bd6c0, 0x63637f0, 0x6363260) and a loop-back to 0x63d03d4; ten 8-slot MTF scans (74 slot-compare instructions, 18 reversed-operand, 18 of 80 slot positions reversed; nine unrolled chains, D1 a counter loop); 10 lu-miss sites sharing one argument pattern with rcx provenance proven by reaching-definitions; 1 second-handler site; a SINGLE ret with two possible exit values (0 / 1).
- Calls (23, 11 distinct direct, 0 indirect): 0x6365150 x1, 0x63d0080 x1, 0x63637f0 x2, 0x634ebb0 x1, 0x6352fc0 x1, 0x63edf10 x1, 0x63bd6c0 x2, 0x63ec4c0 x1, 0x6363260 x2, 0x63d9700 x10, __stack_chk_fail@plt x1. No bin_table_init, no lock-wait helper, no #314–#323 window calls.
- Raw 0xe8 census (own .eh_frame parse): lu-miss 168 sites / 53 FDEs (this FDE 10); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 1; next candidate holds 1).
- .rela.dyn: 60,723 total, 59,534 RELATIVE. .rela.plt: 278. Referenced addresses: 0x65096c0, 0x6511a00, 0x67277c0, 0x6727a00, 0x6728140 (all inside .bss); 0x64da4b0 (inside .data.rel.ro).
- Analysis was complete over the window (all 1037 strict lines classified; 172 jumps, 0 outside). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #323's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

- Verifier exit 0 (502 checks, 0 failures); unit tests exit 0 (12 checks, 0 failures); `make verify` exit 0 (559/7159); `make catalogue-check` exit 2 (pre-existing, not a regression).
- Disjointness: window 0x63d03a0..0x63d17d7 overlaps no prior range (verifier: 77,391 priors scanned, 0 skipped, NONE); next candidate 0x63d17e0..0x63d2a80 likewise disjoint.
- Unknown: entry inputs' caller-side meaning; field (0x14/0x88/0x1) semantics beyond observed reads/writes; dispatcher callees' semantics beyond call sites; exit values' meaning beyond their two distinct paths.
- Next question: packet #325 decodes 0x63d17e0..0x63d2a80 (4768 bytes, 928 strict, 20 calls, 10 lu-miss sites, 0 bti, 1 second-handler site at 0x63d1c81, 1 ret at 0x63d1bd7, bsr 2 — also a SHARED survivor, like this packet).
