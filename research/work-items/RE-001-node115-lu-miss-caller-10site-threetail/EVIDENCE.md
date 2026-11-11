# RE-001-node115-lu-miss-caller-10site-threetail: three walks, three tail jumps, ten miss sites, uniform 0 exit

- Component ID: RE-001-node115-lu-miss-caller-10site-threetail
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the dispatcher callees' semantics are unresolved and stated as such
- Scope included and excluded: included — FDE 0x63d17e0..0x63d2a80 only (4768 bytes, 928 strict lines). Excluded — the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), second miss handler 0x634ebb0..0x634eccd, lock-wait helper 0x63bf680..0x63bf7ee (#251), all dispatcher callees, the prev FDE 0x63d03a0..0x63d17d7 (#324), the next FDE 0x63d2a80..0x63d3071, and the #314–#324 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls325-115). Commands (no node execution; static analysis only):

- `objdump -d --start-address=0x63d17e0 --stop-address=0x63d2a80 artifacts/node/115/hl-node` (exhibit lu_miss_caller_10site_threetail.objdump.txt; strict count uses regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_10site_threetail.py` (static verifier; exit 0)
- `python3 tests/test_node115_lu_miss_caller_10site_threetail.py` (tamper-first unit tests; exit 0)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

- Coordinates: virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .bss 0x64ffe40..0x6728924 (NOBITS, section size 0x228ae4).
- FDE bounds from own .eh_frame parse (135,313 FDEs total): window 0x63d17e0..0x63d2a80 (4768 B); prev FDE 0x63d03a0..0x63d17d7 (gap 9, all 0xcc); next FDE 0x63d2a80..0x63d3071 (padding 0; starts with endbr64).
- Window shape: NO endbr64 (first instruction push %r15 — the second frontier window without one, after #324), canary present, NO TLS flag check. NO outer loop: the size class is computed once at entry from the remaining count (shl, $0x3800 / $0x1000 thresholds, byte table 0x67277c0, size table 0x6727a00, $0x3fff cap, 0x6728140 fallback, $0x4000 cap, two bsr overflow arms); cmpb $0x0,0x1(%r14) gates the second-handler path; key resolver 0x6365150 returns the walk-A key; three context-table walks (A key from resolver return, lock add; B key from the saved node pointer in 0x8(%rsp), lock sub; C key r10, lock sub) with inline shr $0x30 extracts + size table 0x6727a00 and shl/sar $0x10 extracts + node table 0x65096c0; an element loop calling prev FDE 0x63d0080 once per element; a deep-resolution tail (0x63bd6c0, 0x63637f0, 0x6363260); ten 8-slot MTF scans (68 slot-compare instructions, 17 reversed-operand, 17 of 80 slot positions reversed; eight unrolled chains, D1 and D2 counter loops); 10 lu-miss sites sharing one argument pattern with rcx provenance proven by reaching-definitions; 1 second-handler site; a SINGLE ret plus THREE tail-jump exits, all with rax = 0 uniformly.
- Calls (20, 11 distinct direct, 0 indirect): 0x6365150 x1, 0x63d0080 x1, 0x63637f0 x1, 0x634ebb0 x1, 0x6352fc0 x1, 0x63edf10 x1, 0x63bd6c0 x1, 0x63ec4c0 x1, 0x6363260 x1, 0x63d9700 x10, __stack_chk_fail@plt x1. Tail jumps (not calls): 0x63637f0 at 0x63d1abe, 0x63bd6c0 at 0x63d212c, 0x6363260 at 0x63d2450. No bin_table_init, no lock-wait helper, no #314–#324 window calls.
- Raw 0xe8 census (own .eh_frame parse): lu-miss 168 sites / 53 FDEs (this FDE 10); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 1; next candidate holds 1).
- .rela.dyn: 60,723 total, 59,534 RELATIVE. .rela.plt: 278. Referenced addresses: 0x65096c0, 0x6511a00, 0x67277c0, 0x6727a00, 0x6728140 (all inside .bss); 0x64da4b0 (inside .data.rel.ro).
- Analysis was complete over the window (all 928 strict lines classified; 156 jumps, 3 outside — all three tail jumps). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #324's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

- Verifier exit 0 (599 checks, 0 failures); unit tests exit 0 (12 checks, 0 failures); `make verify` exit 0 (559/7159); `make catalogue-check` exit 2 (pre-existing, not a regression).
- Disjointness: window 0x63d17e0..0x63d2a80 overlaps no prior range (verifier: 78234 priors scanned, 0 skipped, NONE); next candidate 0x63d2a80..0x63d3071 likewise disjoint.
- Corrections made during the build (all caught by byte-level verification, not by the handoff draft): the scan→miss-site mapping is A1→1, A2→2, C1→3, C2→4, C3→5, B3→6, D1→7, B1→8, B2→9, D2→10 (the draft had B1→9, B3→10, D2→8); the rcx groups are sites 3, 4, 5, 10 = r10 walk-C key and sites 6, 7, 8, 9 = 0x8(%rsp) walk-B key (the draft had sites 8 and 10 swapped); B2 reversed slots are [3, 4, 5, 6], not [1, 2]; site 1's rdx IS the walk table pointer (via r12, lea 0x1b0(%r14),%r12 at 0x63d18c1 — its only reaching definition there), not a size-class value.
- Unknown: entry inputs' caller-side meaning; field (0x14/0x88/0x1) semantics beyond observed reads/writes; dispatcher callees' semantics beyond call sites; the exit value's meaning beyond its uniform 0.
- Next question: packet #326 decodes 0x63d2a80..0x63d3071 (1521 bytes, 313 strict, 7 calls, 2 lu-miss sites, 0 bti, 1 second-handler site at 0x63d2d51, 1 ret at 0x63d2c97, bsr 2 — also a SHARED survivor, like this packet).
