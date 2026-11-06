# RE-001-node115-lu-miss-caller-2site-ctypescan: ctype pre-scan, single walk, three exits

- Component ID: RE-001-node115-lu-miss-caller-2site-ctypescan
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the node-field semantics, and the dispatcher callees' semantics are unresolved and stated as such
- Scope included and excluded: included — FDE 0x63cddd0..0x63ce23b only (1131 bytes, 242 strict lines). Excluded — the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), second miss handler 0x634ebb0..0x634eccd, lock-wait helper 0x63bf680..0x63bf7ee (#251), all dispatcher callees, the prev FDE 0x63cd910..0x63cddce, the next FDE 0x63ce240..0x63ce501, and the #314–#322 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls323-115). Commands (no node execution; static analysis only):

- `objdump -d --start-address=0x63cddd0 --stop-address=0x63ce23b artifacts/node/115/hl-node` (exhibit lu_miss_caller_2site_ctypescan.objdump.txt; strict count uses regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_2site_ctypescan.py` (static verifier; exit 0)
- `python3 tests/test_node115_lu_miss_caller_2site_ctypescan.py` (tamper-first unit tests; exit 0)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

- Coordinates: virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .bss 0x64ffe40..0x6728924 (NOBITS, section size 0x228ae4).
- FDE bounds from own .eh_frame parse (135,313 FDEs total): window 0x63cddd0..0x63ce23b (1131 B); prev FDE 0x63cd910..0x63cddce (gap 2, all 0xcc); next FDE 0x63ce240..0x63ce501 (padding 5, all 0xcc; starts with endbr64 + pushes).
- Window shape: endbr64, NO canary, NO TLS flag check, NO byte table 0x67277c0. A __ctype_b_loc pre-scan over the rsi string; a call to the prev FDE 0x63cd910 (once); a single context-table walk keyed by the node pointer in 0x18(%r13); inline shr $0x30 extract + size table 0x6727a00; shl/sar $0x10 extract + node table 0x65096c0; lock sub refcount decrement; two 8-slot MTF scans (16 slot-compare instructions, 11 reversed-operand, 11 of 16 slot positions reversed); 2 lu-miss sites sharing one argument pattern with rcx provenance proven by reaching-definitions; 0 second-handler sites; THREE rets with three distinct exit values (0 / 14 / 11, one reaching def each).
- Calls (7, 6 distinct direct, 0 indirect): 0x63cd910 x1, 0x63c89c0 x1, 0x63c3780 x1, 0x63c3b00 x1, 0x63d9700 x2, __ctype_b_loc@plt x1. No bin_table_init, no lock-wait helper, no 0x63be540/0x63be4d0/0x63bd6c0 calls.
- Raw 0xe8 census (own .eh_frame parse): lu-miss 168 sites / 53 FDEs (this FDE 2); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0; next candidate holds 1).
- .rela.dyn: 60,723 total, 59,534 RELATIVE. .rela.plt: 278. Referenced addresses: 0x65096c0, 0x6511a00, 0x6727a00 (all inside .bss).
- Analysis was complete over the window (all 242 strict lines classified; 39 jumps, 0 outside). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #320's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

- Verifier exit 0 (314 checks, 0 failures); unit tests exit 0 (12 checks, 0 failures); `make verify` exit 0 (559/7159); `make catalogue-check` exit 2 (pre-existing, not a regression).
- Disjointness: window 0x63cddd0..0x63ce23b overlaps no prior range (verifier: 76,548 priors scanned, 0 skipped, NONE); next candidate 0x63d03a0..0x63d17d7 likewise disjoint.
- Unknown: entry inputs' caller-side meaning; node-field (0x68/0x18/0x21/0x330) semantics beyond observed reads/writes; dispatcher callees' semantics beyond call sites; exit values' meaning beyond their three distinct paths.
- Next question: packet #324 decodes 0x63d03a0..0x63d17d7 (5175 bytes, 1037 strict, 23 calls, 10 lu-miss sites, 0 bti, 1 second-handler site at 0x63d0837, 1 ret at 0x63d0817, bsr 2 — a SHARED survivor, unlike this packet).
