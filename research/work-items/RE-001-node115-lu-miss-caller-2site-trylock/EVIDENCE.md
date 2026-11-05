# RE-001-node115-lu-miss-caller-2site-trylock: trylock-guarded linked-list walk with two lu-miss sites

- Component ID: RE-001-node115-lu-miss-caller-2site-trylock
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the node-field semantics, and the dispatcher callees' semantics are unresolved and stated as such
- Scope included and excluded: included — FDE 0x63c9650..0x63c9c80 only (1584 bytes, 363 strict lines). Excluded — the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), second miss handler 0x634ebb0..0x634eccd, lock-wait helper 0x63bf680..0x63bf7ee (#251), all dispatcher callees, the prev FDE 0x63c9500..0x63c964d, the next FDE 0x63c9c80..0x63cb146, and the #314–#320 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls321-115). Commands (no node execution; static analysis only):

- `objdump -d --start-address=0x63c9650 --stop-address=0x63c9c80 artifacts/node/115/hl-node` (exhibit lu_miss_caller_2site_trylock.objdump.txt; strict count uses regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_2site_trylock.py` (static verifier; exit 0)
- `python3 tests/test_node115_lu_miss_caller_2site_trylock.py` (tamper-first unit tests; exit 0)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

- Coordinates: virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .bss 0x64ffe40..0x6728924 (NOBITS, section size 0x228ae4).
- FDE bounds from own .eh_frame parse (135,313 FDEs total): window 0x63c9650..0x63c9c80 (1584 B); prev FDE 0x63c9500..0x63c964d (gap 3, all 0xcc); next FDE 0x63c9c80..0x63cb146 (padding 0; starts with push %r15/%r14/%r13/%r12, no endbr64).
- Window shape: NO endbr64, NO canary, NO TLS flag check, NO size class. Entry null guard on the list head; outer linked-list walk over 0x18 next pointers; pthread_mutex_trylock guard with a lock-wait-helper (0x63bf680) retry arm; refcount addq at 0x38(%rbx); three-field ordered-insert key compare (0x8, 0x10, 0x68) via setb/sbb; field dispatch on 0x84(%rbp) (2 -> set 1, 3 -> chain advance); single context-table walk keyed by the node pointer in r12; inline shr $0x30 extract + size table 0x6727a00; shl/sar $0x10 extract + node table 0x65096c0 + lock sub refcount decrement; two 8-slot MTF scans (16 slot compares, exactly 1 reversed-operand at 0x63c998f); 2 lu-miss sites sharing one argument pattern with rcx provenance proven by reaching-definitions (only 0x63c9713 and 0x63c97fd reach either site); exit rax path-dependent (3 reaching defs at ret).
- Calls (12, 10 distinct direct, 0 indirect): 0x63c58b0 x1, pthread_mutex_trylock@plt x1, 0x63c7620 x1, 0x63c50e0 x1, 0x63c89c0 x1, 0x63c7ef0 x1, pthread_mutex_unlock@plt x2, 0x63bf680 x1, 0x63c9500 x1, 0x63d9700 x2. No bin_table_init, no second-handler, no 0x63be540/0x63be4d0/0x63bd6c0 calls.
- Raw 0xe8 census (own .eh_frame parse): lu-miss 168 sites / 53 FDEs (this FDE 2); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0; next candidate holds 1).
- .rela.dyn: 60,723 total, 59,534 RELATIVE. .rela.plt: 278. Referenced addresses: 0x65096c0, 0x6511a00, 0x6713601, 0x6727a00 (all inside .bss); 0x63c4c40 (inside .text; 45-byte field-check callback FDE 0x63c4c40..0x63c4c6d).
- Analysis was complete over the window (all 363 strict lines classified; 58 jumps, 0 outside). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #320's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

- Verifier exit 0 (295 checks, 0 failures); unit tests exit 0 (12 checks, 0 failures); `make verify` exit 0 (559/7159); `make catalogue-check` exit 2 (pre-existing, not a regression).
- Disjointness: window 0x63c9650..0x63c9c80 overlaps no prior range (verifier: 74,862 priors scanned, 0 skipped, NONE); next candidate 0x63ccd60..0x63cd907 likewise disjoint.
- Unknown: entry inputs' caller-side meaning; node-field (0x28/0x30/0x38/0x68) semantics beyond observed reads/writes; dispatcher callees' semantics beyond call sites; exit value's meaning beyond path-dependence.
- Next question: packet #322 decodes 0x63ccd60..0x63cd907 (2983 bytes, 613 strict, 31 calls, 6 lu-miss sites, 0 bti, 1 second-handler site, 1 ret at 0x63cd044, bsr 0 — a SHARED survivor, unlike this packet).
