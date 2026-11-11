# RE-001-node115-lu-miss-caller-6site-twowalk: trylock-guarded install with two walks and six lu-miss sites

- Component ID: RE-001-node115-lu-miss-caller-6site-twowalk
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the node-field semantics, and the dispatcher callees' semantics are unresolved and stated as such
- Scope included and excluded: included — FDE 0x63ccd60..0x63cd907 only (2983 bytes, 613 strict lines). Excluded — the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), second miss handler 0x634ebb0..0x634eccd, lock-wait helper 0x63bf680..0x63bf7ee (#251), all dispatcher callees, the prev FDE 0x63ccd30..0x63ccd5e, the next FDE 0x63cd910..0x63cddce, and the #314–#321 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls322-115). Commands (no node execution; static analysis only):

- `objdump -d --start-address=0x63ccd60 --stop-address=0x63cd907 artifacts/node/115/hl-node` (exhibit lu_miss_caller_6site_twowalk.objdump.txt; strict count uses regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lu_miss_caller_6site_twowalk.py` (static verifier; exit 0)
- `python3 tests/test_node115_lu_miss_caller_6site_twowalk.py` (tamper-first unit tests; exit 0)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

- Coordinates: virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .bss 0x64ffe40..0x6728924 (NOBITS, section size 0x228ae4).
- FDE bounds from own .eh_frame parse (135,313 FDEs total): window 0x63ccd60..0x63cd907 (2983 B); prev FDE 0x63ccd30..0x63ccd5e (gap 2, all 0xcc); next FDE 0x63cd910..0x63cddce (padding 9, all 0xcc; starts with endbr64 + pushes).
- Window shape: endbr64, canary (%fs:0x28), NO TLS flag check, size class via byte table 0x67277c0 feeding the key-resolver helper 0x6364880. Trylock-guarded install (0x63d3aa0 probe, 0x63cba10 allocator, 16-byte zero-init plus node-field init, three lock-wait-helper retry arms at 0x63cd048, 0x63cd140, 0x63cd218); two context-table walks over rbx + 0x1b0 (walk A keyed by the 0x6364880 return, walk B keyed by the saved node pointer in 0x20(%rsp)); inline shr $0x30 extracts (3 sites) + size table 0x6727a00; shl/sar $0x10 extracts (3 sites) + node table 0x65096c0; lock add (walk A) and lock sub (walk B) refcount steps; six 8-slot MTF scans (24 slot-compare instructions, 8 reversed-operand, 14 of 48 slot positions reversed); 6 lu-miss sites sharing one argument pattern with rcx provenance proven by reaching-definitions (noreturn-aware); 1 second-handler site gated on the node table being null; exit rax path-dependent (5 reaching defs at ret).
- Calls (31, 18 distinct direct, 0 indirect): 0x6364880 x1, 0x63d3aa0 x1, 0x63cba10 x1, 0x63d39a0 x1, 0x63c66d0 x1, 0x6352fc0 x1, 0x63edf10 x1, 0x63ec4c0 x1, 0x63bd6c0 x1, 0x63637f0 x1 (#300), 0x6363260 x1 (#298), 0x63bf680 x3, 0x63c9500 x2, 0x63d9700 x6, pthread_mutex_trylock@plt x3, pthread_mutex_unlock@plt x4, __stack_chk_fail@plt x1. No bin_table_init, no 0x63be540/0x63be4d0 calls.
- Raw 0xe8 census (own .eh_frame parse): lu-miss 168 sites / 53 FDEs (this FDE 6); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 1; next candidate holds 0).
- .rela.dyn: 60,723 total, 59,534 RELATIVE. .rela.plt: 278. Referenced addresses: 0x65096c0, 0x6511a00, 0x67277c0, 0x6727a00 (all inside .bss); 0x64da4b0 (inside .data.rel.ro).
- Analysis was complete over the window (all 613 strict lines classified; 87 jumps, 0 outside). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #320's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

- Verifier exit 0 (480 checks, 0 failures); unit tests exit 0 (12 checks, 0 failures); `make verify` exit 0 (559/7159); `make catalogue-check` exit 2 (pre-existing, not a regression).
- Disjointness: window 0x63ccd60..0x63cd907 overlaps no prior range (verifier: 75,705 priors scanned, 0 skipped, NONE); next candidate 0x63cddd0..0x63ce23b likewise disjoint.
- Unknown: entry inputs' caller-side meaning; node-field (0x28/0x30/0x38/0x68/0x80/0x84) semantics beyond observed reads/writes; dispatcher callees' semantics beyond call sites; exit value's meaning beyond path-dependence.
- Next question: packet #323 decodes 0x63cddd0..0x63ce23b (1131 bytes, 242 strict, 7 calls, 2 lu-miss sites, 0 bti, 0 second-handler sites, THREE rets at 0x63cdf2f / 0x63cdf43 / 0x63cdf7a, bsr 0 — a lu-miss-ONLY survivor, unlike this packet).
