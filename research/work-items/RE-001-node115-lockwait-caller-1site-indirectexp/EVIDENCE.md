# RE-001-node115-lockwait-caller-1site-indirectexp: one lock-wait site, indirect callback, exp-based leak summary

- Component ID: RE-001-node115-lockwait-caller-1site-indirectexp
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the lock-wait helper's semantics beyond its observed call-site contract are unresolved
- Scope included and excluded: included — FDE 0x63ce510..0x63ce8b8 only (936 bytes, 216 strict lines). Excluded — the lock-wait helper 0x63bf680..0x63bf7ee (#251), the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), the second miss handler 0x634ebb0..0x634eccd, the key resolver 0x6365150..0x6365660, the log-helper FDE 0x63bf5b6..0x63bf677, #321's window 0x63c9650..0x63c9c80 (called once from this window), the prev FDE 0x63ce240..0x63ce501, the next FDE 0x63ce8c0..0x63cf8bc, and the #314–#335 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls336-115). No node execution; static analysis only.

- `objdump -d --start-address=0x63ce510 --stop-address=0x63ce8b8 artifacts/node/115/hl-node` (exhibit lockwait_caller_1site_indirectexp.objdump.txt; 216 strict lines by regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lockwait_caller_1site_indirectexp.py` (static verifier; exit 0; 507 checks)
- `python3 tests/test_node115_lockwait_caller_1site_indirectexp.py` (tamper-first unit tests; exit 0; 13 checks)
- `make verify` (exit 0; 559 evidence-packet manifests, 7159 entries)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

Original addresses and coordinate system (VA/file offset): virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .data file offset = VA - 0x3000; .data.rel.ro file offset = VA - 0x2000; .bss 0x64ffe40..0x6728924 (NOBITS).

Validated boundaries (own .eh_frame parse, 135,313 FDEs total): window 0x63ce510..0x63ce8b8 (936 B); prev FDE 0x63ce240..0x63ce501 (gap 15 bytes, all 0xcc int3 padding); next FDE 0x63ce8c0..0x63cf8bc (gap 8 bytes, all 0xcc int3 padding; starts with endbr64 at 0x63ce8c0). The log-helper FDE is 0x63bf5b6..0x63bf677 (193 B, 37 strict); the lock-wait helper FDE is 0x63bf680..0x63bf7ee; #321's FDE is 0x63c9650..0x63c9c80 (1,584 B).

Raw disassembly: exhibit lockwait_caller_1site_indirectexp.objdump.txt (216 strict lines). Raw binary: exhibit lockwait_caller_1site_indirectexp.hex (936 raw bytes, equal to the binary slice at file offset 0x63cd510).

Callers/callees/indirect calls: 19 calls (15 distinct direct targets, 1 indirect). Direct: 0x63c8490 x1, 0x63c4c70 x1, 0x63c6bf0 x1, trylock@plt x1, 0x63c7080 x1, unlock@plt x1, 0x63c78f0 x1, 0x63c7fe0 x1, 0x63c9650 x1 (#321's window), lock-wait 0x63bf680 x1, exp@plt x1, 0x63efe40 x2, 0x63bf5b6 x3 (log helper), _exit@plt x1, stack_chk_fail@plt x1. Indirect: `call *0x28(%rsp)` at 0x63ce5be — the slot holds entry rsi (mov %rbp,0x28(%rsp) at 0x63ce573), so the callee is *(entry rsi), the first qword of the object at entry rsi; rdi = entry rdx, rsi = .rodata 0x4451e9 ("\n"); return value discarded.

Source mapping evidence: none — no source mapping is claimed; all claims are disassembly observations. ABI/layout observations: entry rdi -> r12, rsi -> rbp, rdx -> r13 (overwritten by the mutex lea), r8d -> r14d (flag byte); frame sub $0x98, canary at 0x88(%rsp); the lock-wait node is 0x67145a0 with mutex node+0x40 = 0x67145e0 and waited flag node+0x68 = 0x6714608; the list walk strips the low bit of the link (and $0xfffffffffffffffe,%r15) and terminates when the link value is <= 1; the slow path converts two int64 inputs to double with the (x>>1)|(x&1) + addsd-doubling idiom and uses exp@plt with the standard 2^63 cvttsd2si overflow handling (btc $0x3f x2). The .rodata strings 0x964628 / 0x95b6c0 / 0x958228 are jemalloc leak-report messages; the plural suffixes "s" (0x43a810) vs "" (0x4376fd) are chosen by cmove on count == 1.

Analysis was complete over the window (all 216 strict lines classified). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #333's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

Machine-readable metrics: verifier 507/0; unit tests 13/0; `make verify` 559/7159; `make catalogue-check` exit 2 (pre-existing). Disjointness: window 0x63ce510..0x63ce8b8 overlaps no prior range (verifier: 87,507 priors scanned, 0 skipped, NONE); next candidate 0x6386b60..0x6386eb0 likewise disjoint. Raw 0xe8 census: lock-wait 474 sites / 385 FDEs (this FDE 1); lu-miss 168 / 53 (this FDE 0); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0).

What passed/failed: all gates pass; nothing failed. What remains unknown: entry inputs' caller-side meaning; the field semantics beyond observed reads/writes; the lock-wait helper's semantics beyond its call-site contract; the contents of the .bss mutex fields and the 0x6712438 shift byte; the 0x63c8490/0x63c4c70/0x63c6bf0/0x63c7080/0x63c78f0/0x63c7fe0/0x63efe40 callees' semantics beyond their observed call-site contracts; the indirect callee's identity beyond *(entry rsi).

Next question: 0x6386b60..0x6386eb0 (848 bytes, 213 strict, 6 calls, 1 lock-wait site at 0x6386cb4, 0 lu-miss / 0 bin_table_init / 0 second-handler sites, 1 ret at 0x6386c21, bsr 0, endbr64 1, canary present, 34 jumps, 0 outside, 3 PLT calls across 3 targets).
