# RE-001-node115-lockwait-caller-1site-thunk: one lock-wait site, 16-byte thunk resolver, 4-value exit

- Component ID: RE-001-node115-lockwait-caller-1site-thunk
- Target release and full SHA-256: node #115, artifacts/node/115/hl-node, 105,896,032 bytes, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly census + reaching-definitions over the window CFG); the entry inputs' caller-side meaning, the field semantics, and the lock-wait helper's semantics beyond its observed call-site contract are unresolved
- Scope included and excluded: included — FDE 0x6386b60..0x6386eb0 only (848 bytes, 213 strict lines). Excluded — the lock-wait helper 0x63bf680..0x63bf7ee (#251), the lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init 0x63d9880..0x63d9a64 (#262), the second miss handler 0x634ebb0..0x634eccd, the key resolver 0x6365150..0x6365660, the 16-byte thunk callee 0x63643f0..0x6364400, the 11-byte count FDE 0x634eba0..0x634ebab, the prev FDE 0x6386940..0x6386b54, the next FDE 0x6386eb0..0x6387420, and the #314–#336 windows (cited, not claimed).

## Reproduce

Working directory: a worktree of upstream main 05bc2de30 (branch codex/re-004-calls337-115). No node execution; static analysis only.

- `objdump -d --start-address=0x6386b60 --stop-address=0x6386eb0 artifacts/node/115/hl-node` (exhibit lockwait_caller_1site_thunk.objdump.txt; 213 strict lines by regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`)
- `python3 tools/node115_lockwait_caller_1site_thunk.py` (static verifier; exit 0; 539 checks)
- `python3 tests/test_node115_lockwait_caller_1site_thunk.py` (tamper-first unit tests; exit 0; 13 checks)
- `make verify` (exit 0; 559/7159)
- `make catalogue-check` (exit 2; pre-existing `Stale catalogue: README.md`, also present on a pristine checkout)
- Full `make test` is not run (584 files on the new base; hours of runtime and VM-restart risk). This deviation is declared in the README and the PR body.

## Evidence

Original addresses and coordinate system (VA/file offset): virtual addresses; .text file offset = VA - 0x1000; .rodata = VA as-is; .data file offset = VA - 0x3000; .data.rel.ro file offset = VA - 0x2000; .bss 0x64ffe40..0x6728924 (NOBITS).

Validated boundaries (own .eh_frame parse, 135,313 FDEs total): window 0x6386b60..0x6386eb0 (848 B); prev FDE 0x6386940..0x6386b54 (gap 12 bytes, all 0xcc int3 padding); next FDE 0x6386eb0..0x6387420 (gap 0 bytes — the next FDE starts at END; starts with endbr64 at 0x6386eb0). The thunk FDE is 0x63643f0..0x6364400 (16 B, 3 strict); the count FDE is 0x634eba0..0x634ebab (11 B); the lock-wait helper FDE is 0x63bf680..0x63bf7ee.

Raw disassembly: exhibit lockwait_caller_1site_thunk.objdump.txt (213 strict lines). Raw binary: exhibit lockwait_caller_1site_thunk.hex (848 raw bytes, equal to the binary slice at file offset 0x6385b60).

Callers/callees/indirect calls: 6 calls (6 distinct direct targets, 0 indirect). Direct: 0x634eba0 x1 (count, 0x6386c28), 0x63643f0 x1 (thunk resolver, 0x6386c75), trylock@plt x1 (0x6386bad), unlock@plt x1 (0x6386bf7), lock-wait 0x63bf680 x1 (0x6386cb4), stack_chk_fail@plt x1 (0x6386e7c). Indirect: none. PLT determination is by `@plt` suffix only: the internal `.text` calls (0x634eba0, 0x63643f0, 0x63bf680) are NOT PLT stubs.

Source mapping evidence: none — no source mapping is claimed; all claims are disassembly observations. ABI/layout observations: entry rdi -> rbx, rsi -> rbp, rcx -> r13 (destination pointer), r8 -> 0x8(%rsp) (length pointer), r9 -> r12; frame sub $0x38, canary at 0x28(%rsp); the entry gate is the .data byte 0x64ffc28 (file byte 0x01, gate closed at load — the SAME byte as #334); the lock-wait node is 0x6712160 with mutex node+0x40 = 0x67121a0 and waited flag node+0x68 = 0x67121c8 (the SAME global .bss mutex object as #333/#335); the selector is index = *(entry rsi + 8), high 32 bits nonzero -> exit 14, count from 0x634eba0, NULL table entry -> exit 14; the thunk resolver forwards rdi = entry rdi, rsi = table entry + 0x29b0, rdx = output buffer lea 0x18(%rsp), rcx = r9 or the stack temp, and returns al (nonzero -> exit 14); the copy phase copies min(len, 8) bytes with a (len-1)>>3 & 7 remainder dispatch and an 8-at-a-time unrolled loop (r14d += 0x40 per iteration), then writes back *r8 = copied length and exits 22; len == 8 copies the resolved 8-byte value directly and exits 0. The single ret at 0x6386c21 returns r14d with reaching defs {0x6386b68 (2), 0x6386be7 (14), 0x6386c6c (14), 0x6386ca3 (0), 0x6386d00 (22)}.

Analysis was complete over the window (all 213 strict lines classified). The `.bss` objects are referenced by address only; their runtime contents are not established.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in this packet; the verifier is a static Python checker over the binary bytes, records.json, and exhibits (no node execution). Tamper controls (hex flip, strict-count change, call-site change, injected overlap of #333's window) each make the temp-copy verifier fail; the clean temp copy passes; byte-exact revert passes again. Objump regeneration matches the exhibit (header lines stripped).

## Results and limitations

Machine-readable metrics: verifier 539/0; unit tests 13/0; `make verify` 559/7159; `make catalogue-check` exit 2 (pre-existing). Disjointness: window 0x6386b60..0x6386eb0 overlaps no prior range (verifier: 88350 priors scanned, 0 skipped, NONE); next candidate 0x6387ff0..0x6388303 likewise disjoint. Raw 0xe8 census: lock-wait 474 sites / 385 FDEs (this FDE 1); lu-miss 168 / 53 (this FDE 0); bin_table_init 108 / 42 (this FDE 0); second-handler 64 / 28 (this FDE 0).

What passed/failed: all gates pass; nothing failed. What remains unknown: entry inputs' caller-side meaning; the field semantics beyond observed reads/writes; the lock-wait helper's semantics beyond its call-site contract; the contents of the .bss mutex fields and the runtime table 0x65096c0; the 0x63c17e0 tail-jump target's semantics beyond the thunk's observed forwarding contract; the 0x634eba0 count callee's semantics beyond its observed call-site contract.

Next question: 0x6387ff0..0x6388303 (787 bytes, 202 strict, 5 calls, 1 lock-wait site at 0x6388124, 0 lu-miss / 0 bin_table_init / 0 second-handler sites, 1 ret at 0x6388055, bsr 0, endbr64 1, canary present, 33 jumps, 0 outside, 3 PLT calls across 3 targets).
