# RE-001-node115-lu-miss-caller-1site-dispatch3: lu-miss caller with a dispatch body (third dispatcher)

- Component ID: RE-001-node115-lu-miss-caller-1site-dispatch3
- Target release and full SHA-256: node #115, a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301, 105,896,032 bytes
- Source commit / reference commit: upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation
- Scope included and excluded: FDE 0x63577f0..0x635a786 only (12,182 bytes, 2679 strict lines). Cited, not claimed: lu-miss handler 0x63d9700..0x63d987b (#215), bin_table_init body 0x63d9880..0x63d9a64 (#262), second miss handler 0x634ebb0..0x634eccd, lock-wait helper 0x63bf680..0x63bf7ee (#251), extract helper 0x63be540..0x63be54d, 18B thunk 0x63bd2c0..0x63bd2d2, context helper 0x63ef8e0..0x63efba2, PLT stubs, #314/#313/#298/#316/#315 windows, prev/next FDEs.

## Reproduce

Working directory: the packet worktree (~/workspace/hl-wt-calls317-115 at upstream main 05bc2de30). Binary: artifacts/node/115/hl-node (SHA-256 above).

- `objdump -d --start-address=0x63577f0 --stop-address=0x635a786 artifacts/node/115/hl-node` reproduces lu_miss_caller_1site_dispatch3.objdump.txt (header lines stripped in the test's comparison).
- The raw slice `dd if=artifacts/node/115/hl-node of=lu_miss_caller_1site_dispatch3.hex bs=1 skip=$((0x63577f0-0x1000)) count=12182` reproduces the .hex exhibit byte-for-byte (.text file offset = VA - 0x1000).
- `python3 tools/node115_lu_miss_caller_1site_dispatch3.py` (static verifier, byte reads only, no node execution): exit 0, 226 checks, 0 failures.
- `python3 tests/test_node115_lu_miss_caller_1site_dispatch3.py`: exit 0, 12 checks, 0 failures (tamper controls first).
- `make verify`: exit 0 (559 manifests, 7159 entries). `make catalogue-check`: exit 2, pre-existing `Stale catalogue: README.md` (also on a pristine checkout). Full `make test` not run (584 files; declared deviation).

## Evidence

- FDE bounds from own .eh_frame parse (135,313 FDEs, sorted before bisect; CIE zR encoding 0x1b; FDE range field fixed 4 bytes): 0x63577f0..0x635a786 (12,182 bytes). Prev FDE 0x6355900..0x63577e2 (#316, gap 14, all 0xcc). Next FDE 0x635a790..0x635a79b (padding 10, all 0xcc; 11-byte thunk: endbr64, xor %ecx,%ecx, jmp 0x63577f0).
- Strict count 2679 with regex `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` (space-padded bytes column). Calls 132 by objdump mnemonic (35 distinct direct targets + 1 indirect via GOT 0x64ffb38 at 0x6358e7e).
- Entry: endbr64; pushes r15/r14/r13/r12/rbp/rbx; sub $0xa8,%rsp; canary %fs:0x28 -> 0x98(%rsp); rdi -> r11, esi -> rbp (movslq); TLS flag cmpb $0x0,%fs:0x330(%rbx) at 0x635782d; context via call 0x63ef8e0 at 0x6357864.
- Size class: byte table 0x67277c0 + size table 0x6727a00 (two small paths at 0x63578f3 and 0x63581c5); twelve bsr power-of-two roundings (0x6358022, 0x635824b, 0x63582a0, 0x6358558, 0x6358bc1, 0x6359362, 0x63594b0, 0x6359598, 0x63599f4, 0x635a1d5, 0x635a2a4, 0x635a57f).
- Walk (single, table rbx+0x1b0, key r12 loaded at 0x6357fb4): top (key>>0x1a)&0xf0, high bits key & 0xffffffffc0000000, top load 0x1b0(%r14), compare at 0x635811e, mismatch to scan 0x63591e4; second level (key>>0x9)&0x1ffff8 + 0x1b8(%r14), deref at 0x635813a. Node-resolution table 0x65096c0 read at 0x635816c.
- Extract: shl/sar $0x10 + and $0xffffffffffffff80 at 0x635813d..0x6358145, helper 0x63be540 at 0x6358149 (2 sites).
- Scan (single 8-slot MTF, table+0x2b0 in rbx, key in r15): slot 0 at 0x63591e4, loop at 0x635a018 (slots 1-7 share compare at 0x635a024), exhaustion at 0x635a6a2 (cmp $0x8,%rdi), 0 reversed-operand compares.
- Lu-miss (1): block 0x635a6b0, call 0x635a6cd -> 0x63d9700; rdi=rbx, rsi=0x6511a00 (.bss), rdx=lea 0x1b0(%rbx), rcx=r12 walk key (write-set check: no r12 write on the walk -> scan -> miss path), r8d=1, r9d=0; rejoin jmp 0x635813a.
- Second-handler (10): all rdi=rbx, rdx=lea 0x64da4b0 (.data.rel.ro); rsi r12d x6, 0 x2, r14 x1, not established x1.
- Dispatcher: 0x6364880 x13, 0x63e9cd0 x12, 0x6353610 x10, 0x6365150 x8, 0x63ed8b0 x8, 0x63bd2c0 x8, memset@plt x11, 0x63e9c40 x4, 0x63edf10 x4, plus #314 x1, #313 x2, #298 x2.
- Exit: ret 1 at 0x6357e19, rax = r12 (mov %r12,%rax at 0x6357e0c); 0 tail-jump exits; 495 jumps, all inside; lock 0/0; canary failure calls __stack_chk_fail at 0x6359adb.
- .bss 0x64ffe40..0x6728924 (exact end asserted); 14 referenced addresses inside .bss; 0x64da4b0 inside .data.rel.ro; GOT slots in .data.
- Raw-e8 census: lu-miss 168 sites / 53 FDEs (this FDE 1); bin_table_init 108 sites / 42 FDEs (this FDE 0). .rela.dyn 60,723 total / 59,534 RELATIVE; .rela.plt 278.
- Correction: #316's pointer listed bsr 0 for this window; the targeted census finds 12 bsr sites. All other pointer figures verified correct.

## Implementation and comparison

Not yet implemented/measured (static decode packet only; no Rust reconstruction in this packet).

## Results and limitations

- Static verifier exit 0 (226 checks, 0 failures); own unit tests exit 0 (12 checks); make verify exit 0 (559/7159); make catalogue-check exit 2 (pre-existing, not a regression).
- Disjointness NONE over all priors (verifier-scanned count in the README Disjointness section); slug unique vs committed tree.
- Unknown: entry rsi index's caller-side meaning; r12 walk key's caller-side meaning beyond its table-slot load; dispatcher callees' semantics beyond call sites; .bss table contents (runtime-populated).
- Next question: packet #318 decodes 0x635a7a0..0x635c6c7 (7975 bytes, 1720 strict, 103 calls, 4 lu-miss sites, 0 bin_table_init sites, 2 second-handler sites, 1 ret at 0x635ab53, bsr 7).
