# RE-001-node115-lu-miss-caller-1site-dispatch2: lu-miss caller with a dispatch body (second dispatcher)

- Component ID: RE-001-node115-lu-miss-caller-1site-dispatch2
- Target release and full SHA-256: node #115,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
  (105,896,032 bytes, artifacts/node/115/hl-node)
- Source commit / reference commit: upstream main
  05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (static disassembly only; no node execution)
- Scope included and excluded: included — the single FDE
  0x6355900..0x63577e2 (7906 bytes) and its walk/scan/miss structure
  plus its dispatcher callees by address only. Excluded — the lu-miss
  handler, the bin_table_init body, the second miss handler, the
  lock-wait helper, every dispatcher callee's body, the neighboring
  FDEs, and all runtime table contents.

## Reproduce

Working directory: a worktree of lalalune/hyperliquid-source at
upstream main 05bc2de303c05525b71e7e257426e741bc66a390.

```
objdump -d --start-address=0x6355900 --stop-address=0x63577e2 \
  artifacts/node/115/hl-node
python3 tools/node115_lu_miss_caller_1site_dispatch2.py
python3 tests/test_node115_lu_miss_caller_1site_dispatch2.py
make verify
make catalogue-check
```

Tool versions: GNU objdump (binutils, as installed in the VM),
Python 3. Static analysis only; the node binary is never executed.
No side effects beyond reading the binary and the worktree.

## Evidence

Addresses are virtual addresses (VA); file offset in .text is VA -
0x1000. FDE bounds come from an own .eh_frame parse (CIE zR
encoding 0x1b, FDE range field fixed 4 bytes, FDE list sorted before
bisect): window 0x6355900..0x63577e2 (7906 bytes); previous FDE
0x6355830..0x63558f2 (gap 14 bytes, all 0xcc); next FDE
0x63577f0..0x635a786 (padding 14 bytes, all 0xcc). Total FDEs parsed:
135,313. Strict mnemonic lines (regex
`^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]`): 1717. Calls: 111 (31 distinct
direct targets, 0 indirect). Ret: 1 at 0x6355aa8. Bsr: 8 at
0x6355e98, 0x6356547, 0x635696b, 0x6356c56, 0x6356ed5, 0x6357165,
0x63574a7, 0x63575f3. Jumps: 278, all inside the window. Lock: 0/0.

Entry: endbr64 at 0x6355900; pushes r15/r14/r13/r12/rbp/rbx;
sub $0xa8,%rsp; canary %fs:0x28 -> 0x98(%rsp); rdi -> r14,
rsi -> r12; rbx = %fs:0x0 + 0xffffffffffffef58 (TLS-derived context
base); cmpb $0x0,%fs:0x330(%rax) at 0x635593f, jne 0x6355c40 (init
block calls 0x63ef8e0, the #258 exclusion FDE). Size class: product
rdi*rsi (mul %r12 at 0x6355950, rbp = product, seto overflow flag);
byte table 0x67277c0 at index (rbp+7)>>3, cmp $0xe7, size table
0x6727a00, flag byte 0x6713606, thresholds $0x1000 (ja 0x6355e70,
bsr path, movabs $0x7000000000000000) and $0x3800.

Walk (single, key in r13): top index (r13>>0x1a)&0xf0, high bits
r13 & 0xffffffffc0000000, top entry 0x1b0(%r12), compare at
0x6356163 (mismatch -> scan at 0x6356b4d); second level
(r13>>0x9)&0x1ffff8 + 0x1b8(%r12), dereferenced into rdi at the
rejoin 0x6356180. Extract: shl/sar $0x10 + and $0xffffffffffffff80,
then call 0x63be540 at 0x635618f.

Scan (single 8-slot move-to-front, table+0x2b0 in rbx, key in rbp):
slot 0 inline cmp at 0x6356b4d; slots 1-7 share the loop compare at
0x635703d (rdi = 1..7); exhaustion at rdi == 8 reaches the lu-miss
block; MTF swap blocks at 0x6356b5a (slot 0) and 0x635704b (shared).
0 reversed-operand compares.

Lu-miss site (1): block 0x635772d, call 0x635774a -> 0x63d9700,
rdi = rbx, rsi = 0x6511a00 (.bss), rdx = rbx+0x1b0, rcx = r13 walk
key (proven: no r13 write on the walk -> scan -> miss path),
r8d = 1, r9d = 0, rejoin jmp 0x6356180. Second-handler sites (6):
0x63568c4, 0x6356afa, 0x6356bc1, 0x6356dfc, 0x6357651, 0x63576ff,
all rdi = rbx, rdx = 0x64da4b0 (.data.rel.ro); rsi = 0 proven at
sites 1 and 3, not established at sites 2, 4, 5, 6.

Dispatcher calls: #314 window once (0x6356712), #313 window twice
(0x6355b7f, 0x63572e4), #298 window twice (0x63567d3, 0x63573dd),
0x6364880 x13, 0x63e9cd0 x12, memset@plt x12, 0x6353610 x10,
0x63bd2c0 x8, 0x6365150/0x63e9c40/0x63edf10 x4 each, twelve callees
x2 each, __errno_location@plt/sched_getcpu@plt x2 each,
0x63ef8e0/0x63b7240/0x634f0b0/__stack_chk_fail@plt x1 each.
No indirect call in this FDE (unlike #315).

Exit: single ret at 0x6355aa8; rax = r13 (mov %r13,%rax at
0x6355a9b); canary checked, failure calls __stack_chk_fail@plt at
0x6356fdc.

Sections (own ELF parse): .bss 0x64ffe40..0x6728924 (exact end
asserted); 0x6511a00, 0x65096c0, 0x65096a0, 0x67277c0, 0x6727a00,
0x6713606 inside .bss; 0x64da4b0 inside .data.rel.ro; 0x64ffb80,
0x64ffab4 inside .data. .rela.dyn: 60,723 total, 59,534 RELATIVE.
.rela.plt: 278 entries, counted separately.

Raw 0xe8 censuses (own .eh_frame parse + byte scan): lu-miss
0x63d9700 total 168 sites / 53 FDEs, tiers 1x18, 2x14, 3x1, 4x11,
5x1, 6x2, 7x1, 8x1, 10x3, 13x1 (this FDE: 1); bin_table_init
0x63d9880 total 108 sites / 42 FDEs, tiers 1x17, 2x12, 4x8, 5x1,
6x2, 8x1, 10x1 (this FDE: 0).

Disjointness: range-only collector over the merged tree plus all
prior hl-wt-calls* worktree records; the window overlaps no prior
range (verifier: priors scanned, 0 skipped, NONE). The next
candidate 0x63577f0..0x635a786 is likewise disjoint from all priors
and from this window.

## Implementation and comparison

Not yet implemented. This packet is an observation only; no Rust
reconstruction is claimed.

## Results and limitations

Machine-readable metrics: window 7906 bytes / 1717 strict / 111
calls / 31 distinct targets / 1 ret / 8 bsr / 278 jumps (0 outside)
/ 0 bin_table_init sites / 1 lu-miss site / 6 second-handler sites
/ 0 lock-wait sites. Verifier exit 0; own unit tests exit 0
(12 checks); make verify exit 0 (559 manifests, 7159 entries);
make catalogue-check exit 2 (pre-existing Stale catalogue:
README.md, also on a pristine checkout). Full make test is not run
(584 files; declared deviation).

What remains unknown: the entry inputs' caller-side meaning, the
r8d/r9d values' caller-side meaning, the dispatcher callees'
outputs beyond the call sites, the second-handler rsi at 4 of its
6 sites, and all runtime table contents.

Next question: packet #317 decodes 0x63577f0..0x635a786 (12,182
bytes, 2679 strict, 132 calls, 1 lu-miss site at 0x635a6cd, 0
bin_table_init sites, 10 second-handler sites, 1 ret at 0x6357e19,
bsr 0), verified by targeted objdump census against all prior
exhibits.
