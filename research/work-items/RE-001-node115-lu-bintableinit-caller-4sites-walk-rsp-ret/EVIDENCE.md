# RE-001-node115-lu-bintableinit-caller-4sites-walk-rsp-ret: bounded question

- Component ID: lu bin_table_init caller FDE, seventh in the caller chain
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly census + `.eh_frame` bounds); inference (register-use naming, walk/scan interpretation); unresolved (whether the four walk paths are four distinct callers or one caller inlined four times)
- Scope included and excluded: the single FDE 0x636bd90..0x636c49c only. bin_table_init itself, the lu-miss handler, and all callee FDEs are cited, not claimed. Runtime `.bss` values are not claimed (no `.bss` references appear in this FDE).

## Reproduce

Working directory: repository root of a checkout at upstream main `05bc2de30`.
Binary: `artifacts/node/115/hl-node` (105,896,032 bytes, SHA-256 above).
Targeted disassembly only (no full-`.text` dump):
`objdump -d --start-address=0x636bd90 --stop-address=0x636c49c artifacts/node/115/hl-node`
FDE bounds: `readelf --debug-dump=frames-interp artifacts/node/115/hl-node`
(relocation census: `readelf -r artifacts/node/115/hl-node`).
No execution, no side effects; static byte reads only.

## Evidence

Coordinate system: virtual addresses as shown by objdump. `.text` file
offset = VA - 0x1000; `.rodata` = VA as-is; `.data` = VA - 0x3000.
Window 0x636bd90..0x636c49c, 1804 bytes, 379 strict lines
(address + bytes field + tab + lowercase-start mnemonic;
byte-continuation lines excluded), 9 calls, 1 ret.
`.eh_frame` FDE: previous FDE 0x636b940..0x636bd90 (gap before 0),
next FDE 0x636c4a0..0x636c52c (padding after 4 bytes, all 0xcc).
Frame 0x198, canary at 0x188(%rsp), `__stack_chk_fail` call at
0x636c46a. Entry: rdi = context (kept in rbp), rsi = key (kept
in rbx); early ret at 0x636bf08 when rsi == 0.
Walk: (key >> 0x1a) & 0xf0 into context + 0x1b0; high bits
key & 0xffffffffc0000000 compared; second level
(key >> 0x9) & 0x1ffff8 + table + 0x8; 0x6727a00 table indexed
by (value >> 0x30); 0x65096c0-table refcount via
(value & 0xfff) with `lock sub`; insert path swaps 0x100/0x108
fields; threshold gate (value >> 0x30) vs 0x23 at 0x636bf10.
bin_table_init sites (all rdi = rsp): 0x636bf96 (block
0x636bf90, test rdi,rdi je from 0x636bdcd, rejoin 0x636bdd3),
0x636bff6 (block 0x636bff0, test rbp,rbp je from 0x636be27,
rejoin 0x636be2d), 0x636c04e (block 0x636c048, test rbp,rbp je
from 0x636be7f, rejoin 0x636be85), 0x636c233 (block 0x636c22d,
test rbp,rbp je from 0x636bf28, rejoin 0x636bf2e). Each block
is the target of exactly one `je`.
8-slot scan at walk-table + 0x100, 16-byte entries: three
unrolled scans (bases r14, r15, rsi) + one indexed loop
(base r15, index r10 1..8); lu-miss sites 0x636c2c9 (rdx =
r14), 0x636c359 (rdx = r15), 0x636c3e9 (rdx = rsi),
0x636c492 (rdx = r15), all with rdi = rbp, rsi = lea
0x6511a00, rcx = rbx, r8 = 1, r9 = 0.
Exits: ret 0x636bf08; tail-jumps to 0x63637f0, 0x63bd6c0,
0x6363260. No bsr anywhere; no `.bss` references.
Raw-e8 census for target 0x63d9880 grouped by enclosing
`.eh_frame` FDE: 10, 8, 6, 6, 5, 4, 4, 4 (this FDE).
`.rela.dyn`: 60,723 entries, 59,534 RELATIVE; `.rela.plt`:
278 entries, counted separately.
Analysis is complete for this FDE; no timeout, no range limit.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is included
in this packet; the packet is evidence + static verifier +
unit tests only. No Cargo graph, no build comparison is claimed.

## Results and limitations

Verifier: exit 0, 53 checks.
Unit tests: 12/12 pass, tamper controls first, clean temp copy passes.
`make verify`: exit 0 (tally reported in README after the gate run). `make catalogue-check`: exit 2, pre-existing `Stale
catalogue: README.md` on the new base — not a packet
regression, and not claimed as passing. Full `make test`
is NOT attempted (584 test files, hours + VM-restart risk).
Disjointness: NONE overlapping over the merged tree + prior
worktree records (range-only collector, self-exclusion by
exact window equality).
Remaining unknown: four-vs-one caller inlining question;
callee FDE internals; the next caller FDE 0x6350210..0x6352f5e
(4 raw candidates, 11598 bytes, verified unclaimed).
Next question: decode the next bin_table_init caller FDE
0x6350210..0x6352f5e (4 raw candidates, 11598 bytes).
