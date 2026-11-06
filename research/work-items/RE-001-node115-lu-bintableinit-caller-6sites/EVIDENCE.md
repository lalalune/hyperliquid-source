# RE-001-node115-lu-bintableinit-caller-6sites: <bounded question>

Decode the third bin_table_init caller FDE 0x63ce8c0..0x63cf8bc
(6 sites) on node #115: its entry contract, mutex gate, radix
walk skeleton, bin_table_init call sites, and lu-miss call
sites — all from static disassembly, with no leaf classified.

- Component ID: lu bin_table_init caller, 6 sites
- Target release and full SHA-256:
  artifacts/node/115/hl-node, 105,896,032 bytes,
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Source commit / reference commit:
  upstream main 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (disassembly-backed); runtime
  `.bss` values unresolved; callee internals beyond call-site
  argument patterns not claimed
- Scope included and excluded: included — the single FDE
  0x63ce8c0..0x63cf8bc, its 22 calls, its mutex cluster, its
  walk skeleton. Excluded — callee FDE internals, runtime
  values, the 107 remaining static leaves, the next caller
  FDE 0x63d4bbe..0x63d5428.

## Reproduce

Working directory: the worktree root. Binary:
`artifacts/node/115/hl-node` (verified by size + SHA-256).
Tool versions: system `objdump`, `readelf`, `python3`.
No execution of the binary at any point; all evidence is
static parsing and disassembly.

- FDE bounds: `objdump --dwarf=frames
  artifacts/node/115/hl-node`, FDE line
  `pc=00000000063ce8c0..00000000063cf8bc` (also reproduced
  by the verifier's pure-Python `.eh_frame` parser).
- Disassembly: `objdump -d --start-address=0x63ce8c0
  --stop-address=0x63cf8bc artifacts/node/115/hl-node`
  (exhibit `bintableinit_caller_6sites.objdump.txt`).
- Exhibit bytes: `.text` file offset = VA − 0x1000, slice
  [0x63ce8c0−0x1000, 0x63cf8bc−0x1000) = 4092 bytes
  (exhibit `bintableinit_caller_6sites.hex`, raw binary
  bytes, not hex text).
- Strict count: lines matching
  `^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]` = 882.
- Verifier: `python3 tools/node115_lu_bintableinit_caller_6sites.py`
  (exit 0). Unit tests:
  `python3 tests/test_node115_lu_bintableinit_caller_6sites.py`
  (9/9 pass, tamper controls run first).
- Declared side effects: none; read-only analysis.

## Evidence

Original addresses are virtual addresses (VA) in the node
#115 `.text` (file offset = VA − 0x1000); `.rodata`
addresses are VA as-is; `.data` file offset = VA − 0x3000.
FDE bounds are `.eh_frame` bounds (PC-relative sdata4
encoding, fixed 4-byte range fields — not ULEB).
Previous FDE ends 0x63ce8b8 (gap 8); next FDE starts
0x63cf8c0 (padding 4). Six pushes, 0x838 frame, canary at
0x828(%rsp), single `ret` at 0x63cec83, single canary check
at 0x63cec60, `__stack_chk_fail` call at 0x63cf740.
Total calls 22: bin_table_init 6, lu-miss handler 6,
node-fetch 0x6364880 ×1, node-setup 0x63d2a80 ×1,
pthread_mutex_trylock@plt ×1, pthread_mutex_unlock@plt ×1,
lock-wait 0x63bf680 ×1, 0x63637f0 ×1, 0x634ebb0 ×1,
0x63bd6c0 ×1, 0x6363260 ×1, `__stack_chk_fail`@plt ×1.
Raw-e8 census over all `.eh_frame` FDE ranges for target
0x63d9880: 10 (#275 FDE), 8 (#276 FDE), 6 (this FDE),
6 (0x63d4bbe FDE), 5 (0x63bd8c0 FDE) — this FDE's 6 are
objdump-verified by mnemonic. Analysis is complete for
this FDE's range; nothing was timed out.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is
proposed by this packet. The verifier and tests compare
the exhibit bytes against the binary slice, recount strict
lines independently, and re-derive the call census from
the exhibit disassembly; tamper controls (hex flip,
strict-count change, call-site list change, injected
overlap) each fail the verifier, and a clean temp copy
passes. No normalization masks beyond objdump-header
stripping (the `file format` line) in the regeneration
comparison.

## Results and limitations

Machine-readable metrics: 1 window, 4092 bytes, 882
strict lines, 22 calls, 1 ret, 6 bin_table_init sites,
6 lu-miss sites, 0 overlaps against all prior claimed
ranges (independent scan). What remains unknown: runtime
`.bss` values, callee internals, whether the radix root
at rbp+0x1b0 belongs to one named structure, and the
next caller FDE 0x63d4bbe..0x63d5428. The requested
progress gate covers this FDE only; `make verify` exit 0
(7161 entries), `make catalogue-check` exit 2
(pre-existing `Stale catalogue: README.md`, not a packet
regression), full `make test` NOT attempted (584 files;
no full-suite tally claimed). Next question: decode
0x63d4bbe..0x63d5428 (6 raw candidates), or open the
next leaf family outside opt children — pick one, not
both.
