# RE-001-node115-lu-opt-groups16-20-leaves: evidence

- Component ID: RE-001 node-115 control-tree leaves, opt children
  groups 16–20 (metadata_thp, retain, dss, narenas, percpu_arena).
- Target release and full SHA-256: node #115,
  `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`.
- Claim status: observation (disassembly + file bytes + relocation
  addends). No runtime behaviour is claimed; `.data` values are
  file-initial only and `.bss` values are unknown from the file.
- Scope included and excluded: included — the five handler FDEs
  below, their node/slot resolution, their value loads, and the
  read-only contract shape. Excluded — the remaining 146 leaves,
  dispatcher internals, runtime `.data`/`.bss` values, and the
  `0x63cba10` caller FDE.

## Reproduce

Worktree `hl-wt-calls266-115`, branch `codex/re-004-calls266-115`,
base `05bc2de30`. Static analysis only; the binary was never
executed. Tool versions: system `objdump`, `readelf`, `python3`.

- `objdump -d --start-address=0x6370480 --stop-address=0x637068d
  artifacts/node/115/hl-node` (and likewise for the other four
  FDEs) regenerates each `.objdump.txt` exhibit up to the
  path-embedding file-format header line, which the verifier and
  tests strip before comparing (first 2 lines: blank +
  file-format line).
- `.hex` exhibits are raw binary bytes sliced at file offset
  VA − 0x1000 (`.text` program-header mapping re-derived:
  PT_LOAD off=0x1418300 ↔ vaddr=0x1419300), not hex text.
- `.rela.dyn` addends were read with `readelf -r` (60,723 entries
  total, 59,534 of type RELATIVE); `.data` file values were read
  at VA − 0x3000 (section addr 0x64efa20 ↔ file offset
  0x64eca20).

## Evidence

Original addresses and coordinate system (VA/file offset), validated
boundaries, raw disassembly/data, callers/callees/indirect calls:

- Node resolution: opt children array `0x64de2e0`, 65 children,
  5-qword entries (stride 0x28), handler slot at entry offset +32.
  Group 16 node `0x64de560` → name `metadata_thp`, handler
  `0x6370480`; group 17 node `0x64de588` → `retain`,
  `0x6370690`; group 18 node `0x64de5b0` → `dss`,
  `0x6370720`; group 19 node `0x64de5d8` → `narenas`,
  `0x6370940`; group 20 node `0x64de600` → `percpu_arena`,
  `0x6370b00`. Each name comes from the node+0x08 RELATIVE
  addend and each handler from the node+0x20 RELATIVE addend.
- FDE bounds from `.eh_frame` (PC-relative sdata4, CIE
  augmentation zR, encoding 0x1b): `0x6370480..0x637068d`
  (525B), `0x6370690..0x6370716` (134B),
  `0x6370720..0x6370937` (535B), `0x6370940..0x6370af3`
  (435B), `0x6370b00..0x6370d0d` (525B). Paddings to the next
  FDE: 3, 10, 9, 13, 3 bytes respectively; the next FDE after
  the last is `0x6370d10` (group 21, not claimed). The parser
  was validated against packet #265's verified FDE
  `0x636f9e0..0x636fbf7` (535B).
- Value loads (the only per-leaf difference, besides size):
  metadata_thp: `lea 0x6711b34(%rip),%rdx` (`.bss` index dword),
  `mov (%rdx),%ecx`, `lea 0x64ffbd0(%rip),%rsi` (`.data`
  table base), `mov (%rsi,%rcx,8),%rdi`; percpu_arena:
  `lea 0x64ffb80(%rip),%rdx` (`.data` index dword,
  file-initial 2), `mov (%rdx),%ecx`,
  `lea 0x64ffba0(%rip),%rsi`, `mov (%rsi,%rcx,8),%rdi`;
  retain: `lea 0x64ffc28(%rip),%rax`, `movzbl (%rax),%esi`
  (file byte 1); dss: `lea 0x64ffc20(%rip),%rdx`,
  `mov (%rdx),%rdi` (file qword 0); narenas:
  `lea 0x6511734(%rip),%rdx` (`.bss` dword),
  `mov (%rdx),%esi`.
- Contract shape (same skeleton as packet #261's value leaves,
  verified per FDE by marker): entry endbr64;
  `or 0x20(%rsp),%r9` (newlen|newp) → return 1 on nonzero;
  oldp==0 or oldlenp==0 → return 0; *oldlenp==size (8, 1, 8, 4,
  8 respectively) → store value, return 0; otherwise short-read
  copy loop (n = min(*oldlenp, size)) ending in
  `mov %rcx,(%r8)` (*oldlenp := n) and `mov $0x16` (return
  0x16). Single ret per FDE; all jumps stay inside the FDE;
  the only out-of-FDE transfer is the `__stack_chk_fail` call
  (PLT `0x63f0d70`) on canary mismatch.
- Callers: whole-`.text` raw E8 scan finds 0 direct entries per
  leaf (a real direct call would appear as an E8 with an exact
  rel32 target; none targets any of the five handlers). All five
  are reached only by dispatcher indirect tail-call.
- Strict counts: 149, 36, 147, 116, 149 mnemonic lines per FDE
  (address + bytes field + tab + mnemonic starting with a
  lowercase letter; objdump byte-continuation lines excluded).
  Total: 2154 bytes, 597 strict instructions.

## Implementation and comparison

Not yet implemented/measured. No Rust path is claimed by this
packet; it is an observation packet only.

## Results and limitations

Machine-readable metrics with explicit denominators: 5 of 5
target leaves classified (groups 16–20); 0 direct E8 entries per
leaf out of a whole-`.text` scan; 1 ret per FDE; 0 jumps outside
any FDE; 0 overlaps with prior claimed ranges. What remains
unknown: the remaining 146 leaves; runtime `.bss` values at
`0x6711b34` and `0x6511734`; runtime `.data` values at
`0x64ffc28`, `0x64ffc20`, `0x64ffb80`; the `0x63cba10` caller
FDE. If requesting no gate, say so: this packet requests no
gate beyond the standard packet verification above. Finish with
a concrete next question: classify opt children groups 21+ in
tree order (starting with the FDE at `0x6370d10`), or decode
the largest bin_table_init caller FDE `0x63cba10` (10 sites) —
packet #267 should pick one, not both, to stay light.
