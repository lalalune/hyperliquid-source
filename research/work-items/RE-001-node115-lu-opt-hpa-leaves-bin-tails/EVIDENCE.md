# RE-001-node115-lu-opt-hpa-leaves-bin-tails: five opt leaves plus three bin-setup tails

- Component ID: RE-001-node115-lu-opt-hpa-leaves-bin-tails
- Target release and full SHA-256: node #115,
  `artifacts/node/115/hl-node` (105,896,032 bytes),
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (byte windows, FDE bounds, censuses,
  file values) / inference (contract templates, tail phase
  structure, caller/callee roles) / unresolved (see README "Not
  covered")
- Scope included and excluded: 5 leaf FDEs + 3 tail windows
  (5460 bytes) decoded; tails' callee semantics, the 156
  remaining leaves, and the `0x63cba10` caller FDE excluded.

## Reproduce

Working directory: repo root of worktree
`~/workspace/hl-wt-calls264-115` (branch
`codex/re-004-calls264-115`, base `05bc2de30`).

- `objdump -d --start-address=<start> --stop-address=<end>
  artifacts/node/115/hl-node` per exhibit window (see
  records.json for the 8 windows). objdump version as installed
  in this VM (GNU objdump, x86-64).
- Leaf node resolution: read `.rela.dyn` (file offset `0x6be8`,
  60,723 RELA entries, 24 bytes each: r_offset, r_info, addend);
  node+0x08 addend = name string VA (`.rodata`, VA as-is);
  node+0x20 addend = handler VA. File slots are zero-filled.
- Opt children array: node `0x64da5f0` ("opt", 65 children),
  array at `0x64de2e0`, 5-qword entries, handler slot at entry
  offset +32. Our five leaves are groups 6–10.
- FDE bounds: `.eh_frame` section (file offset `0xca6ed8`,
  size `0x77137c`), CIE augmentation `zR`, FDE encoding `0x1b`
  (PC-relative sdata4): initial_location = field VA + sdata4,
  range = following u32. The verifier re-parses this table.
- `.data` file values: VA − 0x3000 (program header: file offset
  `0x64eca20` ↔ VA `0x64efa20`).
- `.text` mapping: VA − 0x1000 (program header: file offset
  `0x1418300` ↔ VA `0x1419300`, size `0x4fd88a0`).
- No execution of the binary at any point; no side effects
  beyond the packet files, tools file, and tests file.

## Evidence

Coordinates are VAs unless marked as file offsets.

Leaf FDEs (`.eh_frame`-confirmed; next FDE start in parens):
- `opt/hpa_slab_max_alloc`: node `0x64de3d0`, FDE
  `0x636f7c0..0x636f9d7` (535B; next `0x636f9e0`, 9B pad).
  Value: u64 at `.data` `0x64ffb00`, file-initial `0x10000`.
- `opt/hpa_hugification_threshold`: node `0x64de3f8`, FDE
  `0x636efa0..0x636f1b7` (535B; next `0x636f1c0`, 9B pad).
  Value: u64 at `0x64ffb08`, file-initial `0x1e6666`.
- `opt/hpa_hugify_delay_ms`: node `0x64de420`, FDE
  `0x636f1c0..0x636f3d7` (535B; next `0x636f3e0`, 9B pad).
  Value: u64 at `0x64ffb18`, file-initial `0x2710`.
- `opt/hpa_min_purge_interval_ms`: node `0x64de448`, FDE
  `0x636f3e0..0x636f5f7` (535B; next `0x636f600`, 9B pad).
  Value: u64 at `0x64ffb20`, file-initial `0x1388`.
- `opt/hpa_dirty_mult`: node `0x64de470`, FDE
  `0x636f600..0x636f7b3` (435B; next `0x636f7c0`, 13B pad).
  Value: u32 at `0x64ffb10`, file-initial `0x4000`.

Contract evidence (identical template in all five; u64 size 8,
u32 size 4): entry `endbr64`, `sub $0x18,%rsp`, canary save,
r11d := 1; `or 0x20(%rsp),%r9; jne` epilogue (write attempt →
1); value load from `0x64ffb00`+offset into a stack temp;
`test oldp; je` epilogue (→ 0); `test oldlenp; je` epilogue
(→ 0); `*oldlenp` == size → store + epilogue (→ 0); else
short-read path: n = min(`*oldlenp`, size) copied from the
stack temp (qword bulk + 4/2/1-byte tail for u64, byte loop
for u32), `*oldlenp` := n, r11d := `0x16`, jump to epilogue.
Epilogue: canary check, `jne __stack_chk_fail` (5-byte call
at FDE end), return r11d. Each FDE holds exactly one `ret`
(the fast-path ret; the copy path jumps back to the epilogue).

Direct-entry census: whole-`.text` raw E8 scan (rel32 targets
computed as site+5+rel32) gives 0 direct entries for each of
the five handler VAs — dispatcher indirect tail-call only.

Tail windows:
- `0x6352fc0` tail `0x63530d5..0x6353608` (1331B, 318
  strict). FDE `0x6352fc0..0x6353608` (1608B). 23 E8 callers
  (matches #263). Single ret `0x635319c`; stack-check call
  `0x6353603`. Jump targets all inside the FDE. Named calls:
  getters `0x6364400`/`0x6364410`/`0x6364430`, validators
  `0x6367450`/`0x6368e40`, wait helper `0x63bf680`,
  bin_getcreate `0x634ebb0` (cited only), logger `0x63bf5b6`,
  `abort`, `sched_getcpu`, `pthread_mutex_unlock`.
  Refcount remainder chain: divisors at `0x6711b40`+0x14+{0x00,
  0x28, 0x50, 0x78, 0xa0, 0xc8, 0xf0, 0x118, 0x140}, remainders
  to out+0xa1..0xa9. Mutex `0x6511700`, contended byte
  `0x6511728`, record base `0x65116c0`.
- `0x63e91c0` tail `0x63e92cd..0x63e9491` (452B, 107
  strict). FDE `0x63e91c0..0x63e9491` (721B). 2 E8 callers at
  `0x63ed254`, `0x63eda85` (matches #263). Single ret
  `0x63e948b`; stack-check call `0x63e948c`. Jump targets all
  inside the FDE. Duff's-device loop: remainder
  `(-count) & 3`, then 4-at-a-time to ebp == 36; per-iteration
  call `0x63eebd0` (out slot r13+24*idx+8, u16-table pointer
  `[0x6728868]`+2*idx). Epilogue call `0x63eebb0`
  ([0x6728868], count, r12, stack temp).
- `0x6365150` remainder `0x6365212..0x6365660` (1102B, 255
  strict). FDE `0x6365150..0x6365660` (1296B). 29 E8 callers
  (matches #263). No `ret` in the remainder; exits are the
  three tail-jumps `0x63bd2c0`, `0x63bcd20`, `0x6364880`
  plus jumps back into the head. Stack-check call
  `0x63655ec`. Named calls: `0x63e9cd0`, `0x63e9c40`,
  `0x63edf10`, setup callees `0x6352f60` (`0x636549f`) and
  `0x6352fc0` (`0x636555c`) (both cited only — packet #263's
  topics), bin_insert `0x63ec4c0` (cited only — packet #261),
  bin_getcreate `0x634ebb0` (cited only — packet #261),
  `memset`, `sched_getcpu`.

Analysis is complete for the 8 claimed windows (full
disassembly read, not sampled) and census-only elsewhere as
stated. Raw `.hex` (binary bytes) and `.objdump.txt` files sit
beside this record.

## Implementation and comparison

Not yet implemented/measured. No Rust code, no build, no
equivalence claim in this packet. The verifier and tests below
check the evidence itself (bytes, counts, bounds, censuses),
not an implementation.

## Results and limitations

- Claimed: 5460 bytes, 1384 strict instructions, 8 windows.
- Verifier exit 0; own tests standalone (counts in the PR
  body); `make verify` exit 0; `make catalogue-check` exit 2
  (pre-existing `Stale catalogue: README.md` on the new base).
- Full `make test` not attempted (584 test files, hours-long,
  VM-restart risk); no full-suite tally claimed.
- Unknown: the 156 remaining leaves; callee semantics listed
  under "Not covered" in the README; runtime `.data` values;
  the `0x63cba10` caller FDE; whether the `0x63e91c0`
  initialized structure is the same structure `0x63ec690`
  drains (shared count global `0x6728850` and 36 split
  observed only, per #263).
- No gate is requested beyond the packet's own verifier,
  tests, `make verify`, and the honest `catalogue-check`
  report above.

Next question: classify the next five leaves in tree order
(opt children groups 11+, starting with handlers `0x636f9e0`
and `0x636fc00`); or decode the largest bin_table_init caller
FDE `0x63cba10` (10 sites). Packet #265 should pick one of
these, not both, to stay light.
