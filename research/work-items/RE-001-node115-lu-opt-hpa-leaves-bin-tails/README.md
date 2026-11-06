# RE-001-node115-lu-opt-hpa-leaves-bin-tails

Node-115-only light packet: five more control-tree leaves classified
(`opt/hpa_slab_max_alloc`, `opt/hpa_hugification_threshold`,
`opt/hpa_hugify_delay_ms`, `opt/hpa_min_purge_interval_ms`,
`opt/hpa_dirty_mult`), and the tails of the three enable-slow-path
bin-setup callees packet #263 left as entry windows
(`0x6352fc0` tail, `0x63e91c0` tail, `0x6365150` remainder).
This packet takes packet #263's first next-question option only;
the largest bin_table_init caller FDE `0x63cba10` (10 sites) is
explicitly NOT decoded here, per #263's "pick one, not both".

- Binary: `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Base: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Static analysis only; the binary was never executed.
- `.hex` exhibit files contain raw binary bytes, not hex text.

## Classified leaves (5, all read-only)

Leaves were resolved as the next five entries of the `opt` node's
children array (`0x64de2e0`, 65 children, 5-qword entries with the
handler `.rela.dyn` slot at entry offset +32) after packet #263's
five: groups 6–10, nodes `0x64de3d0`, `0x64de3f8`, `0x64de420`,
`0x64de448`, `0x64de470`. Each node's name string comes from its
node+0x08 `.rela.dyn` addend and its handler from its node+0x20
addend (file slots are zero-filled, so the addend is the authority).
All five handlers are reached only by dispatcher indirect tail-call:
a whole-`.text` E8 census gives 0 direct entries per leaf.

All five share one contract template (the same shape as packet
#261's value leaves, with u64 size 8 or u32 size 4):

- Write attempt (newp or newlen nonzero, via `or 0x20(%rsp),%r9`)
  returns 1 without touching memory.
- Read with oldp == 0 or oldlenp == 0 returns 0.
- Read with `*oldlenp` == size stores the value and returns 0.
- Any other `*oldlenp` takes the short-read path: n =
  min(`*oldlenp`, size) bytes are copied from a stack temp holding
  the value, `*oldlenp` is set to n, and the handler returns 0x16.
- Stack-canary failure jumps to `__stack_chk_fail` (5-byte call at
  each FDE end).

The values live in one `.data` struct at `0x64ffb00`:

| leaf | node | handler FDE | value | file-initial value |
| ---- | ---- | ----------- | ----- | ------------------ |
| opt/hpa_slab_max_alloc | 0x64de3d0 | 0x636f7c0..0x636f9d7 (535B) | u64 at 0x64ffb00 | 0x10000 (65536) |
| opt/hpa_hugification_threshold | 0x64de3f8 | 0x636efa0..0x636f1b7 (535B) | u64 at 0x64ffb08 | 0x1e6666 (1992294) |
| opt/hpa_hugify_delay_ms | 0x64de420 | 0x636f1c0..0x636f3d7 (535B) | u64 at 0x64ffb18 | 0x2710 (10000) |
| opt/hpa_min_purge_interval_ms | 0x64de448 | 0x636f3e0..0x636f5f7 (535B) | u64 at 0x64ffb20 | 0x1388 (5000) |
| opt/hpa_dirty_mult | 0x64de470 | 0x636f600..0x636f7b3 (435B) | u32 at 0x64ffb10 | 0x4000 (16384) |

File-initial values only: `.data` is writable, so runtime values
may differ. FDE bounds come from `.eh_frame` (PC-relative sdata4
encoding), not from endbr64 scanning; padding to the next FDE is
9 bytes for the first four leaves and 13 bytes for dirty_mult
(next FDE `0x636f7c0`).

At packet #263's start, 166 leaves remained; #263 classified 5
(161 remain); this packet classifies 5 more, so 156 of 204 static
leaves remain unclassified (48 classified in total). This packet
does not claim exhaustive coverage.

## Bin-setup tail: `0x6352fc0` (tail `0x63530d5..0x6353608`, 1331B)

Completes packet #263's head (`0x6352fc0..0x63530d5`). FDE
`0x6352fc0..0x6353608` (1608B, `.eh_frame`-confirmed). Whole-FDE
E8 census: 23 callers, matching #263. Single ret at `0x635319c`;
stack-check call at `0x6353603`. No jumps outside the FDE (the
wait path jumps back to head `0x6353033`, inside the FDE).

- Tail entry continues the head's table walk loop (best-index
  cmove, index +1, cursor +8, loop back to head `0x6353080`).
- Second phase: two-pass selection over the head phase's recorded
  best-index stack array at `0x30(%rsp)`. Pass 0 processes
  table[array[0]] and pass 1 table[array[1]]; each pass calls
  getter `0x6364400` then `0x6364410`, with a record-best update
  (array[pass] := r12d) when the getter succeeds and r12d differs
  from `[0x65096a0]`, and a per-pass flag byte at `0x1f(%rsp)`
  selecting a direct-entry path that skips the getter call.
- First pass stores its entry to out+0x90, atomically increments
  the entry's +0x8 refcount with `lock xadd`, and converts the OLD
  refcount into 9 remainder bytes at out+0xa1..0xa9 via divisors
  at `0x6711b40`+0x14+{0x00,0x28,0x50,0x78,0xa0,0xc8,0xf0,0x118,0x140}.
- Second pass stores its entry to out+0x88, unlocks mutex
  `0x6511700`, clears contended byte `0x6511728`, then runs
  validator gates: flag bytes at `0x2e(%rsp)`/`0x2f(%rsp)` select
  calls to `0x6367450` and `0x6368e40`; a validator failure falls
  to `0x63535a3`, which logs via `0x63bf5b6` and calls `abort`.
- `[0x65096a0]` <= 1 divert (`0x63532d0`): two entries resolved
  directly via `0x6364410` (out+0x90, then out+0x88) with the same
  refcount remainder chain.
- CPU divert (`0x63533c0`, from the head's `[0x64ffb80]` > 2
  guard): `sched_getcpu`, cpu index halved against
  `[0x6511730]`, entry from table `0x65096c0`, falling back to
  bin_getcreate `0x634ebb0` (cited only — packet #261's topic)
  when the table slot is null.
- Wait path (`0x63534e0`): call wait helper `0x63bf680` on
  record `0x65116c0`, contended byte `0x6511728` := 1, jump back
  to the head retry at `0x6353033`.
- Epilogue returns rbp (the selected entry).
- Other cited-only call targets: `0x6364430`, `0x63bf5b6`.

## Bin-setup tail: `0x63e91c0` (tail `0x63e92cd..0x63e9491`, 452B)

Completes packet #263's head (`0x63e91c0..0x63e92cd`). FDE
`0x63e91c0..0x63e9491` (721B, `.eh_frame`-confirmed). Whole-FDE
E8 census: 2 callers, sites `0x63ed254` and `0x63eda85`,
matching #263. Single ret at `0x63e948b`; stack-check call at
`0x63e948c`. No jumps outside the FDE.

- Tail entry runs after the head loop (which covered indices
  0..count-1 with per-index byte sets for indices <= 35 and a
  `0x63eebd0` call per index). If count > 35, jump straight to
  the epilogue call.
- Otherwise a Duff's-device unrolled loop fills indices
  [count, 36): remainder `(-count) & 3` iterations through
  fall-through blocks, then 4-at-a-time iterations until ebp ==
  36. Each iteration calls `0x63eebd0` with out slot
  r13+24*idx+8, u16-table pointer `[0x6728868]`+2*idx, rdx = r12,
  rcx = stack temp at `0x20(%rsp)`, and a stack-passed 0. The
  tail iterations do NOT set the per-index bytes (those slots
  keep their memset zero).
- Epilogue: call `0x63eebb0` with ([0x6728868], count, r12,
  stack temp), then return. The `0x63eebd0`/`0x63eebb0`/`0x63eeb90`
  family semantics are named only, not decoded.

## Allocator remainder: `0x6365150` (`0x6365212..0x6365660`, 1102B)

Completes packet #263's fast path (`0x6365150..0x6365212`,
ending at the small-size ret `0x6365211`). FDE
`0x6365150..0x6365660` (1296B, `.eh_frame`-confirmed).
Whole-FDE E8 census: 29 callers, matching #263. The remainder
contains NO ret: it exits via the three tail-jumps #263 named
(`0x63bd2c0`, `0x63bcd20`, `0x6364880`) or by jumping back into
the head. Stack-check call at `0x63655ec`.

- Fast-path exits: size-class overflow (`rcx > 0x40`) diverts to
  the `0x6365280` block and tail-jumps to `0x63bcd20`; the
  in-range path tail-jumps to `0x63bd2c0` (with ecx = r8d);
  the u16-table path tail-jumps to `0x6364880` (rdx = rbx,
  rsi = r13, ecx = r10d).
- Bitmap path (`0x6365250`): bsr/shift/mask arithmetic over
  (2*rdx-1) computing a class index, jumping back to head
  `0x63651ac`.
- Slow-path continuation (`0x63652e8`): if the entry's +0x1c
  word equals r11w, fall to the resolve block; otherwise store
  the cursor (rdx to entry+0x8, dx to entry+0x18) and jump back
  to head `0x63651de`.
- Resolve block (`0x6365306`): if the u16 table
  `[0x6728868]`[class] is zero, take the `0x6364880` exit;
  otherwise call `0x63e9cd0` then `0x63e9c40` (named only) and
  rejoin the head on either outcome.
- Memset block (`0x6365370`): zeroes table `0x6727a00`[class]
  bytes at r9, rejoining head `0x63651e7`.
- Bin-resolution block (`0x6365390` onward): if the current
  entry's +0x1 byte is positive, take the table[0] path
  (`0x6365507`, bin_getcreate fallback `0x634ebb0` cited only);
  if entry+0x90 is null, call setup callee `0x6352fc0`
  (`0x636555c`, cited only — packet #263's topic) and then the
  insert path; otherwise run the mode-gated cpu selection
  (`[0x64ffb80]`, `[0x6511730]` halving, `sched_getcpu`) and
  call setup callee `0x6352f60` (`0x636549f`, cited only —
  packet #263's topic) followed by `0x63edf10` (named only),
  or bin_insert `0x63ec4c0` (cited only — packet #261's topic)
  when the cursor is null.
- The three setup callees' interplay is now closed: `0x6365150`
  invokes both `0x6352f60` and `0x6352fc0`, and enable-slow
  `0x63ed090` calls all three directly (sites `0x63ed18d`,
  `0x63ed58c`, `0x63ed605` per #263).

## Exhibits (8 windows, 5460 bytes, 1384 strict lines)

Strict = address + bytes field + tab + mnemonic starting with a
lowercase letter; objdump byte-continuation lines excluded.

| exhibit | range | bytes | strict |
| ------- | ----- | ----- | ------ |
| opt_hpa_slab_max_alloc | `0x636f7c0..0x636f9d7` | 535 | 147 |
| opt_hpa_hugification_threshold | `0x636efa0..0x636f1b7` | 535 | 147 |
| opt_hpa_hugify_delay_ms | `0x636f1c0..0x636f3d7` | 535 | 147 |
| opt_hpa_min_purge_interval_ms | `0x636f3e0..0x636f5f7` | 535 | 147 |
| opt_hpa_dirty_mult | `0x636f600..0x636f7b3` | 435 | 116 |
| bin_setup_52fc0_tail | `0x63530d5..0x6353608` | 1331 | 318 |
| bin_setup_e91c0_tail | `0x63e92cd..0x63e9491` | 452 | 107 |
| bin_alloc_65150_remainder | `0x6365212..0x6365660` | 1102 | 255 |

## Verification

- `tools/node115_lu_opt_hpa_leaves_bin_tails.py` exit 0:
  byte reads only; binary identity, exhibit bytes, strict
  counts, objdump regeneration with the path-embedding header
  line stripped, `.eh_frame` FDE bounds, `.rela.dyn` leaf slots
  and opt-children-array order, `.data` file values, E8/E9
  censuses (leaf direct entries 0; `0x6352fc0` 23 callers;
  `0x63e91c0` 2 callers at `0x63ed254`/`0x63eda85`;
  `0x6365150` 29 callers), jump-target containment (all jumps
  inside their FDE except `0x6365150`'s three named
  tail-jumps), single-ret checks, disjointness, MANIFEST hashes.
- `tests/test_node115_lu_opt_hpa_leaves_bin_tails.py`
  standalone, including regeneration comparison, independent
  strict recount, and tamper controls run first (hex flip,
  strict-count change, injected overlap — each confirmed to
  fail the verifier).
- `make verify` exit 0 (tally in the PR body).
- `make catalogue-check` exit 2 with the pre-existing
  `Stale catalogue: README.md` failure on the new base, not a
  packet regression.
- Full `make test` is not attempted: the new base carries 584
  test files, a full run takes hours and risks a VM restart
  mid-run. The gates above are the verified final state.
- Disjointness: range-only collector over the merged tree plus
  packets #183-#263 worktrees, deduplicated by real packet slug,
  census/cited-only subtrees excluded. The collector gathers ONLY
  exhibited windows — string `range` fields, `[start, end]`
  lists, `start`/`end` pairs inside `exhibits` lists or dicts,
  and `windows` lists or dicts — never enclosing-`fde`
  annotation fields. No overlap with packets #183-#263 or with
  packet #232's FDE `0x63b8820..0x63b8d85`. Directory
  `RE-001-node115-lu-opt-hpa-leaves-bin-tails` does not collide
  with any merged-tree directory.

## Not covered (explicit)

- The remaining 156 leaves.
- The getter family `0x6364400`/`0x6364410`/`0x6364420`/
  `0x6364430`, the resolver `0x6362130`, the wait helper
  `0x63bf680`, and the `0x63eebd0`/`0x63eebb0`/`0x63eeb90`
  family, `0x63e9cd0`/`0x63e9c40`, `0x63edf10`, the validators
  `0x6367450`/`0x6368e40`: named only.
- bin_table_init's own 484-byte FDE (`0x63d9880..0x63d9a64`,
  packet #262's verified exhibit) and the 108 callers' full
  argument patterns and subsystem identities: survey only
  (packet #263).
- The largest bin_table_init caller FDE `0x63cba10` (10 sites):
  not decoded (packet #263's other option, explicitly not taken
  here).
- Runtime values of the `.data` globals at
  `0x64ffb00..0x64ffb20` (only file-initial values are reported).
- Packet #263's framings are NOT corrected or re-claimed here;
  nothing in this packet's disassembly contradicts them (the
  `0x6365150` single ret at `0x6365211`, the `0x6352fc0`
  single ret at `0x635319c`, and the `0x63e91c0` single ret at
  `0x63e948b` are all confirmed in the tails).

## Next question (#265)

Classify the next five leaves in tree order (opt children groups
11+, starting with handlers `0x636f9e0` and `0x636fc00`); or
decode the largest bin_table_init caller FDE `0x63cba10`
(10 sites). Packet #265 should pick one of these, not both, to
stay light.
