# RE-001-node115: lu dispatch path construction (name-to-index resolver) and the unreached stats.mutexes.reset leaf

## Question

Packet #255 ended with a next question: which caller constructs the
dispatcher index path `[11, 8, 9]` for `stats.mutexes.reset` — is there a
name-to-index resolver that turns a dotted control name into indices, or do
the callers hardcode the path upstream of the five surveyed
dispatcher-caller FDEs — and is the reset leaf write-only, or can a read
dispatch reach it too?

## Answer, in short

1. **Yes, there is a name-to-index resolver, and it is the mechanism.**
   Function `0x636e340..0x636e817` (1239B) converts a dotted name into
   indices: it splits on `'.'`, matches each segment against the current
   node's children by `strlen` + `strncmp` on the child `+0x08` name, and
   appends the matched child index to the caller's index array past the
   walked prefix. Numeric segments take a separate branch (base-10 parse
   plus a resolver function at the flag-0 child's `+0x08`).
2. **No caller hardcodes `[11, 8, 9]`.** There is no `$0xb` (11) immediate
   anywhere in the seven dispatcher-caller FDEs, no site passes `'reset'`
   or any dotted name ending in reset, and the only `'mutexes'`-reaching
   call resolves the *name* `"stats.mutexes"` from root, not indices.
3. **The `[11, 8]` prefix IS constructed — by name.** FDE 6
   (`0x63e7dd9..0x63e87e5`) resolves `"stats.mutexes"` at length 0, then
   loops over a 9-entry mutex-name table calling the FDE 1 mutex-field
   dumper per mutex. The 9 table names are exactly `mutexes`' 9 interior
   children (verified against `.rela.dyn`); `reset` (child 9, the only
   leaf) is not in the table.
4. **The reset leaf is never dispatched, and its handler has no other
   entry point.** The sweep function `0x63a5bf0` (packet #253's FDE) has
   zero direct call sites and zero address-taken sites; its only reference
   in the binary is the reset leaf's `+0x20` handler field. The two
   live name-resolution paths that *could* reach it — the gated helper
   `0x635dee0` tail-jumping to the invoke function (110 sites) and the
   gated helper `0x635df90` tail-jumping to the wrapper (55 sites) —
   never name it: all 165 sites pass literal names (97 + 54 distinct),
   none of which is `'reset'`, `'mutexes'`, `'stats.mutexes'`, or ends
   in `.reset`. So the reset leaf is dormant as a control node in this
   binary's static call graph.
5. **Read vs write: there is no mode flag.** The dispatcher forwards the
   caller's argument list to the leaf handler unchanged in kind; leaf
   behavior is determined by the leaf's handler alone. The reset leaf's
   only handler is the sweep, which zeroes counters (packet #254) — so
   the leaf is write-only in effect, and additionally uninvoked in
   practice. The sibling function `0x63a8d00` is the resolve-only entry:
   same walk, same leaf gate, but it calls the resolver with a NULL
   out-slot and returns a status instead of invoking any handler.

## The resolver (new, claimed)

`0x636e340..0x636e817`, 1239B, 305 strict mnemonic lines (whole FDE
characterized; key paths exhibited, see below). Entry takes
`(ctx, node, name, out_slot, array_end, count_ptr)` — as called from the
dispatcher (`0x63a9287`, cited from #255) and the sibling (`0x63a8f37`,
exhibited).

- Entry (`resolver_entry`, 64B, 19 strict): saves registers, calls
  `strchr(name, '.')` (`0x63f1aa0`) for the first segment; a name with
  no dot falls back to a single-segment path (`strlen` to the end).
- Segment loop: for each segment, scans the current node's children
  (stride `0x28`, count at node `+0x10`, children at `+0x18`), comparing
  `strlen(child_name)` to the segment length and then `strncmp`
  (PLT `0x63f1500`). On a match it appends the child index to the output
  array (`resolver_append`, 118B, 27 strict: the store is
  `mov %rbx,0x0(%rbp,%r15,8)` where `%rbp` is the array end and `%r15`
  the segment counter) and advances past the dot.
- Bounds: each appended segment index is checked against `*count_ptr`
  (the caller's remaining capacity); overflow returns 2. The caller
  subtracts the walked prefix length from `*count_ptr` before the call
  and adds it back after, so `*count_ptr` ends holding the resolved
  total length. A qword initialized to 7 appears in the setup window of
  all 73 dispatch sites, and at every site decoded in full the
  dispatcher's `r8` points at that qword.
- Numeric branch (`resolver_numeric_return`, 167B, 45 strict): when the
  current node's child is flag-0, the segment is parsed with `strtol`
  (base 10, `0x63be700`); `-1` returns 2. The parsed index is passed to
  the resolver function at `children[0]+0x08`, called as
  `(ctx, array_end, *count_ptr, parsed_index)`; a nonzero result becomes
  the next node. If `children[0]` is not flag-0, control jumps to a
  10-byte `ud2` trap stub at `0x636e32e..0x636e338` (a separate FDE just
  before the resolver) — the single jump in the resolver FDE that leaves
  it. On success with a non-NULL out-slot, the final node is written to
  `*out_slot` and 0 is returned; with a NULL out-slot the function
  returns 0 directly.
- Whole-FDE check: all other conditional/unconditional jumps inside the
  resolver FDE land inside it; direct calls go only to `strchr`,
  `strlen`, `strncmp`, `strtol`, plus the indirect resolver calls.

## The sibling: resolve-only entry (new, claimed)

`0x63a8d00..0x63a8fe8`, 744B, 196 strict lines (characterized; gate
exhibited). It repeats the dispatcher's walk (same init-flag check at
`0x6712140`, same root children `0x64da500` / root node `0x64da4c0`,
same flag-0 resolver calls) and the same completion gate, then calls the
resolver with `out_slot = NULL` (`sibling_gate`, 63B, 20 strict:
`cmpq $0x0,0x20(%rsi)` gate, `xor %ecx,%ecx`, resolver call) and returns
the resolver's status. It never invokes a handler. All jumps inside it
stay inside it; its only direct calls are the init function `0x63a8240`
and the resolver.

## The dispatcher contract (cited from #255, not re-claimed)

The dispatcher FDE `0x63a8ff0..0x63a93ba` is packet #255's exhibit and is
cited here by address only. Its contract, as decoded: walk the caller's
index array (qwords, length in `%rdx`) from the root children; flag-0
nodes resolve through the function at child `+0x08`; at completion the
final node must be non-NULL with `+0x20 == 0` (a handler leaf would fail
this gate with return 2); the resolver then resolves the caller's dotted
name below that node, appends the indices, and writes the final node to
the dispatcher's slot; the dispatcher tail-calls `slot+0x20` with the
caller's register arguments reloaded from its entry saves
(`0x63a92cb..0x63a92fe`). There is no read/write/opcode argument in this
contract — no register, stack slot, or flag distinguishes a read
dispatch from a write dispatch. Which leaf runs, and what it does, is
entirely the leaf's handler.

## Census: every dispatcher and sibling call site (surveyed, not claimed)

Direct-call census over all of `.text` (raw E8/E9 scan, verified by the
tool), plus a lea/movabs address-taken scan and a `.rela.dyn` pointer
scan. Result:

- Dispatcher `0x63a8ff0`: **54 E8 sites, 0 E9, 0 address-taken, 0 rela
  pointers**, in 5 FDEs with 7 / 7 / 23 / 5 / 12 sites.
- Sibling `0x63a8d00`: **19 E8 sites, 0 E9, 0 address-taken, 0 rela
  pointers**, in 6 FDEs with 1 / 4 / 5 / 2 / 6 / 1 sites. The sixth FDE
  is the top-level dumper `0x63e7dd9..0x63e87e5` (its one site is the
  `"stats.mutexes"` resolution below).
- Resolver `0x636e340`: **3 E8 sites** (dispatcher `0x63a9287`, sibling
  `0x63a8f37`, and invoke `0x63a891c`) plus **1 E9 site**: the wrapper's
  tail jump (below). 0 address-taken, 0 rela pointers.
- Sweep `0x63a5bf0`: **0 E8, 0 E9, 0 address-taken**, and exactly one
  `.rela.dyn` reference (slot `0x64dade8`, the reset leaf handler field).
- Wrapper `0x63a8990`: **0 E8 callers, 1 E9 caller** (the third gated
  helper's tail jump `0x635dfd3`, see below).
- Gated helper `0x635df90` (→ wrapper): **55 E8 sites, 0 E9**,
  0 address-taken, 0 rela pointers, in FDE 5 (53) and FDE 6 (2).
  Every site's name was resolved by the same register-tracking method
  as the invoke helper; all 55 resolve to literal `.rodata` names, 54
  distinct, listed in `records.json` under
  `census.helper_resolve_sites`. 54 are `stats.arenas.0.*` — the
  numeric segment `'0'` exercises the resolver's numeric branch
  (arenas child 0 by number) — and one is `'arena.0.initialized'`.
  None is reset-related.
- Invoke `0x63a88a0`: **0 E8, 1 E9** (the gated helper's tail jump
  `0x635df37`), 0 address-taken, 0 rela pointers.
- Walk-invoke `0x63a89f0`: **1 E8** (the second gated helper
  `0x635e07d`), **0 E9**, 0 address-taken, 0 rela pointers.
- Gated helper `0x635dee0` (→ invoke): **110 E8 sites, 0 E9**,
  0 address-taken, 0 rela pointers, in 6 FDEs with 2 / 2 / 92 / 1 /
  12 / 1 sites. Every site's name was resolved by tracking `rdi`
  through register moves to its defining `lea` (a plain
  nearest-`lea`-to-`rdi` scan missed the register-indirected literals
  and was discarded); all 110 resolve to literal `.rodata` names, 97
  distinct, listed in `records.json` under
  `census.helper_gate_sites`. No name is `'reset'`, `'mutexes'`,
  `'stats.mutexes'`, or ends in `.reset`. The three
  `stats.background_thread.*` names resolve under `stats`, not under
  `stats.mutexes`; the lone `'background_thread'` name resolves at
  root index 2 (handler `0x6386940`), a different node from the
  `stats.mutexes` child of the same name.
- Gated helper `0x635e020` (→ walk-invoke): **56 E8 sites, 0 E9**,
  0 address-taken, 0 rela pointers, in FDE 5 (53) and FDE 6 (3). Its
  sites pass the dumper's shared index buffer; buffer contents are
  exactly the paths the SIBL/DISP sequences constructed (censused
  above: no `'reset'` name, no `$0xb` immediate), so no helper-walk
  site can carry `[11, 8, 9]`.
- Root children (census, from `.rela.dyn` addends + `.rodata` names):
  13 children — `version`, `epoch`, `background_thread`,
  `max_background_threads`, `thread` (9), `config` (12), `opt` (65),
  `tcache` (3), `arena` (1), `arenas` (13), `prof` (11), `stats` (11),
  `experimental` (7). Root has no `'reset'` and no `'mutexes'` child,
  so no root-level name resolves to the reset leaf.

Every site's (FDE, name, length-argument class) is recorded in
`records.json` under `census`. Name inventory:

- DISP names (36 distinct, all stat fields): `accum`, `arenas.lextent`,
  `curlextents`, `curregs`, `curslabs`, `dirty_bytes`, `live`,
  `max_num_thds`, `max_wait_time`, `muzzy_bytes`, `nactive_huge`,
  `nactive_nonhuge`, `ndalloc`, `ndirty`, `ndirty_huge`, `nfills`,
  `nflushes`, `nmalloc`, `nmuzzy`, `nonfull_slabs`, `npageslabs_huge`,
  `npageslabs_nonhuge`, `nregs`, `nrequests`, `nreslabs`, `nretained`,
  `nshards`, `nslabs`, `num_ops`, `num_owner_switch`, `num_spin_acq`,
  `num_wait`, `retained_bytes`, `size`, `slab_size`,
  `total_wait_time`. Length classes: constant 3 (10), 4 (4), 5 (20),
  6 (13), variable `r13` (7, all in FDE 1).
- SIBL names (8 distinct + 1 caller-supplied): `arenas.bin`,
  `arenas.lextent`, `hpa_shard.nonfull_slabs`, `mutex`,
  `prof.stats.bins`, `prof.stats.lextents`, `stats.arenas`,
  `stats.mutexes`, plus FDE 1's caller-supplied name (its two callers
  pass fixed table entries, see below). Length classes: constant 0
  (12, resolve from root), 3 (5), 5 (1), variable `r13` (1, FDE 1).
- **No site passes `'reset'`, `'mutexes'` as a DISP name, or any dotted
  name ending in reset.** The only `'mutex'`-family SIBL names are
  `"stats.mutexes"` (FDE 6, length 0) and `"mutex"` (FDE 3, length 5).
- **No `$0xb` immediate exists in any of the seven caller FDEs**
  (FDEs 1–5 plus FDE 6 and FDE 7 `0x63e87e5..0x63e888b`, which contains
  no dispatch site). Verified by an objdump scan with `#` comment
  suffixes stripped, so comment addresses cannot pollute immediates.

## The stats.mutexes chain, traced end to end (new, claimed)

- FDE 6 site `0x63e83c3` (`fde6_sibl_setup`, 46B, 9 strict): array at
  `-0x240(%rbp)`, capacity qword 7 at `-0x2b0(%rbp)`, length 0,
  name `"stats.mutexes"` → sibling call. This appends indices `[11, 8]`
  (verified: `0x64da500 + 11*0x28 = 0x64da6b8` stats,
  `0x64daaa0 + 8*0x28 = 0x64dabe0` mutexes — arithmetic from #255's tree,
  cited).
- Loop (`fde6_loop`, 106B, 26 strict): FDE 1 is called per table entry
  with `(array, length 2, name = table[i])`, then the loop advances
  `r14` by 8 and ends when `r14 == 0x64ffdc8`. Table range
  `0x64ffd80..0x64ffdc8` = 9 qwords.
- The 9 table names, read from `.rela.dyn` addends, are exactly
  `mutexes`' 9 interior children in order: `background_thread`,
  `max_per_bg_thd`, `ctl`, `prof`, `prof_thds_data`, `prof_dump`,
  `prof_recent_alloc`, `prof_recent_dump`, `prof_stats`. Each interior
  child has count 7 — the 7 mutex fields FDE 1 dispatches
  (`num_ops`, `num_wait`, `num_spin_acq`, `num_owner_switch`,
  `total_wait_time`, `max_wait_time`, `max_num_thds`).
- Child 9 is `reset` (node `0x64dadc8`, count 0, children 0, handler
  `0x63a5bf0`): the only leaf, and the only child absent from the
  table. FDE 1 then resolves the mutex name (`length 2 → 3`) and
  dispatches the 7 fields at length 3 — paths `[11, 8, x, field]`.
  No step in this chain ever appends index 9.

## The other mutex paths (surveyed, depth argument)

- FDE 1's second caller is FDE 5 (`0x63e3578`), site `0x63e5c3e`:
  `(array, length 4, name = table[i])` over a 12-entry table at
  `0x64ffd20..0x64ffd80` (`large`, `extent_avail`, `extents_dirty`,
  `extents_muzzy`, `extents_retained`, `decay_dirty`, `decay_muzzy`,
  `base`, `tcache_list`, `hpa_shard`, `hpa_shard_grow`, `hpa_sec`).
  FDE 1 resolves the name (`length 4 → 5`) and dispatches the same 7
  fields at length 5 — depth-5 mutex nodes under arena subtrees, not
  `stats.mutexes` (depth 2) and not `reset` (depth 3, a leaf with no
  field children — a field dispatch below it would fail the dispatcher's
  leaf gate with return 2 before any handler ran).
- FDE 3's `'mutex'` SIBL (site `0x63e0b1c`, length 5) resolves a mutex
  below a depth-5 node, then dispatches the same 7 fields at length 6.
  A depth-6 mutex node cannot be `stats.mutexes` (depth 2); it is a
  per-bin/shard mutex, a sibling of bin stats (`nmalloc`, `ndalloc`,
  `curregs`, `nrequests`, `nfills`, `nflushes`, `nreslabs`,
  `curslabs`, `nonfull_slabs`) dispatched at the same length 5.
- FDE 1 itself is generic: it receives `(array, length, name)` from its
  caller, resolves the name (its one SIBL site, the only null-name site
  in the census), increments the length by 1, and dispatches the 7
  fields. Both of its callers pass fixed tables, so no runtime name can
  redirect it to `reset` either.

## The wrapper: a resolve-from-root entry, live only through its gated helper (new, claimed)

`wrapper_resolve_root`, `0x63a8990..0x63a89f0`, 96B, 34 strict: checks
the init flag, calls init `0x63a8240` on first use (returns 11 on init
failure), then tail-jumps (`E9` at `0x63a89db`) to the resolver with
`rsi = root node 0x64da4c0`, `rcx = NULL` (resolve-only), the name in
`rdx` taken from its own `rsi` input (`mov %rbp,%rdx` in the
tail-jump block), and the caller's remaining arguments in `r8`/`r9`
(from its `rdx`/`rcx` inputs). It is the natural entry a
control-plane client would use to resolve a full dotted name such as
`"stats.mutexes.reset"` from root — and it has **zero E8 callers but
one E9 caller**: the third gated helper below tail-jumps to it. So the
wrapper is exercised, but only for arena stat names, never for reset.

## The invoke family: live gated paths (new, claimed in part)

The tree-entry family has five members, not two. Beside the dispatcher
and the sibling there are three more, all sharing the init-flag check
(`0x6712140`) and the root node / root children:

- **Invoke** `0x63a88a0..0x63a8984`, 228B (characterized, not
  exhibited): init check, then the resolver from root with the
  caller's name, an out-slot on the stack, and a capacity of 7; on
  success it checks the resolved node and its `+0x20` handler are
  non-NULL and `call`s the handler (returns 2 on resolve/handler
  failure, 11 on init failure). It has zero direct callers, but it is
  **not dormant**: the gated helper below tail-jumps to it.
- **Walk-invoke** `0x63a89f0..0x63a8cff`, 783B (gate exhibited): a
  walk variant that loads the root node and root children, walks the
  caller's index array exactly like the dispatcher, and at completion
  requires the final node non-NULL **and** `+0x20 != 0` — the complement
  of the dispatcher/sibling gate — then restores the caller's
  arguments and tail-calls the handler (`walk_invoke_gate`, 72B, 21
  strict: `mov 0x20(%rax),%rax`, null check, `jmp *%rax`). It takes
  no name: the path must already be fully resolved in the array.
- **Gated helper → invoke** `0x635dee0..0x635df87`, 167B
  (`helper_gate_invoke`, 49 strict): reads a global flag at
  `0x64ffab4`; if set, it calls a predicate `0x634f0b0` and returns 11
  when the predicate is nonzero (otherwise it proceeds); it builds a
  TLS context object (the `%fs:0x330` check plus the `0x63ef8e0`
  getter path), then tail-jumps to invoke with the caller's first
  argument as the name. Its only out-of-FDE direct jump is that
  tail-jump (`0x635df37` → `0x63a88a0`); all other jumps stay inside.
  This is the one live name-resolution path in the binary — and its
  110 callers never name `reset` (census above).
- **Gated helper → walk-invoke** `0x635e020..0x635e0c5`, 165B
  (characterized, not exhibited): the same gate structure (global
  `0x64ffab4` + predicate `0x634f0b0` + TLS context), but it `call`s
  walk-invoke with the caller's first two arguments as
  `(array, length)` and returns its status. Its 56 callers are the
  arena/mutex dumpers passing their shared index buffer.
- **Gated helper → wrapper** `0x635df90..0x635e01f`, 143B
  (`helper_resolve_root`, 39 strict): the same gate structure, but it
  tail-jumps to the wrapper with the caller's first argument as the
  name (the wrapper moves its own `rsi` into the resolver's `rdx`),
  the second as the array, and the third as the count pointer — a
  resolve-only-from-root call that appends indices to the caller's
  array. Its only out-of-FDE direct jump is that tail-jump
  (`0x635dfd3` → `0x63a8990`); all other jumps stay inside. Its 55
  callers pass only `stats.arenas.0.*` and `'arena.0.initialized'`
  names (census above).

So the full entry picture: dispatcher (54 sites) and sibling (19) are
the dumpers' workhorses; invoke is live only through its gated helper
(110 sites, all non-reset names); walk-invoke is live only through its
gated helper (56 sites, dumper buffers); the wrapper is live only
through its gated helper (55 sites, arena names only). No entry point
in any of these paths can be driven to `reset` by any name or index
array observed in the binary.

## Exhibits (claimed bytes: 1042B total, 289 strict lines)

| file | range | bytes | strict |
| --- | --- | --- | --- |
| `resolver_entry.hex` | `0x636e340..0x636e380` | 64 | 19 |
| `resolver_append.hex` | `0x636e5b9..0x636e62f` | 118 | 27 |
| `resolver_numeric_return.hex` | `0x636e62f..0x636e6d6` | 167 | 45 |
| `sibling_gate.hex` | `0x63a8f10..0x63a8f4f` | 63 | 20 |
| `fde6_sibl_setup.hex` | `0x63e83a5..0x63e83d3` | 46 | 9 |
| `fde6_loop.hex` | `0x63e83e4..0x63e844e` | 106 | 26 |
| `wrapper_resolve_root.hex` | `0x63a8990..0x63a89f0` | 96 | 34 |
| `helper_gate_invoke.hex` | `0x635dee0..0x635df87` | 167 | 49 |
| `walk_invoke_gate.hex` | `0x63a8c00..0x63a8c48` | 72 | 21 |
| `helper_resolve_root.hex` | `0x635df90..0x635e01f` | 143 | 39 |

This packet has 24 files (10 exhibits × 2 + README + EVIDENCE +
records + MANIFEST), above the usual 18-file light-packet target: the
three extra exhibits cover the gated-helper → invoke path, the
walk-invoke gate, and the gated-helper → wrapper path. The census
showed these to be the only live name-resolution paths and the only
index-only invoke path — and the wrapper exhibit plus the helper
exhibit are what correct the draft's "dormant wrapper" claim, which
the verifier's E9 census caught. Dropping any of them would leave the
"never dispatched" conclusion resting on an unexhibited entry point.

`.hex` files contain raw binary bytes (not hex text), matching packet
#255's format note. Each exhibit has a matching `.objdump.txt`.
Disjointness was checked with the recursive range+fde collector over
all merged-tree `records.json` files, deduplicated by real path, with
census and cited-only subtrees excluded (see `records.json`); the
claimed set is exactly the 10 ranges above. Packet #199's
`RE-001-node115-lu-resolver` is a different resolver
(`0x4d35b60..0x4d35de4`, merge/redistribute) and does not overlap.

## Verification

- Static verifier `tools/node115_dispatch_construct.py`: exit 0
  (binary size + SHA-256, exhibit bytes + strict counts, resolver /
  sibling / FDE 6 / wrapper spot checks, mutex-table cross-check,
  full E8/E9 + address-taken + rela censuses, disjointness, MANIFEST).
- Unit tests `tests/test_node115_dispatch_construct.py`: 10/10
  standalone (binary identity, hex + objdump regeneration with header
  stripped, strict counts, resolver/sibling/FDE 6 targets, mutex-table
  cross-check, no-`$0xb` scan + helper-gate and helper-resolve name
  inventories, verifier exit 0).
- `make verify`: exit 0 (see run log; tally is this packet's own, not
  copied from any earlier packet).
- `make catalogue-check`: run and reported honestly (pre-existing
  `Stale catalogue: README.md` failure on the new base, also present on
  a pristine checkout — not a packet regression).
- Full `make test` was NOT attempted (584 test files on the new base;
  hours-long and liable to be killed by a VM restart). No full-suite
  tally is claimed.

## Scope: surveyed vs decoded vs NOT covered

- **Surveyed**: all 54 dispatcher + 19 sibling direct call sites
  (names, length classes, FDE grouping); all 110 gated-helper →
  invoke sites (name inventory, register-tracked), all 55
  gated-helper → wrapper sites (name inventory, register-tracked),
  and all 56 gated-helper → walk-invoke sites (FDE grouping,
  buffer-passing pattern); all resolver/sibling/wrapper/invoke/
  walk-invoke direct + tail-call entry points; address-taken scans
  (REX 48 form in the verifier, all REX forms in a separate session
  scan — both zero) and rela-pointer scans for all ten functions;
  `$0xb` immediates in all seven caller FDEs; the 9-entry mutex
  table, 12-entry arena table, and 13 root children via `.rela.dyn`.
- **Decoded**: the resolver's segment loop, append store, capacity
  bound, numeric branch, trap edge, and out-slot/return contract; the
  sibling's gate + NULL-out-slot resolve-only contract; the wrapper's
  root-resolve + tail-jump contract; the invoke function's
  resolve-then-call contract; the walk-invoke gate (`+0x20 != 0`) +
  tail-call contract; all three gated helpers' gate structure (global
  flag + predicate + TLS context) and argument shuffling, including
  the wrapper's name-from-`rsi` rule that makes the resolve helper's
  first argument its name; the FDE 6 → FDE 1 stats.mutexes chain end
  to end; the FDE 5 → FDE 1 and FDE 3 mutex chains by depth and
  field-name identity.
- **NOT covered**: stat-leaf handlers' value plumbing (how a dumped
  value travels through the handler's arguments — the dispatcher
  forwarding contract is decoded, per-leaf use is not); the semantic
  labels of FDE 5's 12 table entries beyond their names; the
  formatting helper (`0x63de320`) and the `0x63a8240`
  init function beyond their call sites; the gate predicate
  `0x634f0b0`'s semantics (what condition blocks a gated dispatch)
  and the global flag `0x64ffab4`'s writer; per-site array contents
  for all 56 helper-walk sites (pattern established from the shared
  buffer + SIBL/DISP census, not per-site decoded); the invoke FDE's
  full body beyond its resolver call + handler call + returns;
  whether a runtime-registered or out-of-binary caller could invoke
  the dispatcher (no evidence in the file: no stored pointer, no
  direct call — but static analysis cannot exclude runtime code
  generation). None of these gaps weakens the conclusions: every
  in-binary dispatch path was censused, and none reaches `reset`.

## Corrections to earlier packets

- **Packet #255's "on demand" conclusion stands and is now grounded**:
  #255 inferred the sweep is reached only by a caller deliberately
  supplying `[11, 8, 9]`. This packet shows the stronger result: no
  caller supplies it at all, by name or by index — the path is
  constructed only up to `[11, 8]`, by name, and the table that drives
  the per-mutex loop excludes `reset`.
- **Packet #255's "fixed call" is identified**: the dispatcher's fixed
  call at `0x63a9287` is the name-to-index resolver decoded here, not
  a handler installer. The dispatcher's leaf gate (`+0x20 == 0`
  required before the resolver call) is consistent with this reading:
  the walk ends at an interior node and the resolver finishes the path
  below it.
- **No correction to any address, count, or FDE bound in #253/#254/#255
  was needed.** The sweep FDE, work-fn FDE, wait-helper FDE, dispatcher
  FDE, and tree nodes all re-verified at the cited addresses. (Note for
  future readers: packet #253's FDE `0x63a5bf0` is the reset leaf's
  handler function itself, not a function with its own direct callers —
  its 18 sites are wait-helper calls *inside* it, and packet #254's 18
  sites are work-fn calls *inside* it.)

## Next question (#257)

The control tree's dispatch surface is now mapped, but its *write*
surface is not: is there any caller — in this binary or through the
wrapper's gated helper — that issues a genuine control *write*
(a dispatch whose leaf handler mutates state, as opposed to the stat
dumpers' reads), and if the tree is read-only in practice, what invokes
the wrapper's root-resolve entry at all? A natural next step is to
decode the gate predicate `0x634f0b0` and find the writer of the
global flag `0x64ffab4` (what enables or blocks a gated dispatch),
census the remaining control-tree-adjacent functions (the init
function `0x63a8240` and the formatting helper `0x63de320`), and
check whether any leaf besides `reset` carries a mutating handler.
