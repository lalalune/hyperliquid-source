# RE-001-node115-lu-mutexes-reset

## Question

Packet #254's next question: find the callers of the #253 sweep FDE
`0x63a5bf0..0x63a6470` — who invokes the reset sweep, and what triggers
it — deciding whether the waiter-record reset runs on a timer, on
demand, or on a lifecycle event.

## Answer

On demand, through a control-tree dispatch — not on a timer, and not on
a lifecycle hook. The sweep is the handler of the leaf control named
`reset` at the tree path `stats.mutexes.reset` (index path `[11, 8, 9]`),
and the only way code reaches it is a 970-byte index-walking dispatcher
FDE that resolves an index array through the tree and tail-calls the
leaf's handler. There is no direct call, jump, GOT slot, PLT entry, or
timer edge into the sweep anywhere in the binary: the census is zero on
every direct channel, and the single runtime pointer to the sweep is the
leaf's own handler field.

## The tree

Control nodes are 40-byte (`0x28`) records in `.data.rel.ro`, in
runtime (relocated) form:

- Interior node: `[1, name_ptr, child_count, children_ptr, 0]`.
- Leaf node: `[1, name_ptr, 0, 0, handler]`.

The four path nodes claimed here (file bytes plus `.rela.dyn` addends
give the runtime values; RELATIVE slots are zero-filled in the file):

- Root `0x64da4c0`: `[1, '' (0x4376fd), 13, 0x64da500, 0]`.
  `stats` is child index 11:
  `0x64da500 + 11*0x28 = 0x64da6b8`.
- `stats` `0x64da6b8`: `[1, 'stats' (0x44869a), 11, 0x64daaa0, 0]`.
  `mutexes` is child index 8:
  `0x64daaa0 + 8*0x28 = 0x64dabe0`.
- `mutexes` `0x64dabe0`: `[1, 'mutexes' (0x4385fa), 10, 0x64dac60, 0]`.
  `reset` is child index 9:
  `0x64dac60 + 9*0x28 = 0x64dadc8`.
- `reset` `0x64dadc8`: `[1, 'reset' (0x440c22), 0, 0, 0x63a5bf0]`.
  The handler is the #253 sweep FDE, cited by address only.

`reset` is the only leaf among `mutexes`' ten children; the other nine
are interior nodes with seven children each (the mutex-profile stat
families: `background_thread`, `max_per_bg_thd`, `ctl`, `prof`,
`prof_thds_data`, `prof_dump`, `prof_recent_alloc`, `prof_recent_dump`,
`prof_stats`). The sibling nodes are cited for the tree diagram only,
not claimed. The name strings live in `.rodata` and are cited only.

## The dispatcher, in program order

FDE `0x63a8ff0..0x63a93ba` (970 bytes, `endbr64` entry, 8 bytes of
`int3` padding before it, 6 bytes after it, next FDE at `0x63a93c0`):

1. Prologue saves the caller's registers and three stack arguments;
   the walk takes an index array in `%rsi` and its length in `%rdx`.
2. If the `.bss` init flag at `0x6712140` is clear, it calls the init
   function `0x63a8240` (site `0x63a9056`, cited only); a nonzero
   return fails with code `0xb` (site `0x63a9380`).
3. It loads the root children array `0x64da500` (site `0x63a9063`)
   and the root node `0x64da4c0` (site `0x63a906d`).
4. Per level (four-way unrolled): the next index is bounds-checked
   against the current node's `+0x10` count (root count check against
   `0x64da4d0` at site `0x63a9098`); the child is
   `children_array + index*40`; descent follows the child's `+0x18`
   children pointer. A node whose first byte is 0 is dynamic: the
   dispatcher calls the resolver function at its `+0x08` field
   (sites `0x63a91ab`, `0x63a91f9`, `0x63a921d`, `0x63a9242`,
   `0x63a933f`, `0x63a9393`, and `0x63a9366` for the root level)
   and continues from the node it returns. All three levels of the
   `stats.mutexes.reset` path are static arrays, so the dynamic path
   is not exercised on this path; it is documented, not claimed, for
   this path.
5. On completing the walk, if the final node's `+0x20` handler is null
   the walk fails (check at site `0x63a9266`); otherwise the handler
   is loaded (site `0x63a92aa`) and tail-called with the caller's
   original arguments (site `0x63a92fe`, `jmp *%rax`). A failed walk
   returns code 2 (site `0x63a91e7`). The fixed call at `0x63a9287`
   to `0x636e340` just before the tail-call is cited only; its
   purpose was not decoded and is not needed for the trigger claim.

So reaching the sweep requires a caller to deliberately supply the
index path `[11, 8, 9]` to this dispatcher. Nothing in the binary
supplies it on a schedule: no timer callback, thread-spawn, or
`.init_array` entry points at the sweep or at the dispatcher with this
path, and the sweep itself has no other inbound edge (see census).

## Census: how the sweep is (not) reached

- Direct `E8` calls to the sweep entry `0x63a5bf0`: **0**.
- Direct `E9` jumps to the sweep: **0**.
- RIP-relative LEA references to the sweep: **0**.
- `.rela.plt` entries with addend `0x63a5bf0`: **0**.
- `.rela.dyn` entries with addend `0x63a5bf0`: **exactly 1** — slot
  `0x64dade8`, the `reset` leaf's `+0x20` handler field. That slot is
  the sweep's only runtime pointer in the whole binary.
- The name `reset` (`0x440c22`) is referenced by no `lea` anywhere in
  `.text`; it is reachable only through the leaf node's `+0x08`
  field. There is no name-based lookup of `reset` in code.
- Dispatcher inbound edges: **54** direct `E8` sites, **0** `E9`,
  **0** LEA, **0** `.rela.dyn`, **0** `.rela.plt`. The 54 sites group
  into five large stats-reader/dumper FDEs (7, 7, 23, 5, and 12
  sites); those FDEs are surveyed for counts and grouping only, not
  decoded in depth and not claimed.

## Surveyed vs decoded, honestly

- Surveyed: all 54 dispatcher call sites (grouped by FDE); the full
  children lists of root (13), `stats` (11), and `mutexes` (10);
  the whole `.rela.dyn` table (60,723 entries) for sweep and
  dispatcher addends; the whole `.text` for direct calls, jumps, and
  RIP-relative references to the sweep and the dispatcher.
- Decoded in depth: the dispatcher FDE in full (232 strict
  instructions) and the four tree-path nodes.
- NOT covered: which single one of the 54 dispatcher call sites (or
  which upstream caller of those five FDEs) constructs the index path
  `[11, 8, 9]` — no `$0xb` (11) immediate appears in any of the five
  caller FDEs, so the path is assembled further upstream (registers
  or tables), and isolating that constructor is the next question.
  The read-versus-write argument convention of leaf handlers, and the
  purpose of the dispatcher's fixed `0x636e340` call, were also not
  decoded. Nothing in those gaps weakens the trigger claim: whatever
  constructs the path, it must pass through this dispatcher on
  demand, and no scheduled or lifecycle edge exists.

## What this decides

- Packet #254's open question is answered: the waiter-record reset
  runs on demand via the `stats.mutexes.reset` control, when a caller
  dispatches index path `[11, 8, 9]` through the control dispatcher.
  It does not run on a timer or on a lifecycle event.
- The #253 sweep's role is now placed: it is the handler of a
  statistics-reset control, which fits its behaviour (iterate every
  waiter record, reset each one's counters via #254's record-reset
  function) and its position as the only action leaf under `mutexes`.
- The control tree's node layout is established for this branch:
  40-byte nodes, interior `[1, name, count, children, 0]`, leaf
  `[1, name, 0, 0, handler]`, with runtime values read through
  `.rela.dyn` addends (file qwords at RELATIVE slots are placeholders).

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame` (PC-relative sdata4 encoding);
  `.text` file offset = VA − 0x1000; `.data.rel.ro` file offset =
  VA − 0x2000; `.rodata` file offset = VA as-is. Static analysis
  only; the binary was never executed.
- 5 exhibits, 970 + 4×40 = 1130 bytes: the dispatcher FDE (232 strict
  instructions; strict = mnemonic-line count: address + bytes field +
  tab + mnemonic; objdump byte-continuation lines excluded) and the
  four tree-path nodes (data exhibits, `objdump -s` dumps).
- Disjointness: the five claimed ranges were checked against all
  packets #183–#254 with the recursive range+fde collector (records
  deduplicated by real path; census and cited-only metadata subtrees
  excluded from the claimed set, so this follow-up to #253 is not
  falsely blocked by #253's own cited ranges): 983 unique claimed
  ranges, 0 overlaps. The verifier's merged-tree-only recount gives
  847 unique ranges, likewise 0 overlaps.
- Verification: static verifier exit 0; own unit tests 10/10
  standalone; `make verify` exit 0; `make catalogue-check` run and
  reported honestly (exit 2, pre-existing `Stale catalogue: README.md`
  on a pristine checkout, not a packet regression). Full `make test`
  was not attempted: the new base carries 584 test files and a full
  run takes hours and is liable to VM-restart termination; this
  deviation from the worktree `AGENTS.md` line is disclosed here and
  in the PR body, as in packets #245–#254.

## Next question (for #256)

Which caller constructs the dispatcher index path `[11, 8, 9]` for
`stats.mutexes.reset` — is there a name-to-index resolver that turns
a dotted control name into indices, or do the callers hardcode the
path upstream of the five surveyed FDEs — and is the `reset` leaf
write-only, or can a read dispatch reach it too?
