# RE-001-node115: lu control-tree write surface and the gate that guards it

## Question

Packet #256 ended with a next question: is there any caller — in this
binary or through the wrapper's gated helper — that issues a genuine
control *write* (a dispatch whose leaf handler mutates state, as opposed
to the stat dumpers' reads), and if the tree is read-only in practice,
what invokes the wrapper's root-resolve entry at all? The suggested
steps were to decode the gate predicate `0x634f0b0`, find the writer of
the global flag `0x64ffab4`, census the init function `0x63a8240` and
the formatting helper `0x63de320`, and check whether any leaf besides
`reset` carries a mutating handler.

## Answer, in short

1. **No — the tree is NOT read-only. Genuine write actions exist, and
   five are decoded in full or in their core window.** `epoch` bumps
   the epoch through `0x63a77d0`; `thread.tcache.flush` calls the
   flush routine `0x63ec600`; `thread.peak.reset` calls `0x63c2cf0`;
   `prof.reset` calls `0x63cf9d0` with a clamped count; `prof.dump`
   calls `0x63c3700` and maps its boolean result to 0 or 14. The
   `stats.mutexes.reset` sweep (packets #253/#254, cited) is a sixth.
   All five decoded handlers have zero direct call or jump sites —
   they are reachable only through the dispatcher's indirect
   tail-call, exactly like the sweep.
2. **The gate is a three-state lazy-init flag, and its writer census
   is complete.** Flag `0x64ffab4`: 0 = idle/OK (dispatch proceeds),
   1 = init in progress (callers spin or yield until 0), 2 = init
   requested. There are exactly three writes in the whole binary:
   request-init `0x634ece0` arms 2 (`reqinit_flag2`), the predicate
   sets 1 at slow-path start (`pred_flag1`) and 0 at slow-path end
   (`pred_flag0`). Every other reference is a read (12 sites) or a
   lea-plus-deref read idiom (1 site). No other function can arm,
   clear, or corrupt the gate.
3. **The gate's return contract is: 0 = proceed, 1 = abort.**
   The gated helper `0x635dee0` (cited from #256) reads the flag: if
   0 it takes a TLS-byte check and tail-calls the entry; if nonzero
   it calls the predicate, and a predicate return of 1 makes it
   return 11 immediately without dispatching. The 20-byte thunk
   `0x635f320` (`pred_thunk`, exhibited in full) is the same contract
   in miniature: flag 0 → return 0, else tail-call the predicate.
   The predicate itself returns 0 on the flag-0 fast path and after
   waiting out flag 1; its slow-init exits return 1, except the
   completion path, which tail-calls `0x6368e40` (cited only).
4. **No write goes through the wrapper.** The wrapper `0x63a8990`
   (cited from #256) resolves a name from root and returns a status;
   it never invokes a handler. Its only entry is the gated helper's
   tail jump `0x635dfd3`, whose 55 sites pass arena names
   (`stats.arenas.0.*`, cited from #256) — resolve-only work for the
   dumpers, which then dispatch reads through DISP/walk-invoke. The
   wrapper's root-resolve entry is therefore a dumper utility, not a
   dispatch path, and no write action is reachable through it.
5. **Init `0x63a8240` is the dispatcher's one-time table builder.**
   It locks the shared mutex `0x67121a0`, returns 0 at once if the
   `.bss` flag `0x6712140` is already set, otherwise builds the
   arena/table structure (including the `0x1000`/`0x1001` entries),
   calls `0x63a77d0`, and sets `0x6712140 = 1`. Its only callers are
   the five tree-entry functions (invoke, wrapper, walk-invoke,
   sibling, dispatcher) — one site each, zero tail jumps.
6. **The formatting helper `0x63de320` is read-side.** It renders a
   list into a caller buffer through the formatter `0x63dbd80`,
   gated by a two-state object header (state > 1 → return at once)
   and two flag bytes at `+0x1c`/`+0x1d`. Its 18 call sites are all
   in the stat-dumper FDEs (`0x63e1xxx`–`0x63e8xxx`). It writes only
   to the caller's output buffer — read semantics, not allocator
   mutation.

## The gate, decoded

Predicate `0x634f0b0..0x634f8d5` (2085B; key windows exhibited, whole
FDE characterized by its jump/call structure, not claimed in full):

- Entry (`pred_entry`, 102B, 21 strict): pushes, loads the mutex
  `0x6509660`, `pthread_mutex_trylock` (with the #251 wait helper
  `0x63bf680` on contention), reads the flag into `%ebp`.
- Flag 0 → return 0 (`0x634f200`: clear the contended byte
  `0x6509688`, unlock, `xor %eax,%eax`). The thunk exhibits the same
  fast path in 20 bytes.
- Flag 1 with the caller as the recorded owner thread (`0x6509690`,
  written by request-init from `pthread_self`) → return 0
  (re-entrant owner proceeds). Flag 1 with another owner → spin
  with exponential `pause` backoff (capped, then `sched_yield`
  loop) until the flag reads 0 → return 0.
- Flag 2, or owner 0, or any other nonzero flag → request-init
  `0x634ece0` is called: on failure (nonzero return) the predicate
  returns 1; on success (flag armed to 2) the slow path runs.
- Slow path (`pred_flag1`, 54B, 11 strict): clears the contended
  byte, unlocks, obtains a context from `0x63efbb0` (NULL → return
  1), writes flag = 1, then runs affinity/cpucount/sysconf probes
  and arena setup calls (`0x63673e0`, `0x636b0a0`, `0x6369e20`,
  `0x63c41c0`, `0x63bfa50`, cited only).
- Completion (`pred_flag0`, 33B, 4 strict): after the setup calls,
  two config bytes are loaded and flag = 0 is written; a mask built
  from five config bytes is OR-ed into `0x6509698` and the neighbour
  byte `0x64ffab0` is set to (mask != 0) via `setne`. Other slow
  exits return 1 directly.

Request-init `0x634ece0..0x634f09d` (957B; flag window exhibited):

- Records `pthread_self` into the owner slot `0x6509690`, zeroes a
  `0x336`-byte frame, runs a chain of setup/check calls; any
  nonzero check returns 1.
- On success it writes `0x65096a0 = 1`, `0x650969c = 2`,
  `0x65096c0 = 0`, calls `0x634ebb0` (NULL → return 1), copies the
  result pointer, and — unless the alternate config path applies —
  writes flag = 2 (`reqinit_flag2`, 51B, 8 strict) and returns 0.
  The alternate path reaches the same flag = 2 write through
  `0x634f03e`/`0x634f092`.

## The write actions, decoded

Handler argument convention (from the five decoded handlers, consistent
with the dispatcher's tail-call of the caller's original arguments):
`%rdi` = context, `%rcx` = oldp, `%r8` = oldlenp, `%r9` = newp,
stack = newlen. A pure action requires the value arguments to be
zero; a read/write leaf uses oldp/newp with an 8-byte length.

- **epoch** (`epoch_head`, 148B, 40 strict; FDE `0x63a7fc0..0x63a8239`,
  633B, head exhibited, memcpy tail characterized): locks the init
  mutex `0x67121a0`. Write: newp != 0 requires newlen == 8, else
  22; then calls `0x63a77d0` (the same advance call init makes).
  Read: oldp != 0 and oldlenp != 0 copies from the init structure
  at `0x6712130` to oldp (fast path stores the first qword; the
  `*oldlenp != 8` tail is an 8-byte-unrolled copy loop, characterized
  not exhibited). Write and read can both run in one call. No direct
  E8/E9 sites.
- **thread.tcache.flush** (54B, 16 strict, full FDE): byte 0 of the
  context must be nonzero, else 14. All four value arguments must be
  zero, else 1. Then calls `0x63ec600` and returns 0. No direct
  E8/E9 sites.
- **thread.peak.reset** (38B, 11 strict, full FDE): all four value
  arguments must be zero, else 1. Then calls `0x63c2cf0` and
  returns 0. No direct E8/E9 sites.
- **prof.reset** (97B, 26 strict, full FDE): the prof-enabled byte
  `0x6713606` must be nonzero, else 2. oldp/oldlenp must be zero,
  else 1. Optional newp requires newlen == 8, else 22; absent newp
  a global value at `0x6712438` is used. The value is clamped to
  63 and passed to `0x63cf9d0`; returns 0. No direct
  E8/E9 sites.
- **prof.dump** (81B, 24 strict, full FDE): prof-enabled byte must be
  nonzero, else 2. oldp/oldlenp must be zero, else 1. Optional newp
  requires newlen == 8, else 22; the value (or 0) is passed to
  `0x63c3700`, whose boolean result maps to 0 or 14. No direct
  E8/E9 sites.

Error codes are reported as raw numbers (1, 2, 14, 22); no errno
names are claimed except the size-mismatch context for 22.

## The tree census (surveyed, not claimed)

Walked from the root node through `.rela.dyn` addends (RELATIVE file
slots are zero-filled): **246 nodes, 204 leaves, 7 flag-0 dynamic
nodes** (`arena`, `arenas/bin`, `arenas/lextent`, `prof/stats/bins`,
`prof/stats/lextents`, `stats/arenas`, `experimental/arenas` — the
numeric-index children the #256 resolver's numeric branch resolves).
The full leaf table (path, node, handler) is in `records.json` under
`census.tree.leaves`. Leaves decoded in depth: the five above plus the
cited `stats.mutexes.reset` sweep. The remaining ~199 leaves are
NOT individually classified as read vs write — that is the next
question, not a claim made here. By name, the undecoded candidates
for further write actions include `arenas.create`, `tcache.create`,
`tcache.destroy`, `experimental.hooks.install/remove`,
`prof.log_start/log_stop`, and `thread.prof.active`; the `opt.*`
and `config.*` families are value leaves whose handlers were not
decoded.

## Exhibits (claimed bytes: 851B total, 210 strict lines)

| file | range | bytes | strict |
| --- | --- | --- | --- |
| `pred_entry.hex` | `0x634f0b0..0x634f116` | 102 | 21 |
| `pred_flag1.hex` | `0x634f2a4..0x634f2da` | 54 | 11 |
| `pred_flag0.hex` | `0x634f671..0x634f692` | 33 | 4 |
| `reqinit_flag2.hex` | `0x634ef41..0x634ef74` | 51 | 8 |
| `pred_thunk.hex` | `0x635f320..0x635f334` | 20 | 6 |
| `epoch_head.hex` | `0x63a7fc0..0x63a8054` | 148 | 40 |
| `tcache_flush.hex` | `0x636de20..0x636de56` | 54 | 16 |
| `peak_reset.hex` | `0x636e210..0x636e236` | 38 | 11 |
| `prof_reset.hex` | `0x636d870..0x636d8d1` | 97 | 26 |
| `prof_dump.hex` | `0x6377850..0x63778a1` | 81 | 24 |
| `init_entry.hex` | `0x63a8240..0x63a829b` | 91 | 19 |
| `fmt_entry.hex` | `0x63de320..0x63de372` | 82 | 24 |

`.hex` files contain raw binary bytes (not hex text), matching packet
#255's format note. Each exhibit has a matching `.objdump.txt`.
Disjointness was checked with the recursive range+fde collector over
the merged tree (deduplicated by real path; census and cited-only
subtrees excluded): 847 unique claimed ranges, 0 overlaps; extended
with the #255/#256 worktrees: 862 ranges, 0 overlaps. Slug
`RE-001-node115-lu-write-surface` checked against the merged tree;
no directory-name collision. This packet has 28 files (12 exhibits
× 2 + README + EVIDENCE + records + MANIFEST), above the usual
18-file light-packet target: the count is driven by twelve small
windows (20–148B each, 851B total — smaller than #256's 1042B)
across eight distinct functions, each window grounding a different
mechanism (gate entry, two flag transitions, request-init arming,
thunk, epoch contract, three action handlers, init entry, formatter
entry); dropping any one would leave a claimed mechanism
unexhibited.

## Verification

- Static verifier `tools/node115_write_surface.py`: exit 0
  (binary size + SHA-256, exhibit bytes + strict counts, objdump
  regeneration with header stripped, 22 spot checks, single-pass
  E8/E9 census for all ten functions, tree-walk leaf-set match,
  disjointness, MANIFEST).
- Unit tests `tests/test_node115_write_surface.py`: 10/10
  standalone (binary identity, exhibit + objdump regeneration,
  strict totals 851B/210, flag-write spots, epoch call target, leaf
  inventory, MANIFEST coverage, tamper control, verifier exit 0).
- `make verify`: exit 0 (559 manifests, 7183 entries — this packet's
  own tally: base 7154 + 29).
- `make catalogue-check`: exit 2 with the pre-existing
  `Stale catalogue: README.md` failure on the new base, also present
  on a pristine checkout — not a packet regression.
- Full `make test` was NOT attempted (584 test files on the new base;
  hours-long and liable to be killed by a VM restart). No full-suite
  tally is claimed.

## Scope: surveyed vs decoded vs NOT covered

- **Surveyed**: all 16 flag references (3 writes, 12 reads, 1
  lea-read); all 7 gate-predicate E8 + 1 E9 sites; all 5 init E8
  sites; all 18 formatter E8 sites; direct-entry census for the
  wrapper, invoke, and all five decoded leaf handlers; the full
  246-node tree walk (204 leaves + 7 dynamic nodes) via `.rela.dyn`.
- **Decoded**: the predicate's entry, flag-0 return, owner/spin
  paths, request-init call edge, slow-path flag transitions, and
  completion mask; request-init's owner recording, check chain, and
  flag-2 arming; the thunk in full; the epoch read/write contract
  head; the four action handlers in full; the init entry window;
  the formatter entry window.
- **NOT covered**: the predicate's slow-path setup calls
  (`0x63673e0`, `0x636b0a0`, `0x6369e20`, `0x63c41c0`,
  `0x63bfa50`) beyond their call sites; the completion tail-call
  `0x6368e40`; the TLS-byte slow path (`0x63ef8e0`) shared by the
  helpers and the predicate; the epoch `*oldlenp != 8` copy tail
  beyond its loop characterization; per-leaf read/write
  classification for the ~199 undecoded leaves; the config bytes
  gating `prof.reset`/`prof.dump` (`0x6713606`) and their writers;
  the four large allocator FDEs' flag reads beyond their single
  sites; whether a runtime-registered or out-of-binary caller could
  dispatch a write (no in-file evidence: no stored handler pointer
  besides the leaf fields, no direct call — but static analysis
  cannot exclude runtime code generation). None of these gaps
  weakens the conclusions: every in-binary writer of the gate flag
  was censused, and five write actions plus the cited sweep prove
  the tree is not read-only.

## Corrections to earlier packets

- **None needed.** No address, count, or FDE bound in #253/#254/#255/
  #256 was contradicted. #256's gate description ("global flag
  `0x64ffab4` + predicate `0x634f0b0` + TLS context") is confirmed
  and extended: the flag is tri-state, the predicate is the lazy
  initializer, and the helper's abort code on predicate-1 is 11.
- **One draft self-correction, caught during analysis**: an early
  read of the `0x63ed259` LEA as "address-taken" was wrong — the
  next instruction dereferences the pointer (`mov 0x0(%rbp),%r9d`
  at `0x63ed26b`), so it is a read idiom, not a stored pointer;
  the writer census stands at exactly three.

## Next question (#258)

Complete the per-leaf read/write classification for the remaining
~199 leaves, starting with the named write-action candidates
(`arenas.create`, `tcache.create/destroy`,
`experimental.hooks.install/remove`, `prof.log_start/log_stop`,
`thread.prof.active`); decode the TLS-byte slow path (`0x63ef8e0`)
and the predicate's completion tail-call (`0x6368e40`); and find
the writers of the prof-gating byte `0x6713606`.
