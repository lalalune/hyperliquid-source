# RE-001-node115-lu-value-leaves-bin

Packet #261. Continues packet #260's next question: per-leaf read/write
classification for the next value-family batch (`opt/prof`, `opt/tcache`,
`config/stats`, `thread/allocated`, `stats/allocated`), two
enable-slow-path bin-setup callees (`0x63ec4c0`, `0x634ebb0`), the
interval-value consumer FDE `0x63c41c0`, and the teardown-gate body
callees (`0x63c3b70`, `0x63539d0`, `0x6353a20`, `0x63efd20`).

## What this packet claims

### Leaves classified here (5, all read-only)

All 5 handlers are reached only by dispatcher indirect tail-call: a
whole-`.text` E8/E9 census gives 0 direct entries per leaf, and each
leaf's `.rela.dyn` slot (node + 0x20) holds exactly one RELATIVE
addend equal to the handler address (readelf-verified for all 5).

- `opt/prof` (FDE `0x63737c0..0x6373846`, 134B): read-only byte.
  Value is the prof byte `0x6713606`, read and never written by this
  leaf. Write attempt (newp | newlen nonzero) returns 1. Read with
  oldp + oldlenp: `*oldlenp` == 1 gives `*oldp` = byte, 0; else a
  1-byte copy, `*oldlenp` := (`*oldlenp` != 0), 0x16. Either absent
  gives 0.
- `opt/tcache` (FDE `0x63721c0..0x6372246`, 134B): read-only byte,
  same contract. Value is global byte `0x64ffdf8`, the global
  tcache-enabled default that packet #260's apply-global-default
  stores to ctx+0.
- `config/stats` (FDE `0x6377dc0..0x6377e3e`, 126B): read-only byte,
  same contract. Value is the build-time constant 1 (no global load
  in the handler).
- `thread/allocated` (FDE `0x63749f0..0x6374bfa`, 522B): read-only
  u64. Value is ctx+0x338. Write attempt returns 1. Read with oldp +
  oldlenp: `*oldlenp` == 8 gives `*oldp` = value, 0; else a bounded
  copy of min(`*oldlenp`, 8) from the stack temp (compiler-unrolled
  loop), `*oldlenp` := copied count, 0x16. Either absent gives 0.
- `stats/allocated` (FDE `0x637b190..0x637b440`, 688B): read-only
  u64, same read contract, read under the init mutex `0x67121a0`
  (trylock; contention goes to wait helper `0x63bf680` on record
  base `0x6712160`, contended byte `0x67121c8` := 1, retry;
  counters `0x6712198` +1 every entry, `0x6712188` +1 on ctx change,
  last-ctx `0x6712190`; byte cleared and mutex unlocked on every
  exit path, including the write-refusal path). Value is
  `*(*0x6712138)`.

Previously classified: 28 (packets #257/#258/#259/#260). Classified
here: 5. Remaining unclassified: 171 of 204 leaves. This packet does
not claim exhaustive coverage.

### Bin init: `0x63ec4c0..0x63ec5f4` (full FDE, 308B, 79 strict)

Initializes a bin struct (rsi) under an arena-record mutex. Record
base = rcx+0x28a8: mutex at base+0x40 (rcx+0x28e8), contended byte
at base+0x68 (rcx+0x2910), every-entry counter at base+0x38
(rcx+0x28e0), change counter at base+0x28 (rcx+0x28d0), last-ctx at
base+0x30 (rcx+0x28d8) — the standard record pattern. On entry it
stores the arena pointer to bin+0x28 and self-links bin+0/+8, then
splices bin into the list rooted at slot rcx+0x2898 (insert-after-head,
head preserved when non-empty, set to bin when empty) and splices
bin+0x10 into the second list rooted at slot rcx+0x28a0 with the
same pattern; it stores (rdx+8) to bin+0x20, clears the contended
byte, and tail-jumps to `pthread_mutex_unlock`.

Callers: 27 E8 + 1 E9 across 19 caller FDEs, including 4 E8 in the
enable slow path FDE (0x63ed3fd, 0x63ed50c, 0x63ed5ad, 0x63ed63a)
and 1 E9 tail-jump at 0x63ee02d in FDE 0x63edf10..0x63ee0a0.

### Bin get-or-create: `0x634ebb0..0x634eccd` (full FDE, 285B, 74 strict)

Gets or creates an indexed object from the shared table at `0x65096c0`
(the same table the teardown slots index). Record: mutex `0x6511700`,
record base `0x65116c0` (wait-helper argument), contended byte
`0x6511728` (= base+0x68), every-entry counter `0x65116f8`
(= base+0x38), change counter `0x65116e8` (= base+0x28), last-ctx
`0x65116f0` (= base+0x30) — the standard record pattern. Args: rdi =
ctx (compared against last-ctx), esi = index, rdx = create argument
(passed through to the create call).

- Index > 0xffe: no table access; the object result is 0, and the
  post-unlock tail below still runs.
- Index <= 0xffe: eax = [0x65096b0] (the next-index counter, 8 bytes
  below the table); if the index equals the counter, the counter is
  bumped atomically (`lock addl $0x1`) first. Then r12 =
  [0x65096c0 + index*8]; on a miss (0) the create call `0x6364430`
  (ctx, index, rdx) fills r12.
- After unlocking (contended byte cleared): index 0 returns r12
  directly. Otherwise the tail runs: `0x6367450`(index) nonzero
  returns r12; `0x6368e40`(ctx, index) zero returns r12; otherwise
  a `0x63bf5b6` log call and then `abort`. The callees
  `0x6367450`/`0x6368e40`/`0x63bf5b6` are named only, not decoded.

Callers: 64 E8 + 4 E9, all 68 sites capstone-verified in their
enclosing FDEs, including 3 E8 in the enable slow path FDE
(0x63ed3e1, 0x63ed5e9, 0x63ed723).

Note: the originally assigned second bin callee `0x63d9700` turned
out to be packet #215 lu-miss's own handler FDE (5 exhibited
windows inside it), so it was dropped without fabrication and
substituted with this unclaimed callee; `0x63d9700` must not be
re-attempted as a new packet.

### Interval-value consumer window: `0x63c4316..0x63c43a3` (141B, 26 strict)

Inside the consumer FDE `0x63c41c0..0x63c44d9` (2105B; only this
window is exhibited, the rest characterized below). The window
covers: the prof-byte branch (prof byte `0x6713606` == 0 skips the
rest of init and returns success with flag `0x67123a0` := 1);
`0x6712438` := [0x64ffcf0]; the `0x63ce240` call; snapshots of
prof-state bytes to `0x67125d0` (from [0x64ffcf9]), `0x67124d0`
(from [0x6713605]), `0x6712550` (from [0x64ffcf8] — the same global
packet #260's prof/thread_active_init setter stores to); the
`0x63ccd30` call; then the interval-value read itself:
`0x6712440` loaded to rsi, `0x6712430` := 0, and the call to
`0x63c4bf0` with rdi = counter `0x67125e0` — the interval value
initializes the interval counter. A nonzero result from either
call aborts with return 1.

The rest of the FDE is characterized, not exhibited: an entry
chain of 11 static `0x63bf840` check calls, each taking (global
address, .rodata string, size) with rcx = 0, where any nonzero
result aborts with return 1 (9 in the entry chain, 2 inside
0x70-step loops over 0x1c000 and 0x7000 bytes); the
`0x63d5476`/`0x63d7240` calls; the `0x636b370` allocs feeding
`0x6714500` (0x1c000 bytes) and `0x67144f0` (0x7000 bytes); and the
`0x63d7bb0`/`0x63d7b90` tail calls before the shared success
epilogue (flag `0x67123a0` := 1, return 0). The check helper
`0x63bf840` itself is named only, not decoded.

Sole caller of the consumer: E8 site `0x634f44f` in FDE
`0x634f0b0..0x634f8d5` (packet #257's predicate FDE).

### Teardown-gate body callees (packet #260's characterization confirmed)

Packet #260 characterized the gate body (FDE `0x63ef810..0x63ef8d7`)
as calling these four functions; the census confirms each has
exactly one E8 site, all inside the gate FDE, in address order:

- `0x63c3b70..0x63c3b89` (25B, 7 strict): if ctx+0x68 is zero it
  returns; otherwise it tail-jumps to `0x63cf8c0` with rsi =
  ctx+0x68 (rdi = ctx unchanged). Caller: 0x63ef834.
- `0x63539d0..0x6353a11` (65B, 16 strict): if ctx+0x88 is zero it
  returns; otherwise it indexes the `0x65096c0` table by the
  pointee's +0x13450 field, calls `0x6364420` with (table entry,
  flag 1), then clears ctx+0x88. Caller: 0x63ef83c.
- `0x6353a20..0x6353a61` (65B, 16 strict): the same shape for
  ctx+0x90 with flag 0, then clears ctx+0x90. Caller: 0x63ef844.
- `0x63efd20..0x63efd25` (5B, 2 strict): a no-op stub (endbr64 +
  ret) — that gate step takes no action. Caller: 0x63ef858.

No correction to packet #260's gate-body characterization is
needed; the stub finding is new. (Packet #260's separate
TLS-helper mutex-location refinement was already corrected by the
parent before #260's submission and is not repeated here; this
packet's bin_init record pattern is decoded from its own FDE.)

## Disjointness

Recursive range-only collector over the merged tree plus packets
#183-#260 worktrees, deduplicated by real packet slug,
census/cited-only subtrees excluded (packet #253's rule). The
collector gathers ONLY exhibited windows — string `range` fields,
`[start, end]` lists, `start`/`end` pairs inside `exhibits` lists
or dicts, and `windows` lists (packet #260's lesson) — never
enclosing-`fde` annotation fields (packet #259's lesson). No
overlap with packets #183-#260 or with packet #232's FDE
`0x63b8820..0x63b8d85`. Directory
`RE-001-node115-lu-value-leaves-bin` does not collide with any
merged-tree directory.

## Verification

- `tools/node115_value_leaves_bin.py` exit 0 (byte reads only;
  binary identity, exhibit bytes, strict counts, objdump
  regeneration with the header line stripped, `.rela.dyn` slots,
  named E8/E9 sites by exact byte arithmetic, full-`.text` raw
  E8/E9 census cross-checked at build time against a full capstone
  disassembly of all 135,313 FDEs with identical counts,
  disjointness, MANIFEST hashes).
- `tests/test_node115_value_leaves_bin.py` 10/10 standalone,
  including tamper controls run first: corrupting one exhibit byte
  fails the verifier.
- `make verify` exit 0 (see body for the tally); `make
  catalogue-check` exit 2 with the pre-existing `Stale catalogue:
  README.md` failure on the new base, not a packet regression.
- Full `make test` is not attempted: the new base carries 584 test
  files, a full run takes hours and risks a VM restart mid-run.
  The gates above are the verified final state; no placeholder
  language is used.

## Not covered (explicit)

- The remaining 171 leaves.
- Enable-slow-path bin-setup callees beyond the two decoded here
  (`0x63d9880` first, `0x63ec7a0` with the overlap note above,
  plus `0x6352fc0`, `0x6352f60`, `0x63e91c0`, `0x6365150`),
  named only by packet #260's census. `0x63d9700` is packet
  #215's handler and is not re-attemptable.
- The consumer FDE beyond the exhibited window, and the internals
  of `0x63bf840`, `0x63c4bf0`, `0x6364420`, `0x63cf8c0`, and the
  bin_getcreate tail callees `0x6367450`/`0x6368e40`/`0x63bf5b6`.

## Next question (#262)

Continue leaf classification with the next batch (`opt/prof_prefix`,
`opt/prof_active`, `opt/lg_prof_sample`, `thread/allocatedp`,
`thread/deallocated`); decode the remaining enable-slow-path
bin-setup callees (`0x63d9880` first; `0x63ec7a0`'s FDE overlaps a
lu-wait-callers window at `0x63ec890..0x63ec8a3`, so claim only
unclaimed bytes; `0x63d9700` is packet #215's handler and must not
be re-attempted); decode the consumer check helper `0x63bf840`.
