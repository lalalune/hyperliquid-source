# RE-001-node115-lu-leaf-write-class

## Question

Packet #257's next question: classify the remaining control-tree leaves by
read/write behaviour, decode the TLS-byte slow path and the predicate's
completion tail-call, and find the writers of the prof-gating byte `0x6713606`.

## Answer (short)

- **The tree is not read-only.** All eight candidate leaves are genuine
  write (or read/write) leaves: `arenas.create`, `tcache.create`,
  `tcache.destroy`, `experimental.hooks.install`, `experimental.hooks.remove`,
  `prof.log_start`, `prof.log_stop`, and `thread.prof.active`.
- **The prof-gating byte `0x6713606` has exactly three writers**, found by a
  full-`.text` census: a CLEAR (`movb $0`) and a SET (`movb $1`) inside the
  option-parser function `0x6349be0..0x634eb7c`, and a SET inside the latch
  `0x63c4140..0x63c41b1`. No `.rela.dyn` addend equals `0x6713606`.
- **The TLS slow path `0x63ef8e0..0x63efba2` is a state machine** on the byte
  at context + `0x330`: states 2 (xchg spin loop), 3, 4, and 6 have distinct
  paths; other values return the context unchanged.
- **The predicate's completion tail-call target `0x6368e40..0x6368ebb`** is a
  mutex-guarded work wrapper (counters, last-context slot, contended byte);
  it does not itself write the gate flag `0x64ffab4` — #257's predicate
  writes the flag before tail-calling here.
- **The eight leaf handlers have zero direct E8/E9 call sites** — reachable
  only through the dispatcher's indirect tail-call, like #257's five.

## Scope honesty

- Surveyed: the full leaf table from #257's records (246 nodes, 204 leaves).
- Decoded here: 8 leaves (listed above) + TLS slow path + completion wrapper
  + prof-byte writers.
- Classified before (#257, cited not claimed): `epoch`, `thread.tcache.flush`,
  `thread.peak.reset`, `prof.reset`, `prof.dump`, `stats.mutexes.reset`.
- NOT covered: ~190 leaves remain unclassified (see `records.json`); the
  internals of `0x63ef640` (TLS state-transition helper, modes 0/3/5),
  `0x63eec10`, and `0x63ed870`; the option-parser FDE `0x6349be0..0x634eb7c`
  beyond the two store windows; the post-call bounded-copy tails where entry
  gates already enforce exact lengths; the shared-tail jump target `0x63ef8d7`
  beyond its observed `call abort` bytes.
- No defect is fabricated. All eight candidates turned out to be writes; a
  read-only result would have been reported the same way.

## Findings in detail

### Leaf contracts (handler arg convention: `%rdi` = context, `%rcx` = oldp,
`%r8` = oldlenp, `%r9` = newp, stack = newlen; error codes as raw numbers)

| Leaf | Handler FDE | Contract |
|---|---|---|
| arenas.create | `0x63a5950..0x63a5bef` | oldp+oldlenp present and `*oldlenp == 4`, else `*oldlenp := 0` and return 22; newp present requires newlen 8; creates an arena from a 16B template; result −1 → 11; success → `*oldp` = new index, 0 |
| tcache.create | `0x6377950..0x6377b5d` | newp or newlen nonzero → 1; oldp/oldlenp missing or `*oldlenp != 4` → `*oldlenp := 0`, 22; create failure → 14; success → `*oldp` = id, 0 |
| tcache.destroy | `0x63778b0..0x63778f6` | oldp\|oldlenp nonzero → 1; newp zero → 22; newlen must be 4; destroys tcache `*newp`; 0 |
| experimental.hooks.install | `0x636d5f0..0x636d863` | newp nonzero, newlen 32 (4 pointers), oldlenp+oldp nonzero, else 22; install result 0 → 11; success → `*oldp` = hook pointer, 0 |
| experimental.hooks.remove | `0x6376d50..0x6376d9e` | oldp\|oldlenp nonzero → 1; newp zero → 22; newlen must be 8; `*newp` nonzero, else 22; removes hook `*newp`; 0 |
| prof.log_start | `0x63777f0..0x6377841` | prof byte 0 → 2; oldp\|oldlenp nonzero → 1; newp optional (newlen 8 if present); boolean result → 0 or 14 |
| prof.log_stop | `0x63777c0..0x63777ee` | prof byte 0 → 2; otherwise boolean result → 0 or 14; ignores all value arguments |
| thread.prof.active | `0x636de60..0x636df5e` | snapshot: prof byte 0 → 0, else low byte of `0x63c3d70` (ctx); write path: prof byte 0 → 2, newlen must be 1, nonzero result → 11; read path: `*oldlenp == 1` → `*oldp` = byte, 0; else copy + `*oldlenp := 1`, 22; missing oldp/oldlenp → 0 |

`thread.prof.active` READS `0x6713606` but does not write it; the state
change goes through `0x63c3e20`.

### TLS slow path `0x63ef8e0..0x63efba2` (state byte at ctx + `0x330`)

- Other values (0, 1, 5, 7+) and value 3 with flag nonzero: return ctx.
- Value 4 → install path: `0x63ef640` (ctx, 5); copy 2,632 bytes to the TLS
  slot if needed; `pthread_setspecific`; on success init + return ctx.
- Value 6 with flag nonzero: `0x63ef640` (ctx, 3), then the value-4 path.
- Value 6 without flag: `0x63ef640` (ctx, 0), then the value-2-style loop,
  copy + setspecific, then the shared init sequence + `0x63ed870`.
- Value 3 without flag: `0x63ef640` (ctx, 0); decrement ctx + 1; value-2-style
  loop; `0x63eec10` + init sequence + `0x63ed870`.
- Value 2: xchg spin loop; gates are byte ≤ 2, gate-neighbour byte
  `0x64ffab0` == 0, ctx + 0 nonzero, ctx + 1 ≤ 0; otherwise `0x63eec10` and
  return ctx.

`0x63ef640`'s second argument is a mode (5 / 3 / 0). What it does internally
is NOT decoded — next-question material.

### Completion wrapper `0x6368e40..0x6368ebb`

Mutex `0x6711b00` (trylock; contention → #251 wait helper `0x63bf680`,
record base `0x6711ac0`, contended byte `0x6711b28`); counter `0x6711af8`
+= 1; if ctx differs from last-ctx slot `0x6711af0`, counter `0x6711ae8`
+= 1 and slot := ctx; calls work function `0x6367b20` (ctx, saved `%esi`);
clears contended byte; unlocks; returns the work result.

### Prof-byte writers (`0x6713606`)

- `0x634c035` `movb $0x0,(%r8)` (CLEAR), FDE `0x6349be0..0x634eb7c`.
- `0x634d08c` `movb $0x1,(%rbx)` (SET), same FDE.
- `0x63c41a0` `movb $0x1,0x6713606` (SET, direct), FDE `0x63c4140..0x63c41b1`
  (also writes neighbour `0x6713605` = 0).

Census method: full-`.text` objdump grep for `# 6713606` (76 sites); each
lea site classified by a 256-byte linear window with register-overwrite and
call-clobber tracking. Limitation: a store through a spilled/reloaded
register, or beyond the window, would be missed; all three writers sit
within 8 bytes of their lea, the normal compiler shape for a `.bss` byte
store. Self-correction: the first classifier checked only the first deref
after each lea and produced 6 false-positive writes from register reuse
(`0x635a874`, `0x635c781`, and four more); overwrite tracking fixed it and
both examples were confirmed false by hand.

## Exhibits (raw binary bytes, not hex text; 1361B, 365 strict instructions)

| File | Range | Bytes | Strict |
|---|---|---|---|
| arenas_create_head | `0x63a5950..0x63a5a05` | 181 | 43 |
| tcache_create_head | `0x6377950..0x6377a04` | 180 | 52 |
| tcache_destroy | `0x63778b0..0x63778f6` | 70 | 20 |
| hooks_install_head | `0x636d5f0..0x636d674` | 132 | 34 |
| hooks_remove | `0x6376d50..0x6376d9e` | 78 | 23 |
| log_start | `0x63777f0..0x6377841` | 81 | 24 |
| log_stop | `0x63777c0..0x63777ee` | 46 | 14 |
| prof_active_head | `0x636de60..0x636df06` | 166 | 48 |
| tls_dispatch | `0x63ef8e0..0x63ef92e` | 78 | 21 |
| tls_install | `0x63efa50..0x63efa9e` | 78 | 18 |
| completion | `0x6368e40..0x6368ebb` | 123 | 33 |
| profbyte_clear | `0x634c035..0x634c047` | 18 | 3 |
| profbyte_set | `0x634d08c..0x634d09d` | 17 | 3 |
| profbyte_latch | `0x63c4140..0x63c41b1` | 113 | 29 |

Head windows end at instruction boundaries; the tails they omit are
characterised in EVIDENCE.md, not claimed as exhibited.

## Census

- Direct E8/E9 sites: all 8 leaf handlers 0 + 0; TLS slow path 145 + 1 (the
  E9 site is `0x63efc17`, in the following FDE); completion 5 + 1 (the E9
  site `0x634f751` is inside the predicate — consistent with #257).
- Address-taken scan (RIP-relative comments and `movabs` immediates): 0 hits
  for all 8 handlers.
- `.rela.dyn`: each handler has exactly 1 RELATIVE entry, at its leaf node's
  +`0x20` handler field.
- Disjointness: claimed ranges checked against the merged tree plus prior
  worktree records with a recursive range+fde collector, deduplicated by
  real path, census/cited-only subtrees excluded (see verifier output for
  the scanned-range count); 0 overlaps.

## Verification

- `tools/node115_leaf_write_class.py`: static byte checks only (binary
  size + SHA-256, exhibit bytes, strict counts, objdump regeneration with
  header stripped, rel32 call targets, prof-byte writer bytes, E8/E9 census,
  rela slots, disjointness, MANIFEST hashes).
- `tests/test_node115_leaf_write_class.py`: 10 tests, including a tamper
  control (corrupted exhibit byte must fail the verifier).
- Full `make test` was NOT attempted: the new base carries 584 test files
  and a full run takes hours with VM-restart risk (see packet body).
- `make catalogue-check` on the new base fails pre-existing with
  `Stale catalogue: README.md` on a pristine checkout; not a packet
  regression (reported honestly in the PR body).

## Next question (for #259)

Continue per-leaf classification for the remaining ~190 leaves (next
candidates: `experimental/arenas_create_ext`, `thread/tcache/enabled`,
`thread/prof/name`, the `experimental/hooks` siblings, `prof.active`,
`prof.gdump`, `prof.interval`); decode `0x63ef640` (modes 0/3/5) and
`0x63eec10`/`0x63ed870`; decode the option-parser FDE `0x6349be0..0x634eb7c`
(which option names set vs clear the prof byte).
