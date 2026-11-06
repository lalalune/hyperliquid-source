# RE-001-node115-lu-leaf-write-next: lu leaf write classification and the prof-byte writers

- Component ID: RE-001-node115-lu-leaf-write-next
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes, `artifacts/node/115/hl-node`)
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (decoded disassembly, census, rel32 targets,
  `.rela.dyn` addends, `.rodata` strings). No execution, no values from
  `.bss`, no behaviour beyond what the code proves.
- Scope included and excluded: included — 9 leaf handlers, TLS helper
  `0x63ef640` core, `0x63eec10`, `0x63ed870`, prof / prof_leak_error
  option-parser windows. Excluded — the remaining 181 leaves,
  `0x63ef5e0`/`0x63ef410` internals, the `0x6712440` writer census,
  `0x63ed090`/`0x63ed070` internals, the rest of the option-parser FDE.

## Reproduce

Worktree `hl-wt-calls259-115`, branch `codex/re-004-calls259-115`
(from upstream main `05bc2de30`). Static analysis only; the binary
was never executed. Coordinate conversion: `.text` file offset =
VA - 0x1000; `.rodata` VA as-is; `.rela.dyn` addends for GOT slots.
FDE bounds confirmed with a `.eh_frame` parser (CIE augmentation zR,
sdata4 encoding 0x1b), not by endbr64 scanning. Instruction counts are
strict mnemonic lines (address + bytes field + tab + mnemonic;
objdump byte-continuation lines excluded) and match across README,
records.json, and the PR body. `.hex` exhibit files contain raw binary
bytes (packet #255 format), not hex text.

Commands (from the worktree root):
`objdump -d --start-address=<hex> --stop-address=<hex>
artifacts/node/115/hl-node` for each exhibit;
`python3 tools/node115_leaf_write_next.py` (exit 0);
`python3 -m unittest tests.test_node115_leaf_write_next -v` (10/10);
`make verify` (exit 0); `make catalogue-check` (pre-existing failure,
see below).

## Evidence

Leaf handlers are reached only by dispatcher indirect tail-call:
whole-`.text` raw E8/E9 census gives 0 direct entries for all 9
handlers, matching packets #257/#258. Each leaf's `.rela.dyn` slot
(node + 0x20) holds exactly one RELATIVE addend equal to the handler
address (verified via readelf for all 9).

Leaf decodes (all VAs; read = oldp/oldlenp path, write = newp/newlen
path, return codes as decoded):

- `experimental/arenas_create_ext` (FDE `0x63a56b0..0x63a594f`,
  head `0x63a56b0..0x63a5763`): init mutex `0x67121a0` trylock
  (contention -> wait helper `0x63bf680`, record mutex - 0x40,
  byte `0x67121c8` = 1, retry); counters `0x6712198` +1, ctx change ->
  `0x6712188` +1 and last-ctx `0x6712190`; 16B template at `0x64da4b0`
  replaceable into newp; create call `0x63a5550`; -1 -> 11; success ->
  oldp/oldlenp gate (`*oldlenp` == 4 else `*oldlenp` := 0, then 22;
  oldlenp NULL subcase dereferences rbx, stated as a precondition
  only, not a defect) then `*oldp` = new index, 0, byte clear, unlock.
  Bounded-copy tail after creation (`*oldlenp` != 4) updates
  `*oldlenp` by the copied amount, then 22.
- `thread/tcache/enabled` (full FDE): ctx+0 byte is the current value.
  Write: newlen must be 1 else 22; change -> enable slow path
  `0x63ed090` / disable slow path `0x63ed070`, then store + call
  `0x63ef5e0`; unchanged value still stores + calls `0x63ef5e0`.
  Read: both oldp and oldlenp present -> `*oldlenp` == 1 gives
  `*oldp` = value, 0; else 1-byte copy, `*oldlenp` := 1, 22; either
  absent -> 0.
- `thread/prof/name` (FDE `0x636df60..0x636e202`, core
  `0x636df60..0x636e034`): prof byte 0 -> whole leaf returns 2.
  Read: oldp + oldlenp present, newp and newlen both 0 -> getter
  `0x63c3c90`; `*oldlenp` == 8 gives `*oldp` = pointer, 0; else
  bounded-copy tail (`*oldlenp` updated, 22). Read + write together
  -> 1. Write alone: newlen must be 8 else 22; `*newp` passed to
  setter `0x63c3d50` by tail jump. No oldp/oldlenp and no newp ->
  getter called, result discarded, 0.
- `experimental/hooks/prof_backtrace` (FDE `0x636d3a0..0x636d5eb`,
  head `0x636d3a0..0x636d427`): neither oldp nor oldlenp -> 22.
  Read: getter `0x63c40f0`; `*oldlenp` == 8 gives `*oldp` = pointer;
  else copy tail then 22. Write: prof byte 0 -> 2; newlen must be 8
  else 22; `*newp` 0 -> 22; setter `0x63c40e0` then 0.
- `experimental/hooks/prof_dump` (FDE `0x636d160..0x636d398`,
  head `0x636d160..0x636d1f9`): same shape as backtrace; getter
  `0x63c4110`, setter `0x63c4100`; copy tail ends at `0x636d366`
  (`*oldlenp` := copied amount, jump to `0x636d1cb`, eax = 22).
- `experimental/hooks/safety_check_abort` (full FDE, 67B): pure
  action, no read path. oldp | oldlenp nonzero -> 1; no newp -> 0
  (no-op); newlen must be 8 else 22; `*newp` passed to `0x63d9a70`,
  then 0.
- `prof/active` (full FDE): write: newlen must be 1 else 22; prof
  byte 0 -> new byte 0 falls to the read path (0), nonzero -> 2;
  prof byte nonzero -> setter `0x63c3c10` (new byte) then read path.
  Read alone: prof byte 0 -> value 0; nonzero -> getter `0x63c3b90`
  byte; `*oldlenp` == 1 gives `*oldp` = byte, 0; else copy,
  `*oldlenp` updated, 22. This leaf reads the prof byte but never
  writes it; it differs from packet #258's `thread.prof.active`.
- `prof/gdump` (full FDE): write: prof byte 0 -> 2; newlen must be 1
  else 22; `*newp` byte passed to `0x63c4060`. Read: oldp + oldlenp
  present, `*oldlenp` == 1 gives stored byte, 0; else 1-byte copy,
  `*oldlenp` := 1, 22. No newp: prof byte 0 -> 0; nonzero -> getter
  `0x63c3fe0` then the same read path.
- `prof/interval` (FDE `0x63767f0..0x6376a07`, head
  `0x63767f0..0x637683a`): READ-ONLY. newp | newlen nonzero -> 1
  (write refused). Read: global `0x6712440` 8B value returned via
  oldp; `*oldlenp` == 8 -> 0; else min(`*oldlenp`, 8) copy,
  `*oldlenp` := copied amount, 22. Either oldp or oldlenp absent -> 0.
  The writer census for `0x6712440` is NOT done here (next question).

TLS helper `0x63ef640` (FDE `0x63ef640..0x63ef808`, core
`0x63ef640..0x63ef7b6`): mode = 2nd argument (esi), state = ctx+0x330.
State > 2: store mode; mode > 2 -> call `0x63eec10`, then tail-call
`0x63eec10`; mode <= 2 -> call `0x63ef410`, then tail-call
`0x63eec10`. State <= 2, mode > 2: global mutex `0x67288e0` trylock
(contention -> wait helper `0x63bf680`, record mutex - 0x40, byte
`0x6728908` = 1, retry); counters `0x67288d8` +1, ctx change ->
`0x67288c8` +1 and last `0x67288d0`; ctx spliced out of the
doubly-linked list (0xc8/0xd0 links, `0x6728910` slot); contended
byte cleared, unlock; store mode; tail-call `0x63eec10`.
State <= 2, mode <= 2: spin/wait loop; exits to the xchg path when
state > 2, gate neighbour `0x64ffab0` != 0, ctx+0 != 0, or ctx+1 > 0;
the xchg path atomically exchanges global `0x6728880` != 0 into the
new state; if the pre-exchange state was not 2, call `0x63eec10`
and tail-call it to exit; if it was 2, loop again. Packet #258's
calling modes map: 5 and 3 take the mutex path (when state <= 2),
0 takes the spin path (when state <= 2). The contention path
(`0x63ef7b6..0x63ef7e0`) and unlink path (`0x63ef7e0..0x63ef808`)
are characterized, not exhibited.

`0x63eec10` (full FDE, 97B): state == 0 on entry -> clamp ctx+0x10
and ctx+0x20 to 0 when >= -4095 (0xfffffffffffff001), store to
ctx+0x340/+0x350, `lock orq $0,(%rsp)` barrier, re-check state:
0 -> return, else zero 0x340/0x350 and return. State != 0 on entry
-> zero 0x340/0x350 immediately and return.

`0x63ed870` (full FDE, 52B): store global byte `0x64ffdf8` to ctx+0,
call `0x63ef5e0`, and if the global is still nonzero call enable
slow path `0x63ed090`, return 0.

Option parser (FDE `0x6349be0..0x634eb7c`; `.rodata` VA as-is):
`"prof"` at `0x4343e3`, `"true"` at `0x43f883`, `"false"` at
`0x430e89`, `"prof_leak_error"` at `0x44c4aa`. Name length 4 +
strncmp -> `"prof"`; value length 4 -> `"true"` strncmp (fall-through
to the SET store, cited from packet #258, range
`0x634d08c..0x634d09d`); value length 5 -> `"false"` strncmp
(fall-through to the CLEAR store, cited, `0x634c035..0x634c047`).
`"prof_leak_error"` length 15 + strncmp; value `"true"` -> neighbour
byte `0x6713602` := 1 (exhibited `0x634e5b0..0x634e5e3`); value
`"false"` -> `0x6713602` := 0 (exhibited `0x634d0a8..0x634d0ef`).
When init-done flag `0x651174b` is nonzero, both cases log via
format `<jemalloc>: -- Set conf value: %.*s:%.*s\n` at `0x967c70`
through call `0x63bf5b6` — indirect evidence this is the jemalloc
mallctl option path. Packet #258's latch `0x63c4140..0x63c41b1`
also sets the prof byte (cited, not claimed).

Self-correction note: the draft census first attributed the
`0x63ef625` E9 site to the TLS slow path; the `.eh_frame` enclosing
FDE check showed it belongs to `0x63ef5e0`'s FDE instead, so
`0x63ef5e0` tail-calls `0x63eec10` — the narrative was corrected
to the census, per packet #256's lesson.

## Implementation and comparison

Not yet implemented/measured. No Rust path is claimed; this packet is
evidence only (leaf classification + helper/option decoding).

## Results and limitations

- 17 exhibits, 2283 bytes, 582 strict lines; verifier exit 0; unit
  tests 10/10 standalone; tamper control fails the verifier as required.
- `make verify` exit 0. `make catalogue-check` fails with
  `Stale catalogue: README.md`, pre-existing on a pristine checkout
  of the new base; not a packet regression.
- Full `make test` not attempted (584 files, hours, VM-restart risk);
  the PR body states the partial gate honestly and uses no
  placeholder language.
- Disjointness: no overlap with packets #183-#258 (recursive
  range+fde collector, merged tree + #255-#258 worktrees, dedup by
  real packet slug, census/cited-only subtrees excluded). Claimed
  ranges adjoin packet #258's prof-byte stores without overlapping.
- Unresolved: 181 leaves unclassified; `0x63ef5e0`/`0x63ef410`
  internals; `0x6712440` writer census; `0x63ed090`/`0x63ed070`
  internals; the rest of the option-parser FDE.
- No gate is requested beyond the packet's own verifier and tests.
  Next question: continue leaf classification (181 remain); decode
  `0x63ef5e0` and `0x63ef410`; census the writers of `0x6712440`;
  decode the `0x63ed090`/`0x63ed070` slow paths.
