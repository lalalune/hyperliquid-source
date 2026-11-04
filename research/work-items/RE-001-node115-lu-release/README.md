# RE-001-node115-lu-release: the node #115 release function

This packet answers packet #210's explicitly stated next question:
decode the release function `0x63b3080` end to end: what does it
do with (thread, ref, pool, node, page-aligned size), and what
happens to the node afterwards — is it freed, recycled, or
handed on?

## Answer in one line

The size argument is dead, the node is dispatched through a
pool-object vtable (or default direct calls), and it is always
handed on — the function has no `ret` instruction at all, and
every exit is a tail jump to `0x63b38d0` or `0x63b5760`.

## What it shows

1. **Signature and frame.** FDE `0x63b3080..0x63b38c2`
   (2114B): (thread, ref, pool, node, size) = (rdi, rsi, rdx,
   rcx, r8). It saves thread, ref, pool, node on a `0x38`
   stack frame. An objdump scan of the whole FDE finds zero
   `ret` instructions: the only exits are the tail jumps at
   `0x63b3111` (to `0x63b38d0`) and `0x63b31f4` (to
   `0x63b5760`). Release never frees, zeroes, or returns
   the node itself.

2. **The size argument is dead.** Incoming r8 is never read
   on any path before being overwritten: the tail path sets
   r8 = node, the main path sets r8 = [node], the bit-13
   path recomputes r8 = [node+0x10] & ~0xfff, and the
   retry path zeroes r8. Every size release needs is
   re-derived from the node itself: [node+8] & ~0xfff and
   [node+0x10] & ~0xfff. The walk's page-aligned size
   argument is passed but ignored — a dead argument, stated
   as a control-flow fact, not a defect claim.

3. **Gate 1: which pool object.** Pool-obj = [pool+8] is
   compared against the `.data.rel.ro` address `0x64df1a0`
   (the default object). Equal selects the default arm:
   if the `.data` byte `0x64ffc28` is set, the flag path
   runs; else node[0] bit 16 (`0x10000`) selects the
   `0x63b6ad0(thread, pool, node, 1, 1)` call before the
   main path. Not equal and [pool-obj+8] == 0 also runs
   the flag path directly. Otherwise the main path opens
   with the setup call `0x63ae980(thread, [ref+0xe410],
   node)`.

4. **Flag normalization.** Node[0] bit 13 (`0x2000`) set
   routes to the internal predicate `0x63b2e60(thread,
   pool, node, 0, aligned size)` (see point 6). Bit 13
   clear normalizes the flag word: clear bit 15, then set
   bit 15 iff r9 = `0x8000` (normal arrivals) or leave it
   cleared (r9 = 0 fallback arrivals), store node[0], and
   then: if the `.bss` byte `0x6713606` is clear, tail
   out; else if the `0xe0000` field is zero, subtract
   pages ([node+0x10] >> 12) from the global counter
   `0x67121d8` first, then tail out; else tail out.

5. **Three pool-method slots.** Each slot is null-checked
   and each call is wrapped in the same thread gating: a
   depth byte at thread+1 (incremented before, decremented
   after; hitting zero routes through the `0x63ef5e0`
   helper before rejoining) and a thread-state byte at
   thread+`0x330` (nonzero routes through the
   `0x63ef5e0`/`0x63ef8e0` helpers first); thread == 0
   uses a `%fs` thread-record variant that rejoins the
   same path. The helpers' internals are not decoded here.
   - Slot +8 (main path): (pool-obj, aligned [node+8],
     aligned [node+0x10], node[0] bit 13, [pool]).
     Result 0 tails to `0x63b5760`; nonzero runs the
     retry path (point 6).
   - Slot +0x30 (predicate-nonzero path): (pool-obj,
     aligned8, aligned10, 0, [pool]). Result nonzero
     selects the r9 = 0 flag path; zero selects the
     r9 = `0x8000` flag path.
   - Slot +0x28 (fallback path, when the flag word's
     `0xe0000` field != `0x40000`): (pool-obj, aligned8,
     aligned10, 0, [pool]); both outcomes rejoin the
     r9 = 0 flag path.
   When the pool object is the default (`0x64df1a0`),
   direct calls replace the slots: `0x63ad9a0` for
   slot +8 (same result protocol), `0x63ada80` for
   slot +0x30, `0x63ada60` for slot +0x28.

6. **Retry path and global accounting.** The retry call
   is `0x63ae2b0(thread, [ref+0xe410], node, 0xe8, 0)`.
   Nonzero returns to the flag path. Zero runs the
   accounting: pages = [node+0x10] >> 12, `lock xadd`
   to the `.bss` total `0x67121d8`, a `lock cmpxchg`
   high-water update on `.bss` `0x67121d0`, and — if the
   `.bss` byte `0x67124d0` is set — a `0x63c3730(thread)`
   call, then the flag path. The same `0x63ae2b0`
   `0xe8` call also opens the second release-entry
   wrapper `0x63b3b20` (see census).

7. **The two tail destinations (characterised, not fully
   decoded).** `0x63b38d0` (545B) trylocks the dest
   (ref+`0x9818`)+`0x40` mutex, bumps the dest's
   +`0x38`/`0x28` counters with owner tracking, tests
   node[0] bit 16, and on one path unlocks and re-enters
   release — so a release → hand-on → release cycle is
   possible. `0x63b5760` (129B) trylocks the
   [ref+`0xe418`]+`0x58` mutex, bumps counters, passes
   the node to `0x63aa7d0`, whose head zeroes node+`0x28`
   and node+`0x38` and begins a sorted list walk — the
   node enters a list. Neither destination frees the node
   inside release; the node's final disposition past
   `0x63aa7d0`/`0x63b38d0` is not decided here.

8. **Census (whole `.text`, byte scan + per-site
   disassembly check; `.rela.dyn` for GOT).** Release
   `0x63b3080`: 3 direct E8, 1 E9, 0 LEA, 0 GOT — E8
   `0x63b3a92` (inside `0x63b38d0`, the re-entry call),
   E8 `0x63c0e84` (wrapper `0x63c0dd0`: pool resolved
   via `0x636b340([ref+0xe408])` first, `0x63b42e0`
   tried, release on its nonzero return), E8
   `0x63c1194` (#210's walk), E9 `0x63b3b80`
   (wrapper `0x63b3b20`: `0x63ae2b0` `0xe8` retry first,
   then tail to release). `.rela.dyn` (60,723 entries)
   has no addend equal to the target.

## Corrections to earlier packets

None that change a verdict. #210 confirmed in full: the
walk release-call site `0x63c1194`, the (thread, ref,
pool, node, size) call shape, and the repurpose probe
`0x63b3c00` as a walk-side call. #210 extended once:
the size argument is passed by the walk but dead inside
release (point 2). Disambiguation, not a correction:
release-internal `0x63b2e60` is NOT #210's walk probe
`0x63b3c00` — different functions, different call
sites. #209's worker/callee shapes and #204's C layout
are untouched.

## Exhibits (5, 173B, 49 strict mnemonics)

- `rel_head.hex` — `0x63b3080..0x63b30b2` (50B/16):
  prologue, arg saves, pool-obj load, sentinel compare.
- `rel_flag.hex` — `0x63b30c7..0x63b30e3` (28B/7):
  flag normalize core (r9 = `0x8000`, bit-13 test,
  bit-15 clear/set, store).
- `rel_vcall.hex` — `0x63b31a9..0x63b31c8` (31B/7):
  thread-state gate + slot-+8 virtual call + result.
- `rel_retry.hex` — `0x63b3250..0x63b326a` (26B/6):
  retry call `0x63ae2b0` with code `0xe8`.
- `rel_tail.hex` — `0x63b30f0..0x63b3116` (38B/13):
  hand-on tail call to `0x63b38d0` (ref+`0x9818`,
  node). Claims outside the excerpts (slots +0x28/+0x30,
  predicate call, setup call, sentinel direct calls,
  global counters, TLS variants, census sites, tail
  jump to `0x63b5760`) are covered by exact key-byte
  checks in the verifier/tests and marked address-cited
  in EVIDENCE.md.

## Unresolved (stated, not inferred)

- Internals of the predicate `0x63b2e60`, the setup
  call `0x63ae980`, the retry call `0x63ae2b0`, the
  thread helpers `0x63ef5e0`/`0x63ef8e0`, the
  high-water call `0x63c3730`, the default direct
  calls `0x63ad9a0`/`0x63ada60`/`0x63ada80`, and the
  wrapper helpers `0x63b42e0`/`0x63c1c40`.
- Full bodies of the tail destinations `0x63b38d0`
  and `0x63b5760`/`0x63aa7d0`, and the node's final
  disposition past them.
- Writers and meanings of the `.bss` bytes `0x6713606`
  and `0x67124d0`, the `.data` byte `0x64ffc28`, and
  the `.data.rel.ro` default object at `0x64df1a0`.
- Everything in #210's behind list: repurpose pair
  `0x63b3c00`/`0x63b3b00`, selector's `0x63b1b60` and
  `0x63b0560`, compute callee `0x63a9750` in full,
  C-`0x80` divisor source, entry+8 condvar waiters,
  runtime method pointees, drain helper `0x51e8720`,
  field-drop callees, #200 delegates and unwind callee.
