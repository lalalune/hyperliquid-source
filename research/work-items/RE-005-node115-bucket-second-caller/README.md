# RE-005 node 115 — the bucket body's second caller: a standalone removal that consumes the entry

Open edge of `RE-005-node115-insert-return` (#2651),
"Precise negatives and boundaries":

> "The bucket body `0x5ce29a0`'s second direct caller
> at `0x5ceb06e` and the poll-side conditions under
> which entries are unlinked or bucket-inserted before
> the setter's flag test are not censused here."

This packet censuses that second caller. The call at
`0x5ceb06e` does not belong to the setter's pre-flag
phase at all: it sits in a separate 468-byte body,
`0x5ceafd0..0x5ceb1a4`, that takes the wheel lock
itself, removes the same `&[S+0x20]` entry under the
same gating as the setter's pre-flag call, and then
consumes the entry in place — fired byte cleared,
value slot set to −1, wake pair claimed. The body has
no direct callers anywhere in `.text`; the only
reference to its start in the artifact is one
`R_X86_64_RELATIVE` addend at `0x64dfe40`, a
code-pointer table slot in `.data.rel.ro` (the
predicate-chain packet's slot census already lists
that slot's value; the body behind it was never
opened). The shared bucket body only unlinks, which
also settles the predicate-chain packet's "unlinks or
bucket-inserts" hedge: neither caller inserts into a
bucket.

Both bodies are exported in full (`*.objdump.txt`);
digests, FDE extents, slot resolutions, strings, panic
Location statics, store censuses, the complete
direct-caller census of the bucket body, the reference
census of the second caller and instruction-byte pins
are re-derived from the artifact by
`tools/bucket_second_caller_static.py`.

## The second caller

`0x5ceafd0(rdi = C)`, where `C = &[S+0x10]` for the
same `S` the predicate-chain builder fills: handle
`[C+0x8]` (= `[S+0x18]`), selector byte `[C+0x0]`
(= `[S+0x10]`, offset `0x160` if non-zero else
`0x240`), entry `&[C+0x10]` = `&[S+0x20]`, wheel at
`handle + sel + 0x50`.

- **Timers guard.** If dword `[handle+sel+0x90]` is
  `1000000000`, the body traps through slot
  `0x64df770` (`0x1680bd0`) with the 115-byte
  timers-disabled message at `0x94ca6b` and the
  `entry.rs` Location static `0x64c6158` (line 549,
  col 30) — before any lock.
- **Lock.** Byte-lock `lock cmpxchg [wheel+0x0], 1`
  at `0x5ceb00a`; contention waits via slot
  `0x64e01f8` (`0x5bb59d0`) with a `1000000000`
  timeout and re-reads the value slot.
- **Unlink phase.** If the value slot `[entry+0x18]`
  is −1, nothing is unlinked. Else if `[entry+0x10]`
  is −1, the entry is spliced out inline
  (`0x5ceb075..0x5ceb119`) from the wheel list
  (`[wheel+0x18]` head, `[wheel+0x20]` tail) — the
  same arm the setter has at `0x5cea840`. Else the
  level is computed with the setter's formula
  (`((bsr(([entry+0x10] xor [wheel+0x10]) | 0x3f) ^ 1)
  * 0x2b) >> 8`, pre-bsr clamp `0xffffffffe`); a
  bsr-derived index above `0x23` traps at `0x5ceb168`
  through slot `0x64df620` (`0x1680cbf`) with the
  `wheel/mod.rs` Location static `0x64c6a48` (line
  130, col 17) — the same static the setter's level
  trap uses. In range, `rdi = [wheel+0x8] + level *
  0x410`, `rsi = entry`, call at `0x5ceb06e`.
- **Consume phase.** With the value slot still set:
  byte `[S+0x58] := 0` (the fired byte the setter's
  due arm also clears), `[S+0x38] := -1`,
  `[S+0x50] |= 2` by `lock cmpxchg`; the wake pair
  `[S+0x40]`/`[S+0x48]` is taken only when the old
  state word was 0, and a non-null taken head is
  invoked through `[head+0x18]` with the taken
  argument — a plain call, where the setter's shared
  tail tail-calls `[head+0x8]`. Exactly five stores
  through `r14 = C` (censused in records).
- **Unlock.** `lock cmpxchg [wheel+0x0], 0` at
  `0x5ceb106`; contention takes the release tail
  through slot `0x64e0f38` (`0x5bb5650`). The landing
  pad at `0x5ceb17c` repeats the unlock before
  `_Unwind_Resume`.

## The bucket body, as both callers use it

`0x5ce29a0(rdi = bucket, rsi = entry)` removes the
entry from its level-bucket slot list: shift
`6 * [bucket+0x400]` (overflow traps via slot
`0x64df870`, `level.rs` Location `0x64c5900` 173:19;
shift ≥ `0x40` via slot `0x64e0820`, Location
`0x64c5918` 173:6), slot index
`([entry+0x10] >> shift) & 0x3f`, slot
`bucket + index * 16` with {head +0x0, tail +0x8}.
Prev/next/head/tail are spliced, the entry's link
pair is zeroed, and when the slot empties the
occupancy bit is toggled off at `[bucket+0x408]`
(`0x5ce2a31`); a null head with a non-null tail
panic-formats through slot `0x64df730` (`0x1680e60`)
with the 37-byte `assertion failed:
self.tail.is_none()` message at `0x94cb3f` and the
`linked_list.rs` Location static `0x64c5930` (line
188, col 9). Complete store census: six stores. The
return value is ignored by both callers.

## Same and different vs the setter's call

Same: the entry object; the value-slot gate; the
`[entry+0x10] == −1` inline wheel-list arm; the level
formula, clamp and trap static; the argument shape;
the ignored return. Different: (1) the setter calls
already holding the lock, as a pre-flag preliminary
inside an operation that goes on to test
`[wheel+0x30]`, store a new value and call the
insert body; the second caller locks itself and
removal-plus-consumption is its whole operation.
(2) The setter receives wheel and entry as separate
arguments; the second caller receives a self pointer
at `&[S+0x10]` and derives handle, selector and
wheel. (3) Only the second caller performs the
`entry.rs` 549:30 timers guard. (4) After the call
the setter falls through to its flag test; the
second caller consumes the entry.

## Precise negatives and boundaries

- A whole-`.text` scan finds exactly two direct
  call sites of `0x5ce29a0` — `0x5cea839` (setter)
  and `0x5ceb06e` — no jumps, no rip-relative
  references, and no `R_X86_64_RELATIVE` addend
  anywhere holds the bucket body's address: the two
  call sites are its complete reference set.
- The second caller `0x5ceafd0` has no direct or
  rip-relative references; its single addend
  reference at `0x64dfe40` sits in a run of four
  code-pointer addends (`0x5cf31f0`, `0x5ce88e0`,
  this body, `0x15c2d00`) that ends at `0x64dfe50`,
  a `GLOB_DAT` slot. Which object's table this is,
  and on what runtime event the body is invoked
  through it, is not established here.
- Open edges 1 (`[wheel+0x30]` writer), 2 (runtime
  field contents) and 4 (gate re-invocation,
  `[record+0x1d8]`) from the earlier RE-005 packets
  are untouched, per this packet's boundary. The
  consumers of the wheel list that the inline arms
  maintain are likewise not traced here.

## Packet contents

- `records.json` — every derived record (owners,
  slots, strings, Location statics, constants, store
  censuses, call-site census, reference census, pins,
  findings, the call table, open edges).
- `frames.txt` — the two FDE lines for the exported
  bodies.
- `caller.objdump.txt`, `bucket.objdump.txt` — full
  Intel-syntax exports.
- `MANIFEST.sha256` — digests of the packet files.
- Tool: `tools/bucket_second_caller_static.py`;
  tests: `tests/test_bucket_second_caller_static.py`.
