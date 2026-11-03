# RE-001: the node #115 lu miss handler — directory, evict, then insert

Answers packet #214's next question: what the `0x63d9700` miss handler does
end to end.

## Short answer

`0x63d9700` is not the lu worker's private helper. It is a shared
lookup-or-insert routine with 168 direct callers. Given
`(thread, record, table, key, mode8, mode9)` it consults a directory of
8-byte slots at `record+0x78`, indexed by `(key>>30) & 0x3ffff`. On a
filled slot it installs the entry into the worker's 16-bucket table
(evicting the bucket's current occupant into overflow slot 0) and returns
`dir_value + ((key>>9) & 0x1ffff8)`. On an empty slot it returns NULL in
the worker's strict mode, or lazily allocates a `0x200000`-byte block
under the record's `+0x48` mutex in the alloc mode. The worker re-validates
the returned pointer through its own gates afterwards, so the handler's
return is not final.

## Signature and entry (FDE `0x63d9700..0x63d987b`, 379B, single `ret`)

Args: `rdi` = thread, `rsi` = record, `rdx` = table base, `rcx` = key,
`r8` = mode8, `r9` = mode9. Saves: key → `r12` is the table base
(`rdx`), key → `rbp`/`rbx`, thread → stack slot. The record object, as
addressed by this handler (worker's record is `[ref+0xe410]`):

- `+0x0`: pool pointer (allocator argument)
- `+0x8`: contention-helper argument (passed to `0x63bf680`)
- `+0x30`: thread-switch count (increments only when the locking thread
  differs from `+0x38`)
- `+0x38`: last locking thread
- `+0x40`: lock-acquisition count (increments on every locked path)
- `+0x48`: mutex (`pthread_mutex_trylock` / `pthread_mutex_unlock`)
- `+0x70`: contended byte (1 on the contention path, 0 on success exits)
- `+0x78`: directory base (8-byte slots)

## The three modes

The handler's control flow branches on `mode9` first, then `mode8`.
Only the insert path is shared by all modes.

- **mode8 = 1 (159 sites): unconditional insert.** The slot value is used
  as-is, even if zero. No NULL check, no lock, no allocation.
- **mode8 = 0, mode9 = 1 (8 sites): lazy-alloc insert.** If the slot is
  filled, insert directly. If empty, take the locked path below.
- **mode8 = 0, mode9 = 0 (1 site, the lu worker at `0x63ae239`): strict.**
  Empty slot → NULL immediately. Filled slot → insert. No lock, no
  allocation.
- No caller passes mode8 = 1 with mode9 = 1.

## The insert path (shared)

1. **Shift the overflow.** `memmove(table+0x110, table+0x100, 0x70)`:
   overflow slots 0..6 move to 1..7. Old overflow slot 7 is dropped
   silently — that is the eviction.
2. **Evict the bucket occupant.** Bucket `b = (key>>26) & 0xf0` — the same
   bucket index the worker just missed on. The bucket's key word and value
   move into overflow slot 0 (the most-recent position). The move is
   unconditional: no emptiness check on the bucket.
3. **Install.** Bucket key := `key & 0xffffffffc0000000`, bucket value :=
   directory value.
4. **Return.** `dir_value + ((key>>9) & 0x1ffff8)` — the same entry-pointer
   derivation the worker uses for bucket and overflow hits.

## The locked lazy-alloc path (mode8 = 0, mode9 = 1, empty slot only)

1. `pthread_mutex_trylock(record+0x48)`. On failure, call the contention
   helper `0x63bf680(record+0x8)` — the same helper as packet #210's
   contention path — set the `+0x70` byte to 1, and proceed as if locked
   (the helper's internals are not decoded here).
2. On the locked path, bump `+0x40`; if the thread differs from `+0x38`,
   bump `+0x30` and store the thread into `+0x38`.
3. Re-read the slot. If it is now filled, clear `+0x70`, unlock, and
   insert.
4. If still empty, call the allocator `0x636b370(thread, *record,
   0x200000, 0x40)`. On NULL: clear `+0x70`, unlock, return NULL. On
   success: store the block pointer into the slot, clear `+0x70`,
   unlock, and insert with the new block as the directory value.

## What the handler returns, and what happens next

- Entry pointer `dir_value + ((key>>9) & 0x1ffff8)` on every insert path.
- NULL exactly on: strict mode with an empty slot, or alloc mode with a
  failed allocation. The unconditional-insert mode never returns NULL
  from its own code (its return is `0 + offset` if the slot was zero,
  which the caller then validates).
- The lu worker jumps back to `0x63adfed` with the handler's return and
  runs its own validation: NULL if the pointer is 0, NULL if the
  dereferenced entry word masked with `0xffffffffff80` is 0, then the
  flag6 bit gate, the kind check, the stack7 bit-13 gate, the bit-14
  gate, the xor gate, and the join call. The handler's NULL is therefore
  sufficient but not the only NULL on the miss path.

## Census

Whole-file `E8` scan with rel32-target filter (168 candidates) plus
per-site disassembly and arg-setup sampling: handler `0x63d9700` has
**168 direct E8, 0 E9, 0 LEA, 0 GOT** (60,723 `.rela.dyn` entries, no
addend hits). Mode split by caller arg setup: 159 sites pass
`(mode8, mode9) = (1, 0)`, 8 sites pass `(0, 1)`, 1 site — the lu worker
`0x63ae239` — passes `(0, 0)`. The 8 alloc-mode sites cluster at
`0x63ae627`, `0x63ae6bf`, `0x63af3a8`, `0x63af44d`, `0x63af9cd`,
`0x63afa65`, `0x63afafa`, `0x63afb95`, next to the lu worker.

## Corrections to earlier packets

- **#214, argument naming corrected.** #214 described the miss-handler
  call as `(thread, table, rbx, 0, 0)`. The second argument is not the
  lookup table: it is the record object (`[ref+0xe410]` for the worker),
  whose `+0x78` holds the directory and whose `+0x48` is the mutex. The
  lookup table itself arrives as the third argument (`rdx` =
  `thread+0x1b0`). #214's substance is confirmed: the worker passes
  `(0, 0)` for the two modes, and its return re-enters worker validation
  at `0x63adfed`.
- **#210, helper reuse noted (not a correction).** The contention helper
  `0x63bf680` from #210's record-C path is called here with
  `record+0x8`. Its internals remain undecoded in both packets.
- No bytes claimed by packets #183–#214 are re-claimed. All exhibits lie
  strictly inside the handler FDE; the worker re-entry address
  `0x63adfed` and the bucket/overflow addresses are cited by address
  only.

## Unresolved, stated not inferred

Internals of the allocator `0x636b370` (what it does with
`(thread, pool, 0x200000, 0x40)`, what it returns, when it returns NULL);
internals of the contention helper `0x63bf680`; internals of the
`0x63d9880` thread-== 0 detour; the design intent behind the directory
index using bits 30..47 of the key while the bucket uses bits 26..29;
why no caller uses mode `(1, 1)`; the identity of the record object for
callers other than the lu worker.

## Next question

Decode the `0x636b370` allocator end to end: what it does with
`(thread, pool, 0x200000, 0x40)`, what block pointer it returns, when it
returns NULL, and how the `0x40` argument shapes the allocation.
