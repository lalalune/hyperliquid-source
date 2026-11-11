# RE-001: The arena block deque's grow routine (0x605d000)

## Bounded question

When the arena class behind `memory/arena.cc` needs a new block, what
does the grow routine at `0x605d000` — cited by the merged
`RE-001-arena-allocate-aligned-115` packet only through its
`callees_by_contract` entry, with its internals left in that packet's
unknowns — actually do with the object at `+0x868..+0x8e8`, the fresh
region producer it calls, and the block deque's node map, and which
failures can escape it?

## Windows

- Main: `0x605d000..0x605d3a1` (929 bytes) — the grow routine.
- Helpers: `0x60d4f70..0x60d4ff8` (136 bytes) — the descriptor
  destroy (`0x60d4f70`), move-assign (`0x60d4fa0`), and install
  (`0x60d4fe0`) helpers of the 16-byte `{address, length}` descriptor.
- Create: `0x60d5000..0x60d5094` (148 bytes) — region create
  (`0x60d5000`) and the producer wrapper (`0x60d5050`) that is the
  grow routine's sole source of fresh regions.
- Notify: `0x605e830..0x605e859` (41 bytes) — the trailing notify
  hook.
- Cleanup: `0x605cfd6..0x605cffb` (37 bytes) — the shared exception
  cleanup block the main window's landing pad forwards to.

## Claim status

Modelled and differentially validated. The Python model in
`tools/arena_grow_115.py` is checked against the native bodies in the
pinned artifact by `differential.py` (Unicorn) over 66 scenarios:
the append fast path at every finish fill level, the auxiliary path
with map slack, map recentering, and map regrowth at several sizes,
start-node consumption, notify dormant/active/wake-throws, chunk and
map allocation failures, region-production failure, and fabricated
deque-limit / map-overflow fields. Outcomes, oracle call logs,
object fields, map slots, chunk contents, and the thrown
`length_error` message string all match.

## Relation to other packets

This packet pins the grow callee that
`RE-001-arena-allocate-aligned-115` cites by contract
(`callees_by_contract/grow_0x605d000`) — the caller windows at
`0x605d6c0` / `0x605d7b0` belong to that packet. The descriptor
helpers and the object field offsets (+0x868 map, +0x878/+0x898
iterators, +0x8e0 byte counter) are the same deque and arena object
that packet establishes. The notify hook's wake target at
`0x606a0c0` is in the two-flag neighbourhood and is cited here by
contract only.

## What the body does (pinned from the excerpt)

1. **Produce.** The routine calls the wrapper at `0x60d5050` with a
   stack slot and the requested size. The wrapper calls region
   create (`0x60d5000`) with flag byte 1: the slot `{0, size}` is
   stored, and for a nonzero size
   `mmap(NULL, size, PROT_READ|PROT_WRITE, (1<<0x12)|0x22, -1, 0)`
   runs — flags `0x40022` (`MAP_PRIVATE | MAP_ANONYMOUS |
   MAP_HUGETLB`) — with `MAP_FAILED` folded to address 0. The
   wrapper returns the slot's address. A zero address makes the
   grow routine return 0 with the object untouched (this is also
   the size-0 path).

2. **Append.** Otherwise the descriptor `{address, size}` is
   appended to the back of the block deque (16-byte descriptors,
   32 per 512-byte node). When the finish cursor is not at the
   penultimate slot of the finish node (`finish.cur !=
   finish.last - 16`), the descriptor is installed in place and the
   cursor advances by 16.

3. **Auxiliary path.** Otherwise the element count is recomputed
   from the iterators:
   `((finish.node - start.node)/8 - (finish.node != 0 ? 1 : 0)) * 32
   + (finish.cur - finish.first)/16 + (start.last - start.cur)/16`,
   and equality with the deque maximum `0x7ffffffffffffff` throws
   `std::length_error` with the message "cannot create std::deque
   larger than max_size()" (the string is read from the artifact).
   When no more than one map slot follows the finish node, the map
   is adjusted first: if `map_size > 2 * (node span + 2)` the node
   pointers are recentered with one `memmove` (no allocation, no
   free); otherwise a new map of `2 * (old size + 1)` slots is
   allocated (`(old size + 1) * 16` bytes through the sized
   operator new; the empty-map case allocates the fixed 24 bytes
   for 3 slots), with the start offset `(new size - new count)/2`,
   the live span copied (a single-8-slot span by one unrolled copy,
   wider spans by `memmove`), and the old map released through the
   sized operator delete. The new element count shifted right by
   60 distinguishes the failure: nonzero at `>>60` with zero at
   `>>61` throws `std::bad_alloc`, nonzero at `>>61` throws
   `std::bad_array_new_length`. A fresh 512-byte node is then
   allocated into the finish node's next map slot, the descriptor
   is installed into the old finish node's final slot through the
   install helper — which zeroes the destination slot first, so
   whatever descriptor sat there is dropped without `munmap` —
   and the finish iterator advances to the fresh node.

4. **Accounting and notify.** The region size is added to the byte
   counter at `+0x8e0`, the finish cursor is stored, and the
   routine tail-calls the notify hook (`0x605e830`): when the
   tracker head at `+0x8e8` has both qwords `[+0x0]` and `[+0x20]`
   zero the hook does nothing at all; otherwise it atomically adds
   the size to the counter at `tracker + 0x8` and tail-jumps to
   the wake routine at `0x606a0c0` (contract only here). The
   routine returns the region address.

5. **Exceptions.** The window's LSDA gives the producer call
   (0x605d030..0x605d035) no landing pad — a throw there propagates
   raw — and routes everything from the notify call through the
   map-growth calls (0x605d086..0x605d395) to the 12-byte pad at
   `0x605d395`, which moves the exception object aside and jumps to
   the shared cleanup block at `0x605cfd6`: the region slot is
   destroyed (the descriptor destroy `munmap`s it when nonzero),
   the stack canary is verified, and `_Unwind_Resume` runs. So a
   throw from the auxiliary path unwinds with the object unchanged
   and the fresh region released, while a throw from the notify
   wake unwinds only after the append, the byte counter, and the
   notify counter have all landed.

## Census (whole-binary, from `census.py`)

- Grow `0x605d000`: direct calls at `0x605d73b` (inside the slow
  window at `0x605d6c0`) and `0x605d8af` (inside `0x605d7b0`); no
  tail jumps to it, no absolute qword hits, no RELATIVE slots.
- Region create `0x60d5000`: called only from the wrapper
  (`0x60d5071`). Producer wrapper `0x60d5050`: called only from
  the grow routine (`0x605d030`).
- Install `0x60d4fe0`: called only from the grow routine
  (`0x605d059`, `0x605d15c`).
- Move-assign `0x60d4fa0`: no direct calls; one tail jump from
  the install helper (`0x60d4ff3`).
- Descriptor destroy `0x60d4f70`: eleven direct calls across the
  arena class, including the shared cleanup block (`0x605cfd9`),
  the grow epilogue (`0x605d08e`), and the move helper itself
  (`0x60d4fb5`).
- Notify `0x605e830`: three direct calls — the grow routine
  (`0x605d086`), `0x605d41e` inside the block callee at
  `0x605d3c0`, and `0x605df8d`.
- Cleanup block `0x605cfd6`: no direct calls; one tail jump from
  the grow pad (`0x605d39c`).

## Unknowns left open

- The wake routine at `0x606a0c0` behind the notify hook (another
  work item's territory).
- The owning routines of the destroy helper's eight further call
  sites outside the allocate/grow neighbourhood.
- The callers' context of the two further notify sites.
- Any production frequency of the huge-page `mmap` failure arm.
