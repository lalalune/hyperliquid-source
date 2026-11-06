# RE-005 node 115 time-context field writers

Open edge 2 of the park_timeout provenance packet
(PR #2938), left in the same form by the park-unpark
writer packet (PR #2945): the forwarder 0x5cfdd00
reads the wheel state at ctx+0x58, the stored budget
at ctx+0x78, the shutdown byte at ctx+0x80 and the
base timestamp pair at ctx+0x88/+0x90, and #2938
pinned how it uses them without tracing who writes
them -- and the forwarder's exit path through
0x5ceaa20 recomputes the remaining period by a route
that packet did not trace either.  This packet fixes
the writer of every one of those fields, the value
each writer stores, and the identity of the exit
body, against the authenticated hl-node 115 artifact
only.

## Settled

- Identity: the ctx is the time half of the combined
  driver value built by driver_ctor 0x5ce01f0 --
  ctx = value + 0x40, a nine-field match under that
  shift, confirmed by every independent route
  (current_thread context + 0x1c0, multi_thread
  [[T]+0x10] + 0x160, timer-entry owner + 0x160 /
  + 0x240).
- Base pair (ctx+0x88/+0x90): one writer,
  driver_ctor's fresh arm.  Time flag set: the clock
  0x5c842e0 is called once at construction and the
  pair is that instant.  Flag clear: the nanos word
  is the sentinel 0x3b9aca00 -- the "timers disabled"
  encoding every consumer tests before touching any
  other field.  The tag-3 arm wraps an existing
  context and rewrites nothing.
- Wheel state (ctx+0x58): built only by wheel_ctor
  0x5cf6480, whose only caller in the artifact is
  driver_ctor -- a fresh 6 x 0x410 levels buffer,
  elapsed 0, empty pending list.  The levels pointer
  is never rewritten; elapsed is advanced only by
  wheel_process 0x5cf6510, called only by the unlock
  body.
- Shutdown byte (ctx+0x80): starts 0; the only
  runtime writer is shutdown_setter 0x5ce08e0 (xchg
  of 1, early return when already set, preceded by
  the timers-enabled check at time/mod.rs:190).  Its
  only two callers are the drop body 0x5ceb330 and
  the current_thread signal body 0x5cfbfd0.
- Stored budget (ctx+0x78): three writers -- the
  constructor (0), the forwarder (its resolved
  budget), the unlock body (its re-resolved
  deadline) -- and no reader in the closed method
  set: the deadline is always recomputed from the
  wheel, so the slot is a write-only cache here.
- Exit recompute: 0x5ceaa20 is the state's
  unlock/process body (self = &ctx+0x50), reached
  only from the shutdown setter's call (elapsed -1)
  and the forwarder's exit tail jump.  It caps the
  elapsed argument at the wheel's current elapsed,
  advances and drains the wheel, re-resolves the
  next deadline into ctx+0x78, releases the lock and
  fires the collected wakers.

## Evidence

- Seven bodies exported in full: the driver
  constructor, the wheel constructor, the wheel
  resolver, the wheel process body, the unlock body,
  the shutdown setter and the forwarder.  Twelve
  further bodies (builder, both registration bodies,
  the setter's two callers, the entry cancel/insert
  bodies, the io wake body, the clock helpers) are
  extent/digest pinned.
- Whole-.text rel32 censuses for the constructor and
  all six state bodies, each hit boundary-verified
  against its containing FDE body; a byte-pattern
  census of lock cmpxchg / xchg byte operations at
  displacement 0x50 over the vendored-runtime
  cluster, verified the same way; a .rela addend
  census (the cancel body is reached through the
  slot at 0x64dfe40, the builder through 0x64e1760);
  instruction byte pins at every load-bearing site;
  panic Locations and messages recovered from the
  artifact's own statics (time/mod.rs:190/214/217,
  time/entry.rs:181/549, time/wheel/mod.rs:56/130,
  util/wake_list.rs:35/36).

## Open edges

- The tag-3 constructor arm wraps an already-built
  context; which build paths supply it, and whether
  a wrapped context's fields can be re-initialised,
  is not traced.
- The drop body passes ctx as its second argument
  + 0x150; the object that argument points into is
  not identified here, so that one base relation is
  stated as observed, not derived.
- The insert path's writes (level slots, entry
  fields, the pending-list links at ctx+0x68/+0x70
  under the lock) are not censused here; its stores
  do not land on any of the five settled fields.
- Every traced consumer checks the sentinel nanos
  before reading the base secs; a whole-artifact
  negative for the disabled flavour's secs slot is
  not claimed.
- The io half of the same object (below ctx+0x50)
  belongs to the io driver graph of the earlier
  packets and is not re-traced.
