# RE-005 node 115 park contention fallback

Answers the open edge both the TLS value-object
packet (`RE-005-node115-tls-value-object`, PR #2935,
which listed body `0x5ce30d0` as beyond its boundary)
and the park_timeout provenance packet
(`RE-005-node115-park-timeout-provenance`, PR #2938)
left open: the contention fallback body `0x5ce30d0`
that registration_b calls when its byte claim fails.
This packet fixes, for the authenticated hl-node 115
artifact only, what the body is, which paths reach
it and under what conditions, what it does inside,
and whether the fallback can actually fire.

## Settled

- Identity: the body is the park core of the
  vendored tokio multi-thread scheduler. Its three
  assertion panics carry Locations in
  `/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/park.rs`
  (lines 179, 211, 213), recovered from `.rela.dyn`
  RELATIVE addends. It operates on the per-thread
  park cell Q (in registration_b, the field at
  `[r13+0x10]` of the handle object taken from the
  caller's argument): state word `[Q+8]`, guard
  byte `[Q+0x18]`, wait key `[Q+0x10]`. It never
  reads or writes `[Q+0]`, the shared-inner pointer
  whose byte claim gates entry.
- Sole route in: the whole-`.text` rel32 census
  finds exactly one reference in the artifact —
  call `0x5cec9ec` in registration_b `0x5cec8b0`.
  No tail jump, no stored pointer and no RELATIVE
  addend names the body, so no indirect route
  exists.
- Entry conditions: both arms share the tail at
  `0x5cec9e7` (`esi = 0`, `edx =` the nanos word,
  `rdi = Q`). Sentinel arm: nanos equals the
  `0x3b9aca00` sentinel, the state consume CAS
  (3 → 0 at `0x5cec948`) failed, and the byte claim
  on the shared inner at `[S+0x50]` (`S = [Q+0]`)
  at `0x5cec95e` failed. Finite arm: nanos is not
  the sentinel, the byte claim at `0x5cec9c8`
  failed, and nanos is nonzero (the test/je at
  `0x5cec9e2`/`0x5cec9e5` skips the call for zero).
  The holder keeps the byte across its entire
  selector park (release is the xchg at
  `0x5ceca09`, after the selector call returns),
  so contention lasts a whole park, not a spin
  window.
- Supply: registration_b's only caller, top_reg_b
  `0x5cecc60`, supplies `edx` in `{0, sentinel}`
  at its three call sites (xor-zeroed at
  `0x5cece57` and `0x5ced565`, sentinel constant
  at `0x5ced788`). A zero nanos is gated off
  before the fallback call, so in this artifact
  the fallback is entered only with
  `(secs = 0, nanos = sentinel)` — only its
  indefinite-park arm can execute. Its
  finite-duration arm (deadline = clock now plus
  the pair, the std overflow panic at
  `std/src/time.rs` line 429, remaining recomputed
  through `instant_sub` `0x5c84210`, the timed
  wait) is structurally present but has no
  supplying caller.
- Inside, on the reachable arm: claim the cell's
  own guard byte `[Q+0x18]` (0 → 1 CAS at
  `0x5ce30ee`); if already set, wait through GOT
  `0x64e01f8` (byte_wait `0x5bb59d0`) with
  (byte pointer, `0x3b9aca00`) and continue. CAS
  the state word `[Q+8]` 0 → 1: an old value of 3
  is a raced notification — consume it (xchg to 0)
  and return; any other non-zero old value panics
  "inconsistent park state; actual = {}"
  (park.rs line 179). Otherwise wait in the loop
  at `0x5ce31b5`, calling the wait helper through
  GOT `0x64e73b8` (wait_helper `0x5bb4670`) with
  `(Q+0x10, Q+0x18, sentinel)` until the state CAS
  3 → 0 at `0x5ce31d3` succeeds. Exits release the
  guard byte (1 → 0 CAS at `0x5ce331a`); on CAS
  failure the exit tail-calls the notify helper
  through GOT `0x64e0f38` (byte_notify
  `0x5bb5650`) with (byte pointer, 0). The call
  shapes are the guard idiom the RE-001
  queue-table packets pinned. The body is the
  only writer of state value 1 in this graph.
- Difference from the normal path: the
  claim-success arms drive the state word 0 → 2
  (wrapper_state on the finite arm,
  registration_b's own CAS at `0x5cec973` on the
  sentinel arm) and park through the io/time
  selectors on the shared inner. The fallback
  touches no shared state — the loser parks on
  its own cell through the scheduler wait table,
  cycling the state word 0 → 1 → 0 instead of
  0 → 2 → 0 — and registration_b discards its
  return value, continuing at the same shared
  continuation (`0x5ceca0d`) and storing the same
  pre-claim flag (`bpl = 1` on both fallback arms)
  into the returned object at `+0x74`.
- Panic surface: park.rs lines 179, 211, 213 and
  the std duration-overflow panic. On the
  reachable arm only the line 179 check sits on
  the path, and the pinned writer graph produces
  only 0, or a raced 3, for this cell at that
  point — a consistency assertion, not an expected
  outcome. The line 211/213 panics guard the
  finite arm's exit switch (jump table at
  `0x94cb10`: old state 0 → line 211 panic, 1 →
  exit, 2 → line 211 panic, 3 → exit; old state
  above 3 → line 213) and are unreachable from
  the pinned caller graph, as is the overflow
  panic.

## Evidence

- `records.json` — artifact hash, two exported
  body records, seven pinned body records, the
  whole-`.text` rel32 censuses for the fallback,
  registration_b and wrapper_state (every hit
  boundary-verified against its containing FDE
  body), the RELATIVE rela census over all nine
  chain bodies (the only hits are the three GOT
  slots resolving to the wait/notify helpers),
  the empty raw-pointer scan for the fallback,
  the finite arm's exit jump table, the four
  panic Locations with file paths recovered from
  `.rela.dyn` RELATIVE addends, the four panic
  messages, the instruction byte pins, findings,
  open edges.
- `*.objdump.txt` — full exports of the two
  load-bearing bodies: the contention fallback
  itself and its only caller, registration_b.
- `frames.txt` — `.eh_frame` FDE lines for all
  nine bodies.
- `MANIFEST.sha256` — hashes of everything above.

Reproduce / verify:

```sh
python3 tools/park_contention_fallback_static.py            # {"matches": true}
python3 tools/park_contention_fallback_static.py --generate # regenerate packet
python3 -m unittest tests.test_park_contention_fallback_static -v
```

## Open edges

- Who writes state value 3 to a cell (the
  notify/unpark side), and through which entry
  points a wake targets a specific cell; the
  fallback only consumes 3.
- The internals of the wait helper `0x5bb4670`
  and of the guard wait/notify helpers
  `0x5bb59d0` / `0x5bb5650` — RE-001 territory;
  this packet pins only their GOT slots, extents,
  digests and call shapes.
- Whether any body outside the exported/pinned
  set also claims the byte at `[S+0x50]` on the
  shared inner; within the caller graph above
  registration_b the only claim and release sites
  are registration_b's own.
- Open edges 1, 2 and 4 of the TLS value-object
  packet, and the forwarder time-context writers
  edge of the provenance packet, remain open.
