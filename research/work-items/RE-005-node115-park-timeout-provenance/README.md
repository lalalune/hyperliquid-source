# RE-005 node 115 park_timeout timeout provenance

Answers open edge 3 of
`research/work-items/RE-005-node115-tls-value-object`
(the TLS value-object packet): that packet fixed
`park_timeout` `0x5cfd9a0` and its three call sites
plus one tail jump, but did not trace the timeout
values they pass. This packet fixes, for the
authenticated hl-node 115 artifact only, where each
timeout comes from — constant, computed, or
pass-through — and what caps it.

## Settled

- Every layer passes the timeout as a `(secs u64,
  nanos u32)` register pair. The nanos word doubles
  as the infinity sentinel: `nanos == 0x3b9aca00`
  (1_000_000_000) means "no timeout"; every consumer
  tests the nanos word alone and the secs word is
  then a don't-care.
- Tail jump `0x5ce0193` (selector `0x5ce0160`,
  `io/driver.rs` line 165): a pure pass-through of
  the selector's own pair.
- Call `0x5cfdfa5` (forwarder `0x5cfdd00`,
  `time/mod.rs` line 214, resolver flag clear): a
  pure pass-through of the forwarder's entry pair.
- Call `0x5cfdeab` (forwarder, resolver flag set):
  the one genuinely computed value — `min(caller
  pair, remaining)` where remaining is the time
  left in the context's current timing-wheel period
  (budget from the wheel state at `ctx+0x58` minus
  elapsed since the base pair at `ctx+0x88/+0x90`,
  saturating). A sentinel caller pair skips the min
  and passes the full remaining.
- Call `0x5cf29c8` (loop body `0x5cf27c0`):
  remaining time to the body's own deadline
  (deadline − now, saturating) — finite in form but
  unreached in fact: the only chain above it
  (dispatch `0x5cf6a90` ← pass-through `0x5cf3fe0`)
  is fed exclusively by three wrappers that each
  load the sentinel immediately before calling.
- Supply census: both registration bodies hardwire
  `secs = 0` and forward a bare nanos word; all six
  registration call sites supply nanos in
  `{0, 0x3b9aca00}` only, and a sentinel is diverted
  to the park selector, so the pair that actually
  reaches the timeout selector from this graph is
  `(0, 0)`. The rela addend census over all nineteen
  bodies finds exactly two pointer references —
  slots `0x64e1790`/`0x64e1798` of a larger
  function-pointer table hold the two top
  registration bodies — and both hardwire their
  supplies in their own code; no body that receives
  a duration has any pointer reference.

## Evidence

- `records.json` — artifact hash, ten exported body
  records, nine pinned body records, the
  whole-`.text` rel32 censuses for all ten graph
  bodies (every hit boundary-verified against its
  containing FDE body), the rela pointer census,
  the four panic Locations with file paths
  recovered from `.rela.dyn` RELATIVE addends, the
  three panic/assert messages, the instruction byte
  pins, findings, open edges.
- `*.objdump.txt` — full exports of the ten load-
  bearing bodies: the two selectors, the state
  wrapper, the dispatch, the forwarder, the loop
  body, the two registration bodies, and the two
  arithmetic helpers (wheel resolver, saturating
  pair subtraction).
- `frames.txt` — `.eh_frame` FDE lines for all
  nineteen bodies.
- `MANIFEST.sha256` — hashes of everything above.

Reproduce / verify:

```sh
python3 tools/park_timeout_provenance_static.py            # {"matches": true}
python3 tools/park_timeout_provenance_static.py --generate # regenerate packet
python3 -m unittest tests.test_park_timeout_provenance_static -v
```

## Open edges

- Who writes the pair discriminant at `[pair+0]`
  and the payloads at `[pair+8]`/`[pair+0x10]` (the
  selectors' `>1` slow path runs through
  `0x5ceed20`, `0x5ce7380`, `0x5cee650`) — open
  edge 2 of the TLS value-object packet, untouched.
- The writers of the time-context fields the
  forwarder reads (wheel state `ctx+0x58`, base pair
  `ctx+0x88/+0x90`, shutdown byte `ctx+0x80`,
  stored budget `ctx+0x78`) and the forwarder exit
  path's own recompute through `0x5ceaa20`.
- The contention fallback body `0x5ce30d0` that
  registration_b calls when its byte claim fails.
- Open edges 1, 2 and 4 of the TLS value-object
  packet remain open.
