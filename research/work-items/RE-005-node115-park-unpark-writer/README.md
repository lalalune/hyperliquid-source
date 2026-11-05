# RE-005 node 115 park unpark writer

Answers the open edge the RE-005 park contention
fallback packet (`RE-005-node115-park-contention-
fallback`, PR #2941) left open: who writes state
value 3 to a per-thread park cell (the notify/unpark
side), and through which entry points a wake targets
a specific cell. This packet fixes, for the
authenticated hl-node 115 artifact only, the writer
body, its four old-value arms, and its complete
direct caller census.

## Settled

- The writer is the body `0x5ce3580..0x5ce3662`,
  the unpark half of the vendored tokio multi-thread
  scheduler park module: its one panic carries the
  Location static `0x64c5a38` in
  `/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/scheduler/multi_thread/park.rs`
  (line 288, col 23) and the message piece
  "inconsistent state in unpark; actual = ". It
  takes the handle pointer (the same handle object
  registration_b takes, whose field at `+0x10` is
  the park cell Q of the earlier packets) and swaps
  3 into the state word at `[handle+0x18]`
  (= `[Q+8]`): `mov eax, 3` at `0x5ce3585`, xchg at
  `0x5ce358a`. A whole-`.text` scan for that store
  pattern (immediate 3 loaded for an xchg into a
  `+0x18` word) finds this site alone, and the
  module Location census (all six statics of the
  file) names every module body — `wrapper_state`
  `0x5ce2fd0`, the contention fallback `0x5ce30d0`,
  `registration_b` `0x5cec8b0`, and this unpark — of
  which the first three only consume 3 with the
  CAS 3 → 0 sites the earlier packets pinned.
- Old-value arms (jump table at `0x94cb20`):
  old 0 → return, the 3 stays latched as a pending
  notification for the next park to consume;
  old 1 → claim the cell's guard byte at
  `[handle+0x28]` (= `[Q+0x18]`, CAS 0 → 1 at
  `0x5ce35a8`, waiting on the byte through GOT
  `0x64e01f8` / byte_wait `0x5bb59d0` with the
  sentinel on contention), release it (CAS 1 → 0 at
  `0x5ce35b3`, byte_notify through GOT `0x64e0f38`
  if the release fails), then, if the wait-key word
  at `[handle+0x20]` (= `[Q+0x10]`) is non-zero,
  tail-jump through GOT `0x64ec188` to the wake
  body `0x5bb42e0` with (&key, token);
  old 2 → forward the second argument and tail-jump
  at `0x5ce35d5` to the driver signal body
  `0x5ce09a0`; old 3 → return (already notified).
  Old above 3 panics at line 288 with the old value
  as the {} argument; no writer in the pinned graph
  produces a value above 3.
- The driver signal body `0x5ce09a0..0x5ce0aa2` is
  an inline copy of the runtime-park unpark
  protocol on the shared inner: it dereferences the
  caller-supplied slot (ctx+0x150, ctx+0x160 in the
  broadcast caller), swaps 2 into the inner parker
  state word at `[inner+0x10]`, and on old 1 claims
  the inner byte at `[inner+0x20]`, snapshots the
  token at `[inner+0x18]` and tail-jumps to the
  same wake body through the same GOT slot. Its
  panic is the runtime/park.rs line 187 Location
  (static `0x64c6f60`) the TLS value-object packet
  pinned for the out-of-line unpark `0x5cfd600`.
- Entry points: exactly six direct references and
  no indirect route (no `.rela.dyn` RELATIVE addend
  names the body; its start occurs nowhere in the
  file as a stored pointer). Five callers resolve
  the target cell out of a scheduler context first
  — claim the byte at `[ctx+0xf8]`, bounds-check
  the index against `[ctx+0x90]`, load the handle
  from the 16-byte table at `[ctx+0x88]` (entry
  `+8`), pass `ctx+0x150` as the second argument:
  `signal_arg` `0x5ce3fd0` (tail jump `0x5ce4235`,
  index from a register), `signal_pop_call`
  `0x5ce4430` (call `0x5ce450e`), `signal_pop_jmp_a`
  `0x5ce45b0` (tail jump `0x5ce468f`),
  `signal_pop_jmp_b` `0x5ce4720` (tail jump
  `0x5ce48cb`) and `signal_pop_call_b` `0x5ce4990`
  (call `0x5ce4a88`) — the four pop variants take
  the index from the top of the context stack at
  `[ctx+0x108]`/`[ctx+0x110]`. The sixth,
  `signal_all` `0x5cfadf0` (call `0x5cfaec8` in its
  loop), unparks every entry of its own table
  (`[ctx+0x98]`/`[ctx+0xa0]`, second argument
  `ctx+0x160`). A wake therefore targets exactly
  the cell whose handle the caller resolved; the
  unpark body itself is cell-agnostic.

## Evidence

- `records.json` — artifact hash, two exported body
  records, fifteen pinned body records, the
  whole-`.text` rel32 census for the unpark body
  (every hit boundary-verified against its
  containing FDE body), the six-static module
  Location census with boundary-verified lea sites,
  the xchg store-pattern census, the empty rela and
  raw-pointer censuses for the body start, the
  old-value jump table, the panic message, the
  instruction byte pins, findings, open edges.
- `unpark.objdump.txt`, `inner_unpark.objdump.txt`
  — full exports of the two load-bearing bodies.
- `frames.txt` — `.eh_frame` FDE lines for all
  seventeen bodies.
- `MANIFEST.sha256` — hashes of everything above.

Reproduce / verify:

```sh
python3 tools/park_unpark_writer_static.py            # {"matches": true}
python3 tools/park_unpark_writer_static.py --generate # regenerate packet
python3 -m unittest tests.test_park_unpark_writer_static -v
```

## Open edges

- What distinguishes the four pop-variant signal
  bodies from each other beyond index source and
  call-vs-tail-jump — e.g. which scheduler event
  each one serves — is not traced here.
- The writers of the scheduler context fields the
  signal bodies read (worker table at
  `ctx+0x88/+0x90`, index stack at
  `ctx+0x108/+0x110`, guard byte at `ctx+0xf8`,
  inner slot at `ctx+0x150`) are not censused here;
  the forwarder time-context writers edge of the
  park_timeout provenance packet is the same shape
  of question for the time context.
- Open edges 1 and 4 of the TLS value-object
  packet (the parking layer bit protocol and the
  missing type name) and the `[S+0x50]` byte-claim
  census edge of the contention fallback packet
  remain open.
