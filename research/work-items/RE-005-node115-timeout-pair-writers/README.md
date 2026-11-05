# RE-005 node 115 — who writes the park / park_timeout pair: one constructor, two variants, and what the slow path does

- Component ID: RE-005 (node 115 dispatcher / vendored tokio runtime)
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes; the only artifact this packet reads)
- Source commit / reference commit: lalalune/hyperliquid-source
  `main` at `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: settled findings are observations re-derived
  from the artifact by `tools/timeout_pair_writers_static.py`;
  source-level naming (tokio io driver / scheduler modules)
  rests on the panic Location statics pinned below and is
  labelled inference where it goes beyond the bytes.
- Scope included: the two io-driver selectors `0x5ce0160`
  (park_timeout) and `0x5ce0850` (park), their forwarder
  `0x5cfdd00`, the three slow-path bodies `0x5ceed20`,
  `0x5ce7380`, `0x5cee650`, the sole pair constructor
  `0x5ce01f0` with its helpers `0x5ceeae0` (Poll::new) and
  `0x5ce71f0` (waker registration), the installing builder
  `0x5cf9600`, and the complete passage of the pair through
  both schedulers (current_thread tops `0x5cfb610` /
  `0x5cfb920` + register body `0x5cfb780`; multi_thread
  register body `0x5cec8b0` + park entry `0x5ce2fd0`).
- Scope excluded: the RE-005 TLS value-object packet's own
  open edges (the parking layer's bit protocol; which
  structure fields carry the `{table, payload}` handle
  onward in the node dispatcher — a different pair from
  this one); the park_timeout provenance question, settled
  by the sibling RE-005 park_timeout packet; the
  multi_thread fallback body `0x5ce30d0`, settled by the
  sibling RE-005 race-fallback packet.

## The question

The TLS value-object packet showed the selectors receive
their argument inside a structure their callers form, and
left the supply side open: the selectors read a pair
`{[+0] tag, [+8] word, [+0x10] pointer}` — who writes those
three fields, with what values, and what does the
selectors' non-fast path (the three bodies behind the
`[pair+8] != INT64_MIN` arm) actually do? In particular:
the earlier packets fixed the supplied values at the
park_timeout call sites as (0, 0) / (0, sentinel) — is a
pair with discriminator > 1 ever constructed, and if so,
by whom and carrying what?

## The predicate — settled

Both selectors (`sel_park` 140 bytes, Location
io/driver.rs:160:32, static `0x64c64c8`; `sel_timeout`
137 bytes, io/driver.rs:165:32, static `0x64c64b0`) read
the pair the same way:

- `[pair+0] == 0` → tail-jump to the forwarder
  `0x5cfdd00` (time/mod.rs:217:9) with `rdi = pair+8`.
- Otherwise the fast arm is taken iff
  `[pair+8] == 0x8000000000000000` (INT64_MIN): jump to
  the park body `0x5cfdb90` / park_timeout body
  `0x5cfd9a0` with `rdi = [pair+0x10] + 0x10` and the
  caller's (secs, nanos). The comparison is compiled as
  a dead-flag sequence (`cmp $1` / `xor` / `cmp [pair+8],
  0` / `jno` — the second compare's overflow flag, set
  exactly when `[pair+8]` is INT64_MIN, decides); the
  forwarder's independent `movabs INT64_MIN; cmp; jne`
  on its argument word proves the same predicate without
  the flag trick.
- Any other `[pair+8]` runs, in order, `0x5ceed20`,
  `0x5ce7380` and a tail jump to `0x5cee650`, all on
  `X = pair+8`, then returns.

The forwarder re-tests `[arg+0]` against INT64_MIN
itself (sentinel immediates at `0x5cfdd8e`, `0x5cfdf65`)
and calls the same three bodies on the non-sentinel arm;
on the sentinel arm it selects park vs park_timeout by
the timeout nanos against `0x3b9aca00`. Neither selector
nor the forwarder contains a stored-pointer or
relocation reference anywhere in the artifact; all three
are reached by direct rel32 only (census in
`records.json`).

## The writer census — settled

Method: every E8/E9 rel32 in `.text`, every 8-byte stored
pointer to a body start in non-executable sections
(excluding the `.rela.dyn` section itself), and every
`.rela.dyn` addend, for all eighteen bodies in this
packet. Result:

- The pair head is written by exactly one constructor,
  `0x5ce01f0` (1,627 bytes), called from exactly one
  body: the builder `0x5cf9600` (4,785 bytes;
  builder.rs:2014:54) at `0x5cf9669` and `0x5cf96eb`.
- The only other stores to a live pair head are the
  current_thread park entries' transient marker
  (below). No body outside the constructor / builder /
  scheduler passage touches `[pair+0]`, `[pair+8]` or
  `[pair+0x10]`.
- Stored-pointer / relocation references to any of the
  eighteen bodies: exactly three, all R_X86_64_RELATIVE
  into `.got` slots — builder at `0x64e1760`, the two
  current_thread tops at `0x64e1790` / `0x64e1798`.
  Everything else in the family is direct-rel32 only.

## The constructor — settled

The builder assembles a small config from its own config
(the u16 at builder-config `+0xe5` supplies both bytes)
and calls the constructor twice (two runtime builds).
The constructor reads two independent config bytes:

- config `+8` (low byte) — the variant bit;
- config `+9` — the tag bit.

Both success variants leave through one shared write
block at `0x5ce0442`, which writes the tag as **0 when
the tag byte is 1, and 2 otherwise**. The variants
differ in what lands at `[+8]` / `[+0x10]`:

**Parker variant** (variant byte == 0). `0x5ceeae0` is
never called. A fresh 0x28-byte allocation is created
through slot `0x64df480` with the layout the TLS
value-object packet pinned (strong/weak 1, zeroed
0x18-byte payload) — the vendored parker. The head is
written `{tag, INT64_MIN, parker pointer}`: the sentinel
is materialised as a `movabs` at `0x5ce036d` and stored
to `[+8]`; the allocation pointer to `[+0x10]`. Every
such pair takes the selectors' fast arm.

**Poll variant** (variant byte != 0). `0x5ceeae0`
(Poll::new; called only from the constructor) runs
`epoll_create1` (slot `0x64eb058`), `eventfd` (slot
`0x64eb050`), registers the eventfd with `epoll_ctl`
(slot `0x64e12c0`, event `{flags 0x80002001, data 0}`)
and builds the poll object: `+0` capacity (the
constructor config's first word), `+8` events buffer
(capacity × 12 bytes), `+0x10` 0, `+0x18` epoll fd
(dword), `+0x1c` flag byte 0, `+0x30` the word `0x10`,
`+0x38` a fresh 0x80-byte registry buffer, `+0x60`
fcntl result, `+0x64` eventfd. Then `0x5ce71f0` (waker
registration; also constructor-only) registers the
poll's waker against the global signal state and
returns `{capacity, events buffer, 0, epoll fd,
registration Arc, token}`. Through the shared write
block the installed 0xd8-byte driver value carries the
head `{tag, capacity, events buffer}` with count 0 at
`+0x18`, the epoll fd at `+0x20`, and the poll object
embedded at `+0x40`. Every such pair takes the slow
arm: `[pair+8]` is a capacity, never the sentinel.

**Tag 3 is the error encoding, and it is never
installed.** Poll::new reports failure in-band: its
three exits write `{[+0] = INT64_MIN, [+8] =
(errno << 32) | 2}` to its sret (sentinel immediates at
`0x5ceebab`, `0x5ceebe2`, `0x5ceec1d`). The constructor
detects that word (`neg` / `jo` at `0x5ce0229`) and
exits through `0x5ce06a0` writing `{[+0] = 3, [+8] =
(errno << 32) | 2}` (byte pin at `0x5ce06a4`:
`48 c7 03 03…`). A waker-registration failure — the
registration word comparing equal to INT64_MIN at
`0x5ce02c2` — reaches the same tag-3 tail. The builder
compares the constructed tag against 3 immediately
after both constructor calls (`cmp $3, %r12` at
`0x5cf967e` and `0x5cf9700`) and converts a tag-3 result
into its own error return; only tags 0 and 2 are
installed (the value is memcpy'd through slot
`0x64df508` into the runtime). Inference, labelled:
the constructor is tokio's io `Driver::new` path and
the variant byte is the builder's IO enable — the
selectors' own context check panics with "A Tokio 1.x
context was found, but IO is disabled. Call
`enable_io` on the runtime builder to enable IO."
(message pinned at `0x94ca03`).

## How the pair reaches the selectors — settled

**current_thread.** The two top entries `0x5cfb610`
(current_thread/mod.rs:449:45) and `0x5cfb920`
(:411:45) own the stored 0x98-byte driver object O.
Each snapshots `[O+0..0x40)` to a 0x40-byte stack buffer,
writes **3** into `[O+0]` — panicking with "driver
missing" (string at `0x94db81`) if the old value was
already 3 — and calls the register body `0x5cfb780`
with the snapshot as the pair. `0x5cfb780` calls
`sel_timeout` once and `sel_park` once against the
snapshot, then drains the registry waker queue at
`[S+0x28]` (entries are `{ptr, fn}`; each fn is invoked
through `*0x8(%rdx)`), and the top entry writes the
snapshot back into O. So at park time the pair's tag is
the installed 0 or 2 — the 3 is only the taken-out
marker in the stored object while a park is in flight.

**multi_thread.** The register body `0x5cec8b0`
(worker.rs:862:41, "park missing") takes `T = [P+8]`
out of the 0x78-byte worker park object P, zeroes
`[P+8]`, and forms the pair base as `[T+0x10] + 0x10`
— an Arc payload base, the same head layout as the
stored driver value. The park entry `0x5ce2fd0`
(multi_thread/park.rs:258:28, :271:18) runs the
state-word protocol on `[T+0x18]`: (0, 0) goes straight
to `sel_timeout`; otherwise it CASes the state 0 → 2,
calls `sel_park` when nanos is the sentinel and
`sel_timeout` otherwise; old state 3 is cleared and
reported as notified. `0x5cec8b0` also calls `sel_park`
directly at `0x5cec986` with the same pair base, and on
byte-lock contention at `[Q+0x50]` diverts to the
fallback body settled by the sibling race-fallback
packet.

## The slow path, body by body — settled

All three bodies receive `X = pair+8` (the forwarder
passes its argument through unchanged), so their field
offsets below are X-relative; pair-relative offsets are
X+8 higher.

**`0x5ceed20` — the I/O poll** (729 bytes; Locations
mio/src/event/events.rs:212:9, io/driver.rs:221:17,
io/driver.rs:196:23). On entry it claims the context
byte `[ctx+8]` by cmpxchg (waiting through slot
`0x64e01f8` → byte-wait body `0x5bb59d0` on contention)
and runs the inner poll helper `0x5cf8f10`. It converts
(secs, nanos) to a millisecond timeout (saturating at
`0x7fffffff`; nanos == sentinel means −1) and calls
`epoll_wait` through slot `0x64eb060` with fd
`[X+0x18]` (dword), events buffer `[X+8]`, maxevents
dword `[X+0]`. The returned count is stored at
`[X+0x10]`. Returned 12-byte events are walked: data 0
is skipped; data 1 sets byte `[X+0x1c] = 1`; a data
pointer has the event bits converted and CAS-merged
into `[data+0x10]`, followed by a call to the wake body
`0x5cfd1d0`. `errno == EINTR` returns quietly through
helper `0x5cee460`; any other negative result panics
with the message referenced at `0x443685`,
".unexpected error when polling the I/O driver: "
(the leading '.' is part of the referenced bytes).

**`0x5ce7380` — the signal drain** (550 bytes;
Locations signal/mod.rs:118:26, :121:27). It reads byte
`[X+0x1c]`, clears it, and returns at once unless it
was 1. Otherwise it drains the self-pipe whose fd is
the dword `[X+0x28]`, receiving through slot
`0x64eb080` (`recv`) into a 0x80-byte stack buffer
until would-block: a 0 return panics with "EOF on
self-pipe" (message at `0x454b60`), other failures go
down the errno-key path ("Bad read on self-pipe"
family). It then unregisters the current thread
(helpers `0x5ce6df0`, `0x5ce6eb0`) and sweeps the global
registry (base `0x64fee28`, count `0x64fee30`, stride
`0x20`): each entry whose flag byte at `+8` is set has
its object's lock word `[obj+0x130]` CASed 0 → 8,
counter `[obj+0x138]` incremented by 2, the word
released 8 → 0 (waiting through slots `0x64e0ff0`,
`0x64e1000` on contention), and the callback in slot
`0x64ecba8` (→ `0x5cfcc50`) invoked on `obj+0x10`.

**`0x5cee650` — the global refresh** (679 bytes; no
panic Location referenced). Its argument is
`pair+0x38`, used only as a key. It claims bit 0 of the
global lock byte `0x64fee00` by cmpxchg and returns at
once if the bit was already set. If the cached object
`0x64fee08` exists and `[obj+0x138] & ~1` equals the
cached key word `0x64fee10`, it unlocks and returns.
Otherwise it takes the second lock byte `0x64fede0`,
calls the notify helper `0x5cee900`, and when the cache
is empty resolves a fresh object pair through
`0x5cde710` keyed by 17 bytes at the argument; the old
object's Arc count at `[obj+0x140]` is decremented
(with the release path through slot `0x64e01e8` →
`0x5ce57c0` at zero), the globals are swapped, the
notify helper runs again, and temporaries are released
through `0x5cee460`. Which object family this cache
holds is open edge 2.

## Answer to the chased question

A pair with discriminator > 1 **is** constructed: tag 2
is one of the constructor's two success tags, written
whenever the builder config's tag byte is not 1, in
both variants. But the tag does not select the slow
path — `[pair+8]` does. A tag-2 parker-variant pair
carries the INT64_MIN sentinel and takes the fast arm;
a tag-0 or tag-2 poll-variant pair carries a capacity
and runs the trio. The only constructed heads outside
the poll variant whose `[pair+8]` differs from the
sentinel are the tag-3 error values (`[+8] =
(errno << 32) | 2`), and those never reach a selector:
the builder rejects tag 3 at both call sites and
returns an error instead of installing the value.

## Precise negatives and boundaries

- No stored pointer and no relocation names any of the
  selectors, the forwarder, the three slow bodies, the
  constructor, Poll::new, the waker registration, the
  register bodies, the park entry, or the park bodies;
  the only relocation-named bodies in the family are
  the builder and the two current_thread tops (`.got`
  slots `0x64e1760`, `0x64e1790`, `0x64e1798`).
- The selectors, forwarder and slow bodies contain no
  call to the constructor or the builder; they consume
  the pair, they never form it.
- `slow_c` reads nothing of the pair except the
  `pair+0x38` key value; its writes are to globals, not
  to the pair.
- The trio's X-relative fields line up with the poll
  object's fields only through the pair head
  (`[X+0]` = capacity = `[pair+8]`, `[X+8]` = events
  buffer = `[pair+0x10]`, `[X+0x10]` = count =
  `[pair+0x18]`, `[X+0x18]` = epoll fd = `[pair+0x20]`);
  the poll object embedded at `pair+0x40` is a separate
  copy the constructor makes of Poll::new's result.

## Open edges

1. The constructor's Poll-path registration loop
   (`0x5ce05ab..0x5ce0676`) can divert to the tag-3 exit
   on its exit compare at `0x5ce066d` (rcx against the
   capacity word); under which builder configurations
   that diversion fires is not settled here.
2. The global object `0x5cee650` refreshes (cached at
   `0x64fee08`, key word `0x64fee10`, lookup `0x5cde710`
   on a 17-byte key) is not identified here.
3. The two constructor config bytes are recorded
   mechanically from the builder config u16 at `+0xe5`;
   which source-level Builder settings set them is not
   named here.
4. The construction provenance of the multi_thread
   worker park object (the 0x78-byte object `0x5cec8b0`
   unwraps) is outside this packet; the sibling
   park_timeout provenance packet covers the (0, 0) /
   (0, sentinel) supply side.

## Reproduce

```sh
# with the node #115 artifact materialised at
# artifacts/node/115/hl-node (sha256 as above):
python3 tools/timeout_pair_writers_static.py --generate   # writes this packet
python3 tools/timeout_pair_writers_static.py              # verifies: {"matches": true}
python3 -m unittest tests.test_timeout_pair_writers_static
```

Method note: every digest pin in the tool was re-derived
from the artifact during this packet's preparation. The
first candidate census (an early helper build) returned
empty reference lists against a wrong section base and
was discarded; the census in `records.json` is the
full-.text rel32 scan cross-checked against the exported
disassemblies, and the stored-pointer scan excludes the
`.rela.dyn` section so relocation entries do not count
as stored references to their own addends. Analysis is
static only; the artifact was not executed.

## Packet contents

- `records.json` — every derived record (owners, pinned
  bodies, slots, Locations, the call censuses, the
  relocation and stored-pointer references, sentinel
  sites, byte pins, messages, findings, open edges).
- `frames.txt` — the FDE lines for the exported and
  pinned bodies.
- `sel_timeout.objdump.txt`, `sel_park.objdump.txt`,
  `forwarder.objdump.txt`, `ctor.objdump.txt`,
  `poll_new.objdump.txt`, `waker_reg.objdump.txt`,
  `builder.objdump.txt`, `top_a1_ct.objdump.txt`,
  `top_a2_ct.objdump.txt`, `reg_a_ct.objdump.txt`,
  `reg_b_mt.objdump.txt`, `park_entry_mt.objdump.txt`,
  `slow_a_poll.objdump.txt`, `slow_b_signal.objdump.txt`,
  `slow_c_refresh.objdump.txt` — full Intel-syntax
  exports of the fifteen owner bodies.
- `MANIFEST.sha256` — digests of the packet files.
- Tool: `tools/timeout_pair_writers_static.py`;
  tests: `tests/test_timeout_pair_writers_static.py`.
