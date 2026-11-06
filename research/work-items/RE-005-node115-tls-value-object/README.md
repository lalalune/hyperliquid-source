# RE-005 node 115 — the TLS value object: the dispatcher's cell holds the vendored tokio parker, and here is every consumer

- Component ID: RE-005 (node 115 dispatcher / vendored tokio runtime)
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes; the only artifact this packet reads)
- Source commit / reference commit: lalalune/hyperliquid-source
  `main` at `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: settled findings are observations re-derived
  from the artifact by `tools/tls_value_object_static.py`;
  source-level naming (tokio park module) rests on the four
  panic Location statics and is labelled inference where it
  goes beyond the bytes.
- Scope included: the lazy thread-local getter
  `0x5cdf300`, the cell it serves (disassembly-visible at
  `fs:-0x418`, state byte compared at `fs:-0x410` in the
  dispatcher), the 0x28-byte allocation it creates, the
  four-entry handle table `0x64c6ef8`, the park /
  park_timeout / unpark protocol bodies, the parking-table
  wait and wake bodies, the byte wait/notify bodies, the
  drop helper and deallocation body, and the complete
  direct consumer census of all of them.
- Scope excluded: the parking layer's bit-level protocol
  on the token byte and its global table (open edge 1);
  the timeout provenance at park_timeout's call sites
  (open edge 3); any body whose only connection is
  sharing the generic drop helper for a different
  0x28-byte allocation.

## The question

Earlier RE-005 dispatcher traces left one object
unidentified: the lazy thread-local getter `0x5cdf300`
creates a 0x28-byte value object for the dispatcher's
cell at TLS base `-0x418`, the dispatcher forms a
`{table, payload}` handle out of it and hands the handle
to its phases, and nine other bodies call the same
getter — but what the value is, what protocol it runs,
and which consumers actually read it was carried over
unanswered. This packet settles the identity and the
protocol, and censuses the consumers completely.

## Identity — settled (observation + one labelled inference)

The getter (223 bytes, exported in the sibling trace
records as a pinned body) creates the allocation on
first use per thread: allocator call with size `0x28`
through slot `0x64df480`, then `[value+0x0] := 1`
(strong count), `[value+0x8] := 1` (weak count), the
0x18-byte payload at `+0x10` zeroed (`movups` over
`+0x10..+0x20`, byte `+0x20 := 0`), the cell's state
byte set, and a thread-exit destructor (glue
`0x5cdf3e0`, 43 bytes) registered through slot
`0x64e0510`. A racing second creator lock-decrements
the loser's strong count and drops it through the
helper (getter site `0x5cdf38a`).

All four operations on the payload panic through
Location statics in one source file —
`/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/runtime/park.rs`
(63-byte path string at `0x447492`; statics `0x64c6f48`
park 107:28, `0x64c6f30` park_timeout 153:28,
`0x64c6f18` park_timeout 173:18, `0x64c6f60` unpark
187:18, all `R_X86_64_RELATIVE` to the same path) —
with the messages "inconsistent park state",
"inconsistent park_timeout state" (twice) and
"inconsistent state in unpark". Inference: the value
is the shared parker state of the vendored tokio
runtime park module; the layout below is observation,
the module name is what the Location statics record.

Layout of the 0x28-byte allocation:

- `+0x0` strong count, `+0x8` weak count (Arc-style
  header, both created at 1).
- Payload at `+0x10`: park state word at `+0x10`
  (0 empty, 1 parked, 2 notified), waiter-token word
  at `+0x18`, mutex byte at `+0x20`.

The handle consumers share is the fat pair
`{vtable 0x64c6ef8, payload pointer}`. The table's
four `R_X86_64_RELATIVE` entries are `0x5cfdce0`
(clone: lock-inc the strong count at `[payload-0x10]`,
signed-overflow trap), `0x5cfd8c0` (unpark, then the
release protocol), `0x5cfd600` (unpark only) and
`0x5cfd5e0` (release: lock-dec the strong count, drop
helper at zero). This is the same table
`RE-001-node115-lu-qtable-slot8` characterised from
the waker side as {clone, wake, wake-by-ref, drop};
the two namings describe the same four entries — the
data pointer is the parker payload, so its wake is
this module's unpark. The dispatcher forms the pair
at `0x2ae1974..0x2ae1991` (load value pointer,
lock-inc its first qword, add `0x10`, store
`{0x64c6ef8, payload}` on the stack), and forms an
exit-path pair with the same table at `0x2ae1e0f`.
On any one thread, every getter caller
operates on the single allocation that thread's
getter created.

## (a) The drop chain — settled

The drop helper `0x5ce9190` (30 bytes, exported)
takes a pointer to a pointer slot. A pointer of `-1`
(the moved-out sentinel) returns at once. Otherwise
it lock-decrements the **weak** count at `+0x8`; only
at zero does it tail-jump through slot `0x64df4a0`
to the deallocation body `0x635de30` with
(pointer, size `0x28`, 0), freeing exactly the
allocation. Nothing in the chain closes, poisons or
destructs the payload — it is plain data with no
destructor. The order is fixed by the callers: the
strong owner lock-decrements `+0x0` itself (release
body, unpark_release's second half, the getter's
racing arm, the destructor glue) and invokes the
helper only when the strong count reaches zero, so
the helper's decrement is the second and final count.
The helper is generic over 0x28-byte Arc allocations:
it is reached only through slot `0x64e17f8`, with 18
boundary-verified `.text` references (9 calls, 9 tail
jumps); 5 of the 18 are in this value's own cluster
(getter `0x5cdf38a`, glue `0x5cdf3f6`, release
`0x5cfd5f3`, unpark_release `0x5cfd933` and its
landing pad `0x5cfd97d`), the other 13 drop other
allocations and are not this value's consumers.

## (b) The state-word protocol — settled

`park 0x5cfdb90` (321 bytes, exported) first tries
CAS 2→0 to consume a pending notification. Otherwise
it claims the mutex byte (CAS 0→1 on `+0x20`;
contention parks on the byte through the byte-wait
slot `0x64e01f8` → `0x5bb59d0`), CASes the word 0→1
to arm — a racing 2 is consumed by an xchg to 0
(byte released, return), any other old value panics
at park.rs:107 — then loops calling the
parking-table wait body `0x5bb4670` through slot
`0x64e73b8` with (key = `&+0x18`, byte = `&+0x20`,
timeout `0x3b9aca00` = 1e9 ns) until CAS 2→0
succeeds, and releases the byte (CAS 1→0, byte-notify
slot `0x64e0f38` → `0x5bb5650` on contention).

`park_timeout 0x5cfd9a0` (493 bytes, exported) runs
the same arming, computes a deadline with the clock
body `0x5c842e0` (clock id 1), and after the wait
stores 0 with xchg and requires the old value in
{1, 2}, panicking at park.rs:153 or park.rs:173
otherwise.

`unpark 0x5cfd600` (160 bytes, exported) stores 2
with xchg: old 0 or 2 returns; old 1 claims and
releases the byte (the registration barrier — the
byte is held across the whole park wait, so this
claim orders unpark against a registering waiter),
then, if the `+0x18` token word is non-zero,
tail-jumps through slot `0x64ec188` to the wake body
`0x5bb42e0` with (`&+0x18`, token snapshot); any
other old value panics at park.rs:187 (the panic
call's second argument is the constant `0x39`, the
same constant the RE-006 grow packet recorded; it is
not a byte length). `unpark_release 0x5cfd8c0`
(209 bytes, exported) is unpark followed by the
release protocol.

The dispatcher open-codes the whole sequence inside
its driver_c on the cell's value, at byte-pinned
sites (CAS 2→0 `0x2ae1f79`, byte claim `0x2ae1f8d`,
CAS 0→1 `0x2ae1f9c`, consume xchg `0x2ae1fdc`, wait
call `0x2ae1fbb`, retry `0x2ae1fc3`, byte release
`0x2ae1e72` with notify call `0x2ae1f1d`, byte-wait
call `0x2ae2005`, the same park.rs:107 panic arm at
`0x2ae2147`), and also calls the out-of-line park
once at `0x2ae1ac7`, before driver_a. Caller bodies
`0x5a34440` and `0x5a35480` open-code the same
sequence at their own pinned sites.

## (c) Counts, byte, token — settled

`+0x0` is the strong count: incremented by clone and
by handle-pair formation (dispatcher `0x2ae1977`,
`0x2ae1e0f`, and the guard clones in the caller
bodies); decremented by release, by unpark_release's
second half, by the getter's racing arm and by the
destructor glue. `+0x8` is the weak count: written
only at creation (:= 1) and by the drop helper's
decrement in every traced body — no weak-increment
site exists in the value's cluster, its table, or
the nine getter-caller bodies. Byte `+0x20` is the
parker's mutex byte: claimed CAS 0→1, released CAS
1→0, parking-table byte wait/notify on contention,
held across the whole park wait. Word `+0x18` is the
waiter token: the wait body registers a waiter by
storing the address of the value's own byte (`+0x20`)
into it (read `0x5bb4793`, store `0x5bb47e6` in the
exported wait body), so it is non-zero exactly while
a waiter is registered and its contents are that
byte's address; unpark snapshots it (`0x5cfd649`)
only on the parked path, and the wake body re-reads
it (`0x5bb42f9`), requires it unchanged, works on the
pointed-to byte's flag bits, and stores 0 back
(`0x5bb447b`, `0x5bb4542`) to deregister. The writer
census for `+0x18` is complete: {getter creation,
wait-body registration, wake-body deregistration};
no other store to `+0x18` exists in the dispatcher,
the protocol bodies, the table methods, or the nine
getter callers.

## The consumer mapping — who actually reads the value

Complete direct-call census (whole-`.text` rel32
scan, every candidate boundary-verified against its
containing FDE body's own disassembly; site lists in
`records.json`, containing bodies derived the same
way):

- **Getter `0x5cdf300`** — 20 direct call sites, no
  jumps, in 9 bodies: the dispatcher `0x2ae1690`
  (4 sites: `0x2ae1ad6`, `0x2ae1fea`, `0x2ae20a1`,
  `0x2ae21f7`); the open-coding caller bodies
  `0x5a34440` (2) and `0x5a35480` (2); the runtime
  bodies `0x158cdc0` (2) and `0x158f270` (2); and
  one body each at `0x2b149d0` (2), `0x5ab6df0` (2),
  `0x5cf27c0` (2) and `0x5cfd6a0` (2). These nine
  bodies are the complete consumer set of the cell;
  every one of them reaches the same per-thread
  allocation.
- **park** — 7 calls and 1 tail jump, one site in
  each of 8 bodies: the runtime bodies `0x158cdc0`
  (`0x158e6dc`) and `0x158f270` (`0x158f415`), the
  dispatcher (`0x2ae1ac7`), body `0x2b149d0`
  (`0x2b14bb4`), body `0x5ab6df0` (`0x5ab7137`), the
  538-byte body `0x5cfd6a0` immediately after unpark
  (`0x5cfd7f5` — the same body that fetches the
  parker through the getter twice), the forwarder
  `0x5cfdd00` (`0x5cfdf8b`), and the tail jump
  `0x5ce087c` in the 140-byte selector body
  `0x5ce0850`, whose one arm tail-jumps to park with
  the payload of the handle in its argument struct
  and whose zero arm tail-jumps to the `0x5cfdd00`
  forwarder with `ecx = 0x3b9aca00`.
- **park_timeout** — 3 calls and 1 tail jump, in 3
  bodies: body `0x5cf27c0` (`0x5cf29c8`), the
  forwarder `0x5cfdd00` (`0x5cfdeab`, `0x5cfdfa5` —
  it selects park vs park_timeout by comparing a
  field against `0x3b9aca00`), and the tail jump
  `0x5ce0193` in the matching 137-byte selector body
  `0x5ce0160`.
- **unpark** — exactly 2 direct calls, both in the
  open-coding caller bodies (`0x5a34bc8` in
  `0x5a34440`, `0x5a358b9` in `0x5a35480`); all other
  unparking happens through the table or inline
  copies.
- **release** — 6 direct calls in 3 bodies: caller
  body `0x5a34440` (2), caller body `0x5a35480` (2),
  body `0x5ab6df0` (2).
- **Never fetch the value themselves (negative)**:
  the selector bodies `0x5ce0850` / `0x5ce0160` and
  the forwarder `0x5cfdd00` contain no getter call —
  they receive the payload inside an argument
  structure from their callers.
- **No direct call or jump anywhere**: clone
  (`0x5cfdce0`), unpark_release (`0x5cfd8c0`), the
  wait body, the wake body, the drop helper, the
  deallocation body. The first two are reached only
  through the `{table, payload}` pair; the wait and
  wake bodies only through their slots
  (`0x64e73b8`, `0x64ec188`) from the protocol
  bodies and inline copies; the drop helper only
  through slot `0x64e17f8` (§a).
- **Receive-but-never-read (negative)**: driver_a
  `0x2ae41e0` and driver_c `0x2cde430` receive the
  `{table, payload}` pair inside their argument
  structures and, in the traced windows, never call
  its methods or lock its payload (driver_c's phase
  instead open-codes the protocol on the raw value —
  §b). Which structure fields carry the pair onward
  is open edge 2.

Censused non-value lock operations in the dispatcher
are excluded by pin, not by assumption: the
prologue's other TLS cell at `fs:[rbp+0x48]`
(rbp = `-0x1130`), the `[rsp+0x118]` object (lock inc
at `0x2ae1bb5`), the neighbouring TLS Arc at
`fs-0x428` (lock inc at `0x2ae1c34`, drop through a
different slot), and the exit pair at
`[rsp+0x48]`/`[rsp+0x50]`.

## Precise negatives and boundaries

- No type-name string for the value itself was
  found; the name-bearing statics pinned are the
  four park.rs Locations and the panic messages.
- The censuses above are direct-reference censuses.
  Indirect invocation through the `{table, payload}`
  pair (the only route to clone and unpark_release)
  leaves no `.text` reference to the method bodies
  and is therefore counted as reachability through
  the pair's formation and onward passage, not as
  call sites.
- Open edge 1 (`[wheel+0x30]` writer), 2 (runtime
  field contents) and 4 (gate re-invocation) of the
  earlier RE-005 wheel packets are a different
  object family (the timing-wheel entry) and are
  untouched here.

## Open edges

1. The bit-level protocol the parking layer runs on
   the token byte (which bits the wake body
   `0x5bb42e0` and the byte wait body `0x5bb59d0`
   set, test and clear at the byte the `+0x18` word
   points to, and how the global table at
   `0x64ec148` chains waiters under the golden-ratio
   address hash) is extent/digest pinned here, not
   settled; it is the direct continuation of this
   trace.
2. driver_a `0x2ae41e0` and driver_c `0x2cde430`
   receive the pair inside their argument structures
   and never use it in the traced windows; which
   structure fields carry the pair onward to its
   next consumer is not traced here.
3. park_timeout's three call sites pass timeout
   values this packet does not trace; the forwarder
   `0x5cfdd00` selects by comparing a field against
   `0x3b9aca00`, but the provenance of the timeout
   values stays open.
4. No type-name string for the value itself was
   found; a more specific source-level type name
   than "the shared parker state of the park module"
   is not recorded in the artifact.

## Reproduce

```sh
# with the node #115 artifact materialised at
# artifacts/node/115/hl-node (sha256 as above):
python3 tools/tls_value_object_static.py --generate   # writes this packet
python3 tools/tls_value_object_static.py              # verifies: {"matches": true}
python3 -m unittest tests.test_tls_value_object_static
```

Method note: every digest pin in the tool was
re-derived from the artifact during this packet's
preparation. Two hand-transcribed pins (wait_fn,
byte_notify) failed on first run and were corrected
to the artifact-derived values before generation;
all other pins, censuses, slot resolutions and byte
pins verified as drafted. Analysis is static only;
the artifact was not executed.

## Packet contents

- `records.json` — every derived record (owners,
  pinned bodies, slots, the table, Locations,
  messages, the call censuses, the drop-slot
  reference census, dispatcher rows, body structures,
  relocation references, findings, open edges).
- `frames.txt` — the FDE lines for the exported and
  pinned bodies.
- `drop_helper.objdump.txt`, `park.objdump.txt`,
  `park_timeout.objdump.txt`, `unpark.objdump.txt`,
  `unpark_release.objdump.txt`, `release.objdump.txt`,
  `clone_wrap.objdump.txt`, `dealloc.objdump.txt`,
  `clock.objdump.txt`, `wait_fn.objdump.txt`,
  `wake_fn.objdump.txt` — full Intel-syntax exports
  of the eleven owner bodies.
- `MANIFEST.sha256` — digests of the packet files.
- Tool: `tools/tls_value_object_static.py`;
  tests: `tests/test_tls_value_object_static.py`.
