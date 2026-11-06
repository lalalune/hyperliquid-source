# RE-005 node115 timeout-cache count +0x148: the owner handle is the registry entry record itself

## Question

The timeout-cache object-fields packet (#2953,
`RE-005-node115-timeout-cache-object-fields`) pinned the
registry entry object cached at `0x64fee08` (vendored tokio
signal registry, signal 17 / SIGCHLD): Arc counts `+0x00`/
`+0x08`, nine `sync::Notify` wait cells, the claim word
`+0x130`, the event counter `+0x138` and two handle counts
`+0x140` and `+0x148`. For `+0x140` it found the getter's
`lock inc` and two `lock dec` sites. For `+0x148` it found
exactly one decrement site in `.text` (the drop body
`0x5cfc8f0`), no `lock inc` site anywhere, and left the edge
open: which handle type owns the `[obj+0x148]` count on the
registration side — which registration call creates it, and
as what kind of handle?

## Answer

The owner is the registry entry record itself — the
0x20-byte element of the per-signal Vec that the registry
globals construction builds. The count is a non-cloneable
ownership token minted once per signal at construction time;
no registration call ever increments, clones or otherwise
creates it.

### The entry record (Vec element, 0x20 bytes)

| record offset | field | evidence |
|---|---|---|
| +0x00 | entry-object pointer | stored by the constructor-grower `0x5cfe910` at `0x5cfe9b0` |
| +0x08 | pending byte | zeroed by the grower (`0x5cfe9b3`); atomically swapped out by the driver drain `0x5ce7380` before each delivery (`0x5ce7496`) |
| +0x10 | registration cell (16 bytes) | tag dword at `+0x10`, registration-id dword at `+0x14`; written only by the entry-init bodies (`0x5cdf4c6`/`0x5cdf4c8`, direct form `0x5cdf696`/`0x5cdf698`) |
| +0x18 | embedded `std::sync::Once` state word | initialised to 3 by the grower (`0x5cfe9b8`); validated on record drop by the count's drop body against the panic Location `std/src/sys/sync/once/futex.rs:91` ("internal error: entered unreachable code: invalid Once state") |

### Creation: the registry construction chain, not a registration

The grower initialises `[obj+0x148]` to 1 in the same pass
that writes the three record fields above (`0x5cfea0b`). Its
only caller is the Vec builder `0x5ce1320`, whose only caller
is the registry constructor wrapper `0x5cfcec0`, whose only
callers are the two globals-init forms (closure `0x5cdf4f0`,
direct `0x5cdf6c0`) reached from the OnceCell accessor
`once_globals 0x5cdf582`. An extended whole-`.text` census of
every lock-prefixed read-modify-write form a Rust atomic can
take on a memory operand (inc/dec, add/sub/or/and with imm8
or imm32, xadd, cmpxchg) with displacement `0x148` finds
exactly one site: the decrement in `0x5cfc8f0`. The raw
displacement bytes `48 01 00 00` occur inside every pinned
body that can hold the entry-object pointer only at the
grower's init store and at that decrement — the only other
occurrences, inside the registry insert body, are
rsp-relative stack slots (byte-pinned). Contrast `+0x140`:
the same census shows it incremented by the getter
`0x5cfcf90` (panic Location
`z_vendor/tokio/src/signal/registry.rs:73`) and decremented
by the pair-drop `0x5cee390` and the refresh `0x5cee650` —
that count belongs to the transient lookup pair the getter
hands out, not to the registry's own record.

### Release: only the Vec drop glue, only on construction unwind

The entry-Vec drop glue `0x5cfc9c0` (new pin) walks the Vec
buffer forward in 0x20-byte strides, calling the count's
drop body once per record (two call sites in the glue: the
normal loop `0x5cfc9ed` and its own unwind loop `0x5cfca3d`),
then frees the buffer through the dealloc slot `0x64df4a0`.
A whole-`.text` direct-branch census shows the glue's only
callers are the constructor-grower's landing pad (`0x5cfeb2b`)
and the Vec builder's landing pad (`0x5ce1398`), the drop
body's only callers are the glue's two sites, and no
`.rela.dyn` addend names either body. On successful
construction the Vec moves into the registry globals OnceCell
(`0x64fee20`: vec pointer `0x64fee28`, length `0x64fee30` —
referenced only by the lookup `0x5cde710` and the drain) and
is never dropped. So in every reachable non-unwind execution
`[obj+0x148]` stays at its construction value 1, and the drop
body's zero-transition (set the sticky bit 0 of
`[obj+0x138]`, run the eight-cell drain callback once, drop
the strong count) is reachable only when registry
construction itself unwinds.

### The registration side never touches the count

When the lookup finds a record whose Once state word is
nonzero it runs the record's once shim `0x5cdf535` (new pin),
which invokes std's once slow-path helper (GOT slot
`0x64df9f0`, body `0x5c87d50`) once per record. The init body
it runs — the cluster holds a closure form `0x5cdf460` and a
direct form `0x5cdf630` of the same body, and the direct-
branch census shows these two are the insert's only callers —
calls the vendored signal-hook-registry table insert
`0x5cdbf20` and stores only the outcome tag/id pair into the
record's `+0x10` registration cell. The insert's own
allocation is a separate 0x20-byte Arc object (counts 1/1
written at `0x5cdbf83`, the globals pointer at `+0x10`, a
token dword at `+0x18`) — not the entry object. The creation
the parent packet located "in the signal-hook-registry half
of the vendored code" is therefore the registry-construction
cluster itself: the count is owned by the registry's
per-signal entry record, created when the registry globals
are built, and discharged only if that construction unwinds.

## Open gaps

- Whether the vendored fork's lazy registration can write a
  record's `+0x10` cell on paths other than the lookup's:
  the cell semantics are pinned for the lookup path only.
- The producer of the global signal fd at `0x64fee24` is a
  separate open edge (owned by another packet); it is not
  addressed here.

## Files

- `records.json` — every pin below in canonical JSON form.
- `../../tools/timeout_cache_count148_owner_static.py` —
  re-derives all pins from the materialised artifact
  (`analyze()`): PT_LOAD map, FDE ranges and sha256 of 23
  bodies, `.rela.dyn` resolution of six GOT slots, three
  panic Locations plus the std Once message bytes, 46 byte
  pins, the globals RIP-reference census, the direct-branch
  caller census for eleven control-flow targets, the
  extended lock-RMW displacement census, the pinned-body
  disp-`0x148` byte-pattern scan, and the `.rela.dyn`
  addend check for the drop bodies.
- `../../tests/test_timeout_cache_count148_owner_static.py`
  — compares the recomputed analysis against `records.json`
  and asserts the census conclusions directly (6 tests).
- `MANIFEST.sha256` — hashes for this packet folder.
