# RE-005 node115: the four slots after the tokio Debug vtable are a RawWakerVTable

Question left open by RE-005 node115 shared Debug vtables
(PR #3141): the io-error Debug vtable at `0x64c6458` measured
extent `0x40` — the "tokio exception" — and its four local slots
at +0x20/+0x28/+0x30/+0x38 were recorded with targets but no
trait. What trait do those four slots serve?

## Answer

None — they are not methods of that vtable. The compiler vtable
at `0x64c6458` is a standalone `dyn Debug` vtable for the 8-byte
tagged io-error value (drop `0x5cee460`, size 8, align 8, shared
Debug stub `0x5ca5610` at +0x18), true extent `0x20` like the
other 18 standalone-family members. The extent heuristic used
by the earlier packet (extend while cells resolve to FDE
starts) ran past it because the next static in `.data.rel.ro`
is also four RELATIVE pointers to FDE starts: a
`core::task::RawWakerVTable` at `0x64c6478`, in core's field
order.

| field | cell | body | bytes | behaviour |
|---|---|---|---|---|
| clone | `0x64c6478` | `0x5cee5a0` | 20 | `lock incq` strong at data−0x80, `ud2` on overflow, returns (rax = `0x64c6478`, rdx = data) |
| wake | `0x64c6480` | `0x5cee590` | 10 | data−0x80, tail-jump to the consuming body `0x5cfc550` |
| wake_by_ref | `0x64c6488` | `0x5cee5c0` | 136 | xchg woken flag at data+0x150, thread-local consult, tail-call to the wake body on data+0x1c0; never touches the count |
| drop | `0x64c6490` | `0x5cee570` | 27 | `lock decq` strong at data−0x80; at zero calls the destroy body `0x5ce86d0` |

The consuming wake body `0x5cfc550` (193 bytes) sets the same
flag at alloc+0x1d0, consults the same thread-local context,
calls the I/O-driver wake body `0x5ce09a0` on the sub-object at
alloc+0x240 when the current context is foreign, and then
decrements the strong count — wake consumes the reference, as
the RawWaker protocol requires. The offset identities
data+0x150 == alloc+0x1d0 and data+0x1c0 == alloc+0x240 hold
with data = alloc+0x80.

## The allocation

The destroy body `0x5ce86d0` (389 bytes, reached through GOT
`0x64dfdb8`) is the inner type's `drop_in_place`: strong count
at +0x00, weak count at +0x08, allocation size `0x300` (its
final dealloc), field drops at +0x100, +0x170 (a Vec of
24-byte elements), +0x200, +0x210, +0x238, +0x240 (the wake
target: fallback state pointer at +0x00, fd checked against −1
at +0x44) and +0x2e0. None of the four waker functions
dereferences the 8 bytes at the data pointer itself; every
access is relative (count −0x80, flag +0x150, wake target
+0x1c0).

The allocation is the tokio I/O driver's shared inner state:
the wake body both entries funnel into is the one whose
`expect` panics `failed to wake I/O driver`
(tokio/src/runtime/io/driver.rs:272). That same body explains
the neighbouring vtable's reference census — its panic path
passes the Debug vtable `0x64c6458` to the panic helper
(`0x1680c30`, via GOT `0x64df6a0`), whose format shim
(`0x1687260`) dispatches only the vtable's +0x18 slot.

## Census

- RawWakerVTable base `0x64c6478`: referenced exactly once in
  the binary — the `lea` inside clone that returns it. No
  RELATIVE addend names it.
- Debug vtable `0x64c6458`: referenced exactly at the seven
  panic-format sites already pinned by #3141, all in
  `expect`-style formatting paths; no other lea, movabs or
  addend reference exists.

## Validation

`tools/tokio_waker_table.py generate` re-derives every pin
from the materialized artifact (PT_LOAD/section mapping,
RELATIVE relocation resolution, FDE extents, body byte
patterns, GOT resolutions, lea census) and fails on any
drift; `check` compares the regenerated records against the
retained `records.json`. `tests/test_tokio_waker_table.py`
re-runs the analysis, verifies the MANIFEST over all packet
files, the field order and offset identities, and rejects
mutated body bytes.

## Limitations

- No DWARF type names exist in the binary. The allocation is
  attributed to the tokio I/O driver's inner state from the
  wake body's panic location and the pinned field layout,
  not from a name.
- The thread-local cell the wake paths consult (TLS slot
  −0x1130, access helper `0x5ca0d20`, key `0x5cdf410`) is
  pinned by its consult pattern only; the parker value object
  behind it is #2935's subject and is not re-identified here.
- The role (if any) that other code gives the field at the
  data pointer (alloc+0x80) is out of scope: the waker
  functions never read it.
- Static records only; nothing was executed.
