# RE-001: what the node #115 lu.rs Q table's slot +0x8 calls — the consuming wake of a four-slot waker table

- Component: `base/src/lu.rs` conversion context pointer, answered through the
  Q table's slot `+0x8`.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: packet #186 (PR #2158, open) left open what the Q table's slot
  `+0x8` calls, needing a static Q-table instance or a coop-site Q
  construction trace. Answer, in one paragraph: the static table at
  `0x64c6ef8` has four slots — clone (`0x5cfdce0`), wake (`0x5cfd8c0`),
  wake-by-ref (`0x5cfd600`), drop (`0x5cfd5e0`) — and slot `+0x8` calls
  the 209-byte wake function `0x5cfd8c0`. It atomically takes the deferred
  item (state word `xchg` to 2, guard-byte lock with a 10^9-ns timeout wait
  loop), hands the stored item to the shared 643-byte park-queue function
  `0x5bb42e0`, and then releases one cell refcount before returning. It is
  the consuming twin of slot `+0x10`: slot `+0x10` runs the same take
  sequence but tail-jumps to `0x5bb42e0` with no refcount touch. This
  packet cites #183 (PR #2106), #184 (PR #2125), #185 (PR #2137), and #186
  (PR #2158, the inviting prior packet) as prior work; their bodies are
  cited, not re-claimed. The new bytes claimed here are the four table
  slot bodies and the table record only.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| slot +0x0, clone (characterized) | `0x5cfdce0..0x5cfdcf4` | 20 | 6 |
| slot +0x8, wake (characterized) | `0x5cfd8c0..0x5cfd991` | 209 | 61 |
| slot +0x10, wake-by-ref (characterized) | `0x5cfd600..0x5cfd6a0` | 160 | 48 |
| slot +0x18, drop (characterized) | `0x5cfd5e0..0x5cfd5fb` | 27 | 9 |

All bodies are hash-pinned without normalization. Coordinates are ELF
virtual addresses (PIE); `.text` file offset = VA − 0x1000,
`.data.rel.ro`/`.got` file offset = VA − 0x2000, `.rodata` file offset = VA.

## The static table: four slots, resolved through relocations

The table at `0x64c6ef8` is 32 bytes in `.data.rel.ro`; its file slots are
zero and the targets resolve through RELATIVE relocation addends:

| Slot | Target | Role, from its body |
| --- | --- | --- |
| `+0x0` | `0x5cfdce0` | clone: `lock inc [rdi-0x10]`, returns `(table, payload)` |
| `+0x8` | `0x5cfd8c0` | wake (consuming): take + invoke + refcount release |
| `+0x10` | `0x5cfd600` | wake-by-ref (borrowing): take + tail invoke, no refcount touch |
| `+0x18` | `0x5cfd5e0` | drop: `lock dec [rdi-0x10]`, finalizer at zero |

The next record at `0x64c6f18` resolves to the `park.rs` file string and
begins a run of Location records — it is not a fifth table slot. The four
slots' order and bodies match the `RawWakerVTable` layout (clone, wake,
wake-by-ref, drop) exactly; that identification is inference from the
layout plus the park evidence below, not from a symbol name, and the Rust
type name of the woken item is not asserted.

## The cell model the four slots share

Every slot takes `rdi` = payload, where payload = cell + `0x10`:

| Cell offset | Field |
| --- | --- |
| `+0x0` | strong refcount (`lock inc` in clone, `lock dec` in wake/drop) |
| `+0x8` | second count (finalizer `0x5ce9190` decrements it; zero frees) |
| `+0x10` | state word: 0, 1, or 2 (the payload itself) |
| `+0x18` | stored item (the deferred thing to wake) |
| `+0x20` | guard byte (low byte of the proceed queue's guard word) |

The two proceed direct callers (#185) build exactly this shape:
`lock inc [cell]`, payload = cell + `0x10`, table = `0x64c6ef8`. The
helper `0x5cf2d30` (#184) builds the same pair at `0x5cf280c`
(`lock inc [cell]`, payload = cell + `0x10`, table `lea` to `0x64c6ef8`).

## Slot +0x8, the wake: take, invoke, release

`0x5cfd8c0` (209 bytes, 61 instructions, landing pad `0x5cfd96d..0x5cfd991`):

- Prologue saves the cell (`lea rax, [rdi-0x10]`, `[rsp]` = cell) for the
  cleanup at the end — the one structural difference from slot `+0x10`,
  which saves nothing.
- `mov eax, 2; xchg [rdi], rax` takes the state word: old `1` runs the
  wake work; old `0` or `2` skips straight to the refcount cleanup; any
  other old value panics through GOT `0x64df6b8` (→ `0x1680e80`) with the
  57-byte message at `0x94dc34` and the `park.rs:187:18` Location
  (`0x64c6f60`, file string `0x447492`, 63 bytes).
- Wake work: acquire the guard byte at `[payload+0x10]` (`lock cmpxchg`
  0→1); on failure call the timeout-wait helper via GOT `0x64e01f8`
  (→ `0x5bb59d0`) with (guard pointer, `0x3b9aca00` = 10^9 ns) and retry.
  Then release the guard (`lock cmpxchg` 1→0); on failure call the notify
  helper via GOT `0x64e0f38` (→ `0x5bb5650`) with (guard pointer, 0) and
  continue. The wait/notify labels are inference from the call shapes
  (pointer + timeout / pointer + 0) plus the park context; the helpers'
  internals are not decoded.
- Then `rsi = [payload+0x8]` (the stored item); if nonzero, call the
  shared park-queue function via GOT `0x64ec188` (→ `0x5bb42e0`) with
  `rdi` = &stored-item slot. `0x5bb42e0` (643 bytes, context, not fully
  decoded) walks a waiter list (head `[rbx+0x8]`, tail `[rbx+0x10]`, next
  `[node+0x8]`) and computes a xorshift timeout jitter (seed `[rbx+0x28]`,
  mod 10^6, plus `edx`, clamped at 10^9).
- Cleanup: `lock dec [cell]`; if it reaches zero, call the finalizer via
  GOT `0x64e17f8` (→ `0x5ce9190`, 30 bytes: second count at `[cell+0x8]`,
  dealloc via GOT `0x64df4a0` → `0x635de30` with `esi` = `0x28`) with
  `rdi` = `rsp`, then return. The landing pad runs the same cleanup and
  resumes unwinding (its trailing call goes through GOT `0x64df4c0` →
  `0x1680cab`). The finalizer's `0x28` argument is reported as
  observed, not interpreted as the cell size: the proceed queue struct at
  cell + `0x20` extends past `0x28`.

## Slot +0x10, the borrowing twin: same take, no release

`0x5cfd600` (160 bytes, 48 instructions) is the same take sequence with
two differences: it never saves the cell, and after the stored-item step
it tail-jumps to `0x5bb42e0` instead of calling and cleaning up. Its
old-`0`/old-`2` paths are plain returns (no refcount touch at all), and
its wait-retry differs mechanically: after a timeout wait it attempts
the 1→0 release directly, where slot `+0x8` retries the 0→1 acquire.
So the table's two wake entries differ exactly by ownership: slot `+0x8`
consumes one refcount (wake), slot `+0x10` borrows (wake-by-ref).

## The other two slots, for completeness

- Clone `0x5cfdce0` (20 bytes, 6 instructions): `lock inc [rdi-0x10]`
  (refcount up, `ud2` if the old value was negative), then returns the
  pair `(rax = table 0x64c6ef8, rdx = payload)`. This is what the
  proceed dedup cache stores: it calls slot `+0x0` and keeps the returned
  pair as the new cache entry.
- Drop `0x5cfd5e0` (27 bytes, 9 instructions): `lock dec [rdi-0x10]`;
  at zero it calls the finalizer `0x5ce9190` with `rdi` = `rsp` (the
  saved cell pointer), then returns. No state word, guard, or item touch.

## Census: who references the table and the slots

Table `lea` sites (byte scan over `.text`, every hit confirmed by
objdump): 11 total — `0x158ce16`, `0x158f2b1`, `0x2ae1985`, `0x2ae1e1d`,
`0x2b14a71`, `0x5a34771` and `0x5a35531` (the two proceed direct
callers), `0x5ab6e8f`, `0x5cf280c` (the helper's own pair construction),
`0x5cfd6e1`, and `0x5cfdce7` (inside clone itself, returning the table).

Direct `E8` callers (byte scan, every hit confirmed by objdump):

| Slot | Direct callers | Why |
| --- | ---: | --- |
| clone `0x5cfdce0` | 0 | reached only through the table |
| wake `0x5cfd8c0` | 0 | reached only through the table |
| wake-by-ref `0x5cfd600` | 2 | `0x5a34bc8`, `0x5a358b9` — see below |
| drop `0x5cfd5e0` | 6 | `0x5a34c99`, `0x5a35313`, `0x5a35aa5`, `0x5a35f12`, `0x5ab7197`, `0x5ab7296` |

The two wake-by-ref callers are the proceed callers' fallback paths:
each branches on `[cell+0x18] == 0` to a direct slot-`+0x10` call with
`rdi` = payload (`[rsp+0x38]` in both), skipping the proceed deferral
when the stored item slot is empty. The consuming wake (slot `+0x8`)
has no direct caller and no static call site is attributable to it:
like #186's `[vtable+0x18]` method call, table-indirect calls are
generic, so the wake path is live by table membership, not by a traced
call site.

## What this does not claim

- The Rust type/trait names of the table, the cell, and the woken item
  are not asserted; the `RawWakerVTable` reading is a layout match, not
  a symbol.
- The park-queue function `0x5bb42e0`, the wait helper `0x5bb59d0`,
  the notify helper `0x5bb5650`, and the finalizer's dealloc size
  argument are not fully decoded.
- No static site is attributed to a slot-`+0x8` call; the wake entry's
  liveness rests on table membership and the FDE record.
- No gate is requested by this packet; the next question is either a
  full decode of `0x5bb42e0` (park-queue wake mechanics and its timeout
  jitter) or an attribution of a table-indirect slot-`+0x8` call site.
