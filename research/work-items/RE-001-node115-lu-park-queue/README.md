# RE-001: the node #115 lu.rs park-queue move — unlink, requeue-or-futex-wake, and a xorshift deadline

- Component: `base/src/lu.rs` conversion context, the park queue reached
  from the Q table's slot `+0x8` wake.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: packet #187 (PR #2179, open) left open a full decode of the
  park-queue function `0x5bb42e0`. Answer, in one paragraph: it is a
  move-or-wake primitive over a singly linked waiter list. It resolves a
  source queue through a hash-bucket lookup, checks that a slot still
  holds the expected item, unlinks the node keyed by that slot, and then
  either requeues the node into a second queue (when the item's flag
  byte has bit 0 set) or wakes it with a `futex` wake-private call and
  refreshes the source queue's deadline to now plus a xorshift jitter
  (when bit 0 is clear). It returns 1 when a node was handled and 0
  when nothing was. This packet cites #183 (PR #2106), #184 (PR #2125),
  #185 (PR #2137), #186 (PR #2158), and #187 (PR #2179, the inviting
  prior packet) as prior work; their bodies are cited, not re-claimed.
  The new bytes claimed here are the park body, the lookup body, and
  the cleanup body only.

## Correction of #187's size figure

Packet #187's `records.json` records the park callee as range
`0x5bb42e0..0x5bb4663` with 643 bytes. The range is right and the count
is wrong: `0x5bb4663 - 0x5bb42e0 = 0x383 = 899` bytes. 643 ends
mid-instruction inside the late release block (`0x5bb4563` falls inside
the `lock xadd` at `0x5bb4560..0x5bb4565`), so it marks no boundary.
The correct figures are: FDE 899 bytes, body proper to the single `ret`
758 bytes (`0x5bb42e0..0x5bb45d6`), unwind tail 141 bytes
(`0x5bb45d6..0x5bb4663`, release-cleanup blocks plus the overflow
panic). #187's "clamped at 10^9" shorthand for the jitter is likewise
corrected below: the code normalizes with a carry into seconds, it does
not clamp.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| park (characterized) | `0x5bb42e0..0x5bb4663` | 899 | 257 (incl. 2 nop paddings) |
| lookup (context) | `0x5bb4d00..0x5bb4f78` | 632 | — |
| cleanup (context) | `0x5bb66b0..0x5bb678b` | 219 | — |
| timer (context) | `0x5c842e0..0x5c843a9` | 201 | — |

All bodies are hash-pinned without normalization. Coordinates are ELF
virtual addresses (PIE); `.text` file offset = VA − 0x1000,
`.data.rel.ro`/`.got` file offset = VA − 0x2000, `.rodata` file offset = VA.
The park FDE's CIE is `0x00000000`; it has one `ret`, at `0x5bb45d5`.

## Signature and return contract

`park(rdi = slot pointer, rsi = expected item, rdx = destination queue) -> u8`:

| Return | Meaning |
| --- | --- |
| `0` | nothing handled: slot mismatch, empty source list, or node not found |
| `1` | a node was unlinked — requeued into the destination queue, or futex-woken |

The first call resolves the source queue: `lookup(rdi, rsi)` returns
`rbx`, a 64-byte bucket entry that doubles as the queue struct:

| Queue field | Meaning |
| --- | --- |
| `+0x0` | state word (claimed `0 -> 1`; released with `lock xadd -1`) |
| `+0x8` | list head (singly linked via node `+0x8`) |
| `+0x10` | list tail |
| `+0x18` | deadline seconds (qword) |
| `+0x20` | deadline nanoseconds (dword) |
| `+0x28` | xorshift32 seed (dword) |

The destination queue `rdx` has the same head/tail layout
(`[rdx+0x8]`, `[rdx+0x10]`); its deadline/seed fields are never touched
here. Every release site checks `rbx == rdx` first and skips the second
release when they are the same object.

## The lookup (context)

`0x5bb4d00` multiplies both arguments by the golden-ratio constant
`0x9e3779b97f4a7c15`, shifts each by `64 - [table+0x18]`, compares the
shifted values against the bucket count at `[table+0x8]`, and claims a
64-byte entry (`shl 6` stride) with `lock cmpxchg 0 -> 1`, retrying
through the `0x5bb6790` helper on contention. The table pointer
variable is at `0x64fff28` (via GOT `0x64ec148`). The lookup's own
release of a raced entry uses the same `lock xadd -1` idiom as the
park body, but branches the other way on the same condition (nonzero
→ retry the lookup; zero → proceed) — see the release section below.

## Slot check and item flag protocol

The body proper starts with the gate: if `[slot] != rsi`, it releases
`rbx` (and `rdx` when different) and returns 0. On match it reads the
flag byte at `[rsi]` — the first byte of the item object, not of the
list node:

- Bit 0 clear: proceed directly to the list walk with no flag write.
- Bit 0 set: spin `lock cmpxchg` to set bit 1 on that byte, then
  proceed. Bit 1 stays set on the requeue path below; the wake path
  never touches it.

What sets bit 0 in the first place is not established here; the two
paths below are keyed on the observed bit, not on an assumed meaning.

## List surgery

Nodes are keyed by their first qword and linked via `+0x8`. The walk
finds the first node whose key equals the slot pointer:

- Head hit: `[rbx+0x8] = [head+0x8]`; if the head was also the tail,
  `[rbx+0x10] = 0` (the list is now empty).
- Middle hit: `[prev+0x8] = [curr+0x8]`; if the removed node was the
  tail, `[rbx+0x10] = prev`.
- Miss (empty list, or walk exhausts): return 0 via the release path.

After any removal the body scans the remaining list for the slot key
again (`bpl` = found-again flag). The slot is cleared (`[slot] = 0`)
if and only if the key no longer appears in the source list; if it
still appears (the slot is queued twice), the slot is left intact.
This scan-and-clear rule is identical on both outcome paths.

## Outcome 1: requeue (flag bit 0 set)

The removed node's key is overwritten with the item pointer
(`[node] = rsi`), and the node is tail-appended to the destination
queue: if `[rdx+0x8] == 0` it becomes the head, else it is linked
after `[rdx+0x10]`; then `[rdx+0x10] = node`. No timer call, no futex
call, no deadline change. Return is `eax(0) | r13(1) = 1` (`r13 = 1` marks this
path). The destination queue's deadline and seed are untouched.

## Outcome 2: wake (flag bit 0 clear)

The removed node is not requeued. Its `+0x10` and `+0x20` fields are
cleared, and then:

1. The timer `0x5c842e0(edi = 1)` — a `clock_gettime` wrapper (GOT
   `0x64e1248` → `clock_gettime@GLIBC_2.17`) — returns now as
   `(rax = seconds, edx = nanoseconds)` for `CLOCK_MONOTONIC`.
2. If now is strictly greater than the stored deadline
   (`[rbx+0x18]`, `[rbx+0x20]`), compared as a (seconds, nanoseconds)
   pair, the deadline is recomputed: the seed at `[rbx+0x28]` runs
   xorshift32 (`x ^= x << 13; x ^= x >> 17; x ^= x << 5`, stored back),
   the result is reduced mod 10^6 with the magic multiply
   `0x431bde83` and shift 50, and the jitter is added to now's
   nanoseconds. If the sum reaches 10^9, seconds increment (with
   `inc; jo` to the overflow panic below) and nanoseconds drop by
   10^9 — a carry normalize, not a clamp. If now has not passed the
   stored deadline, the stored deadline is kept unchanged.
3. The tail call is `syscall(202, node+0x20, 0x81, 1)` — `futex` with
   `FUTEX_PRIVATE_FLAG | FUTEX_WAKE`, waking one waiter on the node's
   `+0x20` word (GOT `0x64e06b8` → `syscall@GLIBC_2.2.5`). The word's
   value was just cleared to 0; for a wake the value is irrelevant,
   only the address matters.
4. Return is `eax(1) | r13(0) = 1`, where the `1` is the value saved to
   the `[rsp]` spill before the timer call.

The overflow panic at `0x5bb464a` cites
`/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/time.rs:429:33`
with the 40-byte message `overflow when adding duration to instant`.
That message confirms the deadline reading independently of the
arithmetic: the recompute is an `Instant + Duration` addition, and the
trap fires on signed overflow of the seconds increment (`inc; jo` —
a full `u64` wrap would not trap, only `i64::MAX + 1` does).

## The release idiom and the cleanup helper (mechanical)

Six sites in the park body (plus one in the lookup) release a queue
word with `lock xadd -1` and branch on `(old & 2) >> 1 | (old < 4)`:

- Park: when the result is zero (`old >= 4` and bit 1 clear), call the
  cleanup helper via GOT `0x64ec150` (→ `0x5bb66b0`); otherwise
  continue. The lookup's raced-release site uses the same condition
  with the opposite sense (it retries the lookup instead).
- Cleanup `0x5bb66b0` (219 bytes): if `[rdi] < 4` or bit 1 is set, it
  returns at once. Otherwise it `lock cmpxchg`-sets bit 1, unlinks one
  node from the list rooted at `old & ~3`, clears bit 1, and
  futex-wakes one waiter on that node's `+0x18` word — a different
  futex field from the park body's `+0x20`, so the two helpers operate
  on different node shapes and must not be conflated.
- The `0x5bb6790` helper (329 bytes, used by the lookup on contention)
  shows bit 0 is a lock bit: it `lock cmpxchg`-sets bit 0 to acquire,
  spins with `pause` backoff, and after 10 rounds falls back to a
  futex wait on a queue derived from `old & ~3`.

The full entry-word lifecycle is left open: the claim value is `1`,
yet both helpers mask `old & ~3` to recover a pointer, so the word
must gain pointer bits somewhere between claim and cleanup. Nothing in
this packet asserts whether the word is a count, a tagged pointer, or
both at different times; the release condition and branch targets above
are the observed facts.

## Call-site census: who calls the park function

Direct `E8` callers: none (byte scan over all of `.text`, every hit
checked). All calls go through GOT slot `0x64ec188` (→ `0x5bb42e0`):

| Site | Caller | Arguments established by the caller |
| --- | --- | --- |
| `0x5cfd965` | wake `0x5cfd8c0` (#187) | `rdi` = &stored-item slot (`rbx + 0x8` after `rbx = payload`), `rsi` = stored item (loaded at `0x5cfd91d`); so the slot check passes by construction |
| `0x5cf521b` | FDE `0x5cf5100..0x5cf55d7` (1239B) | `rdi` = `r14 + 0xc8`, `rsi` = `[r14+0xc8]` loaded before the add — the same slot-plus-value shape as the wake site |
| `0x5cf4e8e` | FDE `0x5cf47f0..0x5cf50f2` (2306B) | `rdi` = `[r14+0xb8]` only; `rsi`/`rdx` not traced in this packet |

One honest gap at the wake site: the wake's own code never writes
`rdx` before the call, so `rdx` (the destination queue) flows through
from the wake's entry — or from the wait helper's return on the
wait-retry path — and is not established by the wake body itself. The
park body dereferences `rdx` on both outcome paths, so a complete
wake-site attribution still needs the wake caller's `rdx` setup. That
is exactly why #187's second next-question option (a table-indirect
slot-`+0x8` call site) remains open: table-indirect calls are generic,
and this packet attributes GOT calls, not a table-slot invocation.

## What this does not claim

- The Rust type/trait names of the queue, the node, and the item are
  not asserted; the "park queue" label is a behavior description from
  the futex + deadline + jitter mechanics, not a symbol.
- The item flag bit 0/bit 1 meanings (queued? locked?) are not proven;
  only their branch effects are claimed.
- The entry-word encoding (claim `1` vs `old & ~3` pointer mask) is
  unresolved, as stated above.
- The lookup's table-resize path and the cleanup's list shape are
  context only, not fully decoded.
- No static site is attributed to a table-indirect slot-`+0x8` call;
  the wake entry's liveness still rests on table membership.
- No gate is requested by this packet; the next question is either
  the entry-word lifecycle (what turns the claim value `1` into a
  pointer-bearing word, and what raises it to `>= 5`), or the
  wake-site `rdx` setup that would complete a slot-`+0x8` attribution.
