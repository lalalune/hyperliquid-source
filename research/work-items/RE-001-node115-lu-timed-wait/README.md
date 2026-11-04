# RE-001: the node #115 lu timed wait — enqueue, futex-wait with a deadline, and the wake-drain

- Component: `base/src/lu.rs` conversion context, the hash-bucket entry-word
  family shared by the park queue, the lookup, and the cleanup helper.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: packet #189 (PR #2197, open) left open decoding one family
  function end to end, naming the 4525-byte FDE `0x5bb2440` (three helper
  call sites) as the largest candidate, to see the word-chain pop path
  from the inserter side. Answer, in one paragraph: `0x5bb2440` is the
  inserter-side timed wait. It takes a slot pointer and a deadline, spins
  the slot word into a workable state, lazily builds a waiter node, claims
  a hash bucket, enqueues the node on the bucket list, and futex-waits on
  the node's word with the deadline as timeout — untimed when the deadline
  nanos field is exactly `10^9`, otherwise recomputed from the remaining
  time on every wake. On timeout it calls the 417-byte timeout handler,
  unlinks itself, and returns 0. On wake it proceeds to a second wait
  phase on a per-thread node, and on that phase's timeout it drains the
  bucket: it collects every slot-keyed node into a 24-byte-entry vector,
  refreshes the bucket deadline to now plus a xorshift jitter, resets the
  collected nodes, and futex-wakes each one. This packet cites #183
  (PR #2106), #184 (PR #2125), #185 (PR #2137), #186 (PR #2158), #187
  (PR #2179), #188 (PR #2190), and #189 (PR #2197, the inviting prior
  packet) as prior work; their bodies are cited, not re-claimed. The new
  bytes claimed here are the `0x5bb2440` body only. The lookup, park,
  cleanup, contention-helper, table-creation, constructor, and
  deadline-add bodies are prior claims or context, referenced here by
  address for the transition sites.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | --- | ---: |
| timed wait (characterized) | `0x5bb2440..0x5bb35ed` | 4525 | 1164 (1144 excluding nop padding) |
| lookup (cited, #188) | `0x5bb4d00..0x5bb4f78` | 632 | — |
| park (cited, #188) | `0x5bb42e0..0x5bb4663` | 899 | 257 |
| cleanup (cited, #188) | `0x5bb66b0..0x5bb678b` | 219 | — |
| contention helper (cited, #189) | `0x5bb6790..0x5bb68d9` | 329 | 104 |
| table creation (context) | `0x5bb6400..0x5bb645f` | 95 | — |
| timeout handler (context) | `0x5bb3ca0..0x5bb3e41` | 417 | 107 |
| TLS check (context) | `0x5bb5130..0x5bb51fe` | 206 | — |
| vector grow (context) | `0x5bb5450..0x5bb5643` | 499 | — |
| constructor (context) | `0x5bb6070..0x5bb63f5` | 901 | — |
| deadline add (context) | `0x5ca94e0..0x5ca9528` | 72 | — |

All bodies are hash-pinned without normalization. Coordinates are ELF
virtual addresses (PIE); `.text` file offset = VA − 0x1000,
`.data.rel.ro`/`.got` file offset = VA − 0x2000. The timed-wait FDE's CIE
is `0x00000000`; it has one `ret`, at `0x5bb3486`. The body SHA-256 is
`4f25e4444597bae4621a1bbb55307355749ce1e2e970efdb90f4e47ed0de9f19`.
The tail `0x5bb3487..0x5bb35ed` is panic stubs (`ud2`) and
`_Unwind_Resume` landing pads, including the refcount decrement; the
panic message texts are not decoded here.

## Signature and arguments

`wait(rdi = slot pointer, rsi = deadline seconds, edx = deadline nanoseconds) -> u8`:

- `rsi` is saved to `[rsp+0x38]` and `edx` to `[rsp+0x14]`; the pair is
  compared against `clock_gettime` output as a (seconds, nanoseconds)
  pair on every wait iteration (expired when now is strictly greater).
- `[rsp+0x7]` records whether `edx != 10^9` (`0x3b9aca00`); that byte is
  stored into each waiter node's `+0x24` field as a has-deadline flag.
- The slot pointer is saved to `[rsp+0x8]`; its golden-ratio hash
  (`rdi * 0x9e3779b97f4a7c15`, the same constant as #188's lookup) is
  saved to `[rsp+0x30]` and selects the drain-phase bucket, while the
  second phase hashes the tagged pointer `slot | 1` and waits on a
  different bucket.
- Return: `0` when the drain completes or the first phase exits by
  timeout/unlink; `1` when the second spin loop finds the slot word
  below `0x10` (not pointer-bearing).

## The slot-word spin loops

Two spin loops precede the waits, both with the helper's backoff shape
(`2^(round+1)` pauses per round, `sched_yield` from round 3, via GOT
`0x64e1558`):

1. **First loop** (`0x5bb24a8..0x5bb27cf`, up to 10 rounds): on the slot
   word it sets bit 3 (`0x8`) with `lock cmpxchg` when bits 2..3 are
   clear (sites `0x5bb2747`, `0x5bb2777`); it pauses/yields while bits
   0..1 are clear; after 10 rounds it acquires bit 0 (`lock cmpxchg`
   `or 0x1`, sites `0x5bb275d`, `0x5bb2795`) or proceeds when bit 0 is
   already set. Bit 3's meaning is not established here. Success lands
   at `0x5bb2a0a`, which requires the word to be `>= 0x10`
   (pointer-bearing) and then hashes `slot | 1` for the second phase.
2. **Second loop** (`0x5bb2a70..0x5bb2b0e`, counter at `[rsp+0x18]`,
   up to 10 rounds): it spins while the slot word stays `>= 0x10`; if
   the word drops below `0x10` the function returns `1`
   (`0x5bb2f0d`); if 10 rounds elapse it sets bit 1 (`lock cmpxchg`
   `or 0x2` at `0x5bb2ad7`, the cleanup-in-progress bit per #189) and
   proceeds.

Both loops consult a TLS gate before the lookup: the byte at
`fs:[-0x4b0]` must be `1`, and the 206-byte check at `0x5bb5130`
(TLS struct at `fs:0 - 0x4d8`, saved to `[rsp+0x20]`, second argument
`0`) must return nonzero; otherwise the loop retries. The check's
semantics (budget? readiness?) are not asserted.

## The waiter nodes (one layout, two homes)

The first phase waits on a lazily built stack node at `[rsp+0x138]`; the
second phase waits on the per-thread node at the TLS struct
(`[rsp+0x28] = [rsp+0x20]`). Both share this layout:

| Offset | Content |
| --- | --- |
| `+0x0` | key: the slot pointer (first phase) or `slot \| 1` (second phase) |
| `+0x8` | list link, `0` at enqueue |
| `+0x10` | status word, read at first-phase exit (see below) |
| `+0x18` | `8` at enqueue |
| `+0x20` | futex word, `1` while waiting |
| `+0x24` | has-deadline byte (`edx != 10^9`) |

The stack node is built by the 901-byte constructor at `0x5bb6070`
(GOT `0x64ec170`, called at `0x5bb2527` and `0x5bb2cc9`), which fills
40 bytes at `[rsp+0x68..0x90]` copied to the node; the copy is guarded
by the `[rsp+0x130]` initialized flag, and every exit path (plus the
unwind pads) runs `lock dec` on the refcount variable at GOT
`0x64ec168` (→ `0x64fff20`) when the flag is set. The constructor's
individual field values are context only, not decoded here.

Enqueue is the same in both phases: claim the bucket with the
#188 lookup shape (table variable GOT `0x64ec148` → `0x64fff28`,
bucket count `[table+0x8]`, shift `64 - [table+0x18]`, 64-byte stride,
`lock cmpxchg 0 -> 1`, contention helper GOT `0x64ec160` on race,
table creation GOT `0x64ec158` → `0x5bb6400` when the table is null,
release-then-cleanup on table change), then tail-append the node to
the bucket list (`[bucket+0x8]` head, `[bucket+0x10]` tail) and release
the bucket word with `lock xadd -1`, calling cleanup (GOT `0x64ec150`
→ `0x5bb66b0`) exactly when the old value is `>= 4` with bit 1 clear.

## The futex wait: deadline sentinel and remaining time

Each phase waits on its node's `+0x20` word with `syscall(202, word,
0x80, 1)` (`FUTEX_WAIT_PRIVATE`, GOT `0x64e06b8` → `syscall@GLIBC_2.2.5`).
There are 5 futex call sites in this FDE: 3 GOT-direct (first-phase
timed wait `0x5bb25d5`, second-phase timed wait `0x5bb2d75`, drain
wake `0x5bb33f4`) and 2 register-indirect through a GOT-loaded
`syscall` pointer (first-phase untimed wait `0x5bb29b7`, second-phase
untimed wait `0x5bb2c8a`).

The deadline sentinel: when the deadline nanos field equals exactly
`10^9`, the wait is untimed (NULL timeout, looping while the word is
nonzero). Otherwise the wait is timed:

1. `clock_gettime` wrapper `0x5c842e0` (`CLOCK_MONOTONIC`) returns now.
2. If now has not passed the stored deadline, the remaining time is
   computed by `0x5c84210` (deadline in, remaining out at `[rsp+0x68]`)
   and the futex wait uses that timespec (`r8 = [rsp+0x70]`).
3. If now has passed the deadline, the timeout path runs: the 417-byte
   handler `0x5bb3ca0` is called with the node, the node is unlinked
   from the bucket list by a key walk, the bucket is released (cleanup
   if the release condition fires), and the phase exits.

The first-phase exit block (`0x5bb29c1`) reads the node's `+0x10`:
`al = ([node+0x10] == 1)`. If `al == 1` the function proceeds to the
second phase (`0x5bb2a0a`); if `al == 0` it retries the first spin
loop (`0x5bb24e0`). Which writer sets `+0x10` to `1` is **not**
established in this FDE — the drain phase writes `0` there (below),
and the constructor fills `+0x10..+0x20` opaquely — so the `+0x10`
signal is reported as an observed branch, not an interpreted one.
The first phase's other exits are by state: release → retry the first
phase; unlink (timeout) → return `0`.

The second phase's exits are by flag: timeout/unlink → drain
(`0x5bb2f14`); woken → retry the second spin loop. Its exit path
first runs `lock xadd -10` on the slot word (`0x5bb2f14`): `-10`
exactly reverses the `+8` set by the first spin loop and the `+2` set
by the second, and the old bit 0 decides the outcome — clear means
return `0`, set means enter the drain with claim value `1`.

## The drain: collect, refresh, reset, wake

The drain claims the bucket for the original (untagged) hash with value
`1`, then walks the bucket list from `[bucket+0x8]`, unlinking every
node whose key equals the slot pointer (link-pointer walk with tail
fixup) and appending it to a vector of 24-byte entries
`{node, flag, futex-ptr}`:

- Inline capacity is 8 entries at `[rsp+0x68]`; the 9th push grows to
  a heap buffer via the 499-byte grow function `0x5bb5450`; the count
  is tracked at `[rsp+0x128]` while inline and at `[rsp+0x70]` once
  heap-allocated (the post-walk count is the inline count when it is
  below 9, else the heap count).
- The walk sets the wake flag at `[rsp+0x18]` to `1` when a collected
  node's `+0x18` field has bits `0xc` set while the walk accumulator's
  bit 2 is set. The accumulator starts at `0x14` and adds each
  collected node's `+0x18` value, but its final value is not consumed
  after the walk. Every node enqueued by this protocol has `+0x18 =
  8`, and `8 & 0xc != 0`, so the flag is set by the first
  protocol-shaped node collected. A test of the accumulator's bit 3
  (`0x5bb304a`) cannot fire given the accumulator's reachable values
  (`0x14`, then `1`) and is dead in this instantiation.
- If the vector is nonempty, the bucket deadline is refreshed when now
  exceeds it: the seed at `[bucket+0x28]` runs xorshift32 (`13/17/5`,
  stored back), reduced mod `10^6` with the magic multiply
  `0x431bde83` and shift `50`, and the 72-byte deadline-add helper at
  `0x5ca94e0` (GOT `0x64ec178`) computes `(now secs, now nanos) +
  (0 secs, jitter nanos)` with a seconds carry on reaching `10^9` and
  a signed-overflow panic; the result is stored to `[bucket+0x18]`
  (seconds) and `[bucket+0x20]` (nanoseconds). The bucket deadline
  fields match #188's queue layout exactly (`+0x18` seconds, `+0x20`
  nanoseconds, `+0x28` xorshift seed).
- If the wake flag is set, the collected nodes are reset (unrolled by
  4): `[node+0x10] = 0`, `[node+0x20] = 0` (dword), `[entry+0x8] = 1`,
  `[entry+0x10] = &node+0x20`.
- The slot word's bit 0 is cleared (`lock and [slot], ~1` at
  `0x5bb31d9`).
- The entries are normalized into a uniform array (inline entries
  relocated to `[rsp+0x130]`, a 176-byte `memcpy` of the inline tail;
  heap entries used in place), and each entry whose flag is not `2`
  is futex-woken with `syscall(202, entry+0x10, 0x81, 1)`
  (`FUTEX_PRIVATE_FLAG | FUTEX_WAKE`, one waiter, at `0x5bb33f4`).
  No path in this FDE sets flag `2` (creation sets `0`, reset sets
  `1`), so every collected entry is woken on the mainline. A second
  flag scan follows the wake loop; its result is not consumed before
  the heap free (GOT `0x64df4a0` → `0x635de30`) and the return of `0`.

Open edge, stated plainly: when the wake flag is clear but the vector
is nonempty (only possible for foreign-shaped nodes, whose `+0x18`
lacks bits `0xc`), the reset is skipped yet the wake loop still runs,
so the futex address would come from an entry `+0x10` field this FDE
never wrote. The mainline (protocol-shaped nodes) is unaffected, and a
futex wake on a stale address wakes nobody, but the foreign-node path
is not fully resolved here.

## Call-site census

Callers of the timed wait itself: 0 direct `E8` callers; 40
GOT-indirect sites via slot `0x64e0ff0` (→ `0x5bb2440`) across many
FDEs — this is a widely shared runtime primitive, not a park-only
helper.

Calls inside the timed wait (objdump-counted):

| Target | Sites | Notes |
| --- | --- | --- |
| cleanup, GOT `0x64ec150` → `0x5bb66b0` | 10 | release paths, both waits, drain exit |
| table creation, GOT `0x64ec158` → `0x5bb6400` | 3 | one per lookup |
| contention helper, GOT `0x64ec160` → `0x5bb6790` | 3 | as in #189's census |
| constructor, GOT `0x64ec170` → `0x5bb6070` | 2 | lazy node init |
| deadline add, GOT `0x64ec178` → `0x5ca94e0` | 1 | drain refresh |
| `syscall`, GOT `0x64e06b8` | 3 direct + 2 register-indirect | 5 futex sites total |
| `sched_yield`, GOT `0x64e1558` | 2 | one per spin loop |
| `clock_gettime` wrapper `0x5c842e0` (E8) | 3 | both waits + drain check |
| remaining-time `0x5c84210` (E8) | 2 | one per wait |
| timeout handler `0x5bb3ca0` (E8) | 2 | one per wait |
| TLS check `0x5bb5130` (E8) | 2 | one per wait |
| vector grow `0x5bb5450` (E8) | 1 | 9th push |
| `memcpy`, GOT `0x64df508` | 1 | inline relocation, 176 bytes |
| deallocator, GOT `0x64df4a0` → `0x635de30` | 3 | 1 heap free + 2 unwind pads |
| `_Unwind_Resume` (E8) | 4 | landing pads only |

## What this does not claim

- The Rust type/trait names of the slot, the bucket, the waiter node,
  and the queue are not asserted; "timed wait", "drain", and "wake
  flag" are behavior descriptions from the atomic operations and
  syscalls, not symbols.
- The slot-word bit 3 (`0x8`) meaning, the TLS check's semantics, the
  constructor's field values, and the timeout handler's internals are
  context only, not decoded here.
- The `+0x10 == 1` first-phase exit signal's writer is not established
  (see above); the foreign-node drain edge is not fully resolved.
- No gate is requested by this packet; the next question is either the
  vtable dispatch site that would settle the wake-site `rdx` question
  (still open since #188), or the timeout handler `0x5bb3ca0` end to
  end, to see what it records on the timed-out node.

## Verification

`tools/node115_lu_timed_wait.py` passes (target digest, body hash,
single ret, futex sites, xorshift shifts, division magic, deadline-add
call, GOT census, caller census);
`tests/test_node115_lu_timed_wait.py` passes (7 tests, including
corruption controls); `make doctor` reports `analysis_ready` true;
`make verify` and `make catalogue-check` pass.
