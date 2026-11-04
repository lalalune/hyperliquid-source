# RE-001: the node #115 lu RwLock read wait — reader-count fast path, TLS-node futex wait, and timeout unlink

- Component: `base/src/lu.rs` conversion context, the hash-bucket entry-word
  family shared by the park queue, the lookup, and the cleanup helper.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: packet #191 (PR #2226, open) left open the family FDE
  `0x5bb1a60` end to end, whose timeout path already shares the #191
  handler. Answer, in one paragraph: `0x5bb1a60` is an RwLock
  read-acquisition wait with a deadline. It first tries the fast path
  — incrementing the slot word's reader count by `0x10` with one
  `lock cmpxchg`, returning 1 on success — and when the word is in the
  waiting shape it takes the slow path: it acquires the word's bit 0,
  passes a TLS gate, claims a hash bucket with the #188 lookup shape,
  tail-appends the per-thread TLS waiter node, and futex-waits on the
  node's `+0x20` word with the deadline as timeout (untimed when the
  deadline nanos field is exactly `10^9`). On wake it returns 1 when
  the node's `+0x10` status is 1 and retries otherwise; on timeout it
  calls the #191 handler, unlinks itself, clears slot bit 0 when no
  other node carries the key, and returns 0. This packet cites #183
  (PR #2106), #184 (PR #2125), #185 (PR #2137), #186 (PR #2158), #187
  (PR #2179), #188 (PR #2190), #189 (PR #2197), #190 (PR #2206), and
  #191 (PR #2226, the inviting prior packet) as prior work; their
  bodies are cited, not re-claimed. The new bytes claimed here are
  the `0x5bb1a60` body only. The lookup, park, cleanup,
  contention-helper, table-creation, constructor, timed-wait, and
  timeout-handler bodies are prior claims or context, referenced here
  by address for the transition sites.

## The word is an RwLock state word

The overflow panic proves the identification: adding `0x10` to a word
greater than `u64::MAX - 16` panics with the 28-byte message `RwLock
reader count overflow` at
`/home/ubuntu/hl/code_Mainnet/z_vendor/parking_lot/src/raw_rwlock.rs:707:30`.
So the slot word's high bits are a reader count in units of `0x10`
(count = word >> 4), and bits 0..3 are flags. Observed flag roles in
this FDE: bit 0 is acquired by this function (`lock cmpxchg or 0x1`)
and cleared on the timeout path (and by #190's drain); bit 1 is the
cleanup-in-progress bit per #189; bit 3 gates the slow path (see
below). Bit 2's role is not established here. The "RwLock" label is
the panic message's own wording, not a symbol read from the binary.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | --- | --- |
| family wait (characterized) | `0x5bb1a60..0x5bb210a` | 1706 | 426 (417 excluding nop padding) |
| lookup (cited, #188) | `0x5bb4d00..0x5bb4f78` | 632 | — |
| park (cited, #188) | `0x5bb42e0..0x5bb4663` | 899 | 257 |
| cleanup (cited, #188) | `0x5bb66b0..0x5bb678b` | 219 | — |
| contention helper (cited, #189) | `0x5bb6790..0x5bb68d9` | 329 | 104 |
| timed wait (cited, #190) | `0x5bb2440..0x5bb35ed` | 4525 | 1164 |
| timeout handler (cited, #191) | `0x5bb3ca0..0x5bb3e41` | 417 | 107 |
| table creation (context) | `0x5bb6400..0x5bb645f` | 95 | — |
| constructor (context) | `0x5bb6070..0x5bb63f5` | 901 | — |
| TLS check (context) | `0x5bb5130..0x5bb51fe` | 206 | — |

All bodies are hash-pinned without normalization. Coordinates are ELF
virtual addresses (PIE); `.text` file offset = VA − 0x1000,
`.data.rel.ro`/`.got` file offset = VA − 0x2000, `.rodata` file offset = VA.
The wait FDE's CIE is the `zPLR` CIE at `.eh_frame` offset `0x39672c`
(eh_frame-confirmed, personality routine plus LSDA — unlike #190/#191's
`zR` zero CIE, consistent with this FDE's landing pads); it has one
`ret`, at `0x5bb20a2`. The body proper to the ret is 1603 bytes
(`0x5bb1a60..0x5bb20a3`); the tail `0x5bb20a3..0x5bb210a` (103 bytes)
holds the four panic stubs and the `_Unwind_Resume` landing pads,
including the refcount decrement. The body SHA-256 is
`95d9b142970398a722b871c66eb3d77a3b06ae45a55333dc5c668b3773f96aac`.

## Signature and arguments

`wait(rdi = slot pointer, esi = mode byte, rdx = deadline seconds, rcx = deadline nanoseconds) -> u8`:

- `rdi` is saved as `r15` (the slot); its golden-ratio hash
  (`rdi * 0x9e3779b97f4a7c15`, the same constant as #188's lookup) is
  saved for the bucket claim.
- Only the low byte of `esi` is read (`cmp BYTE [rsp+0x1c], 0`); it
  selects the entry check (see below). Its meaning beyond that
  selection is not asserted.
- `rdx` is saved to `[rsp+0x50]` (deadline seconds) and `rcx` to
  `r13d`/`[rsp+0x18]` (deadline nanoseconds); the pair is compared
  against `clock_gettime` output as a (seconds, nanoseconds) pair on
  every wait iteration (expired when now is strictly greater).
- `[rsp+0xf]` records whether `ecx != 10^9` (`0x3b9aca00`); that byte
  is stored into the waiter node's `+0x24` field as a has-deadline
  flag.
- Return: `1` when the reader count was incremented (fast path) or
  when the waiter was woken (node `+0x10 == 1`); `0` when the timeout
  unlink completed. Anything else loops internally; it does not
  return.

## Phase 1: the fast path (reader-count increment)

Two entry checks, selected by the mode byte, decide whether the fast
path is attempted at all:

- Mode byte nonzero: if `(word & ~7) == 8` (bit 3 set, reader count
  zero), skip the fast path and go directly to the acquire phase.
  Otherwise spin: try `lock cmpxchg [slot], word + 0x10` (sites
  `0x5bb1aee`, `0x5bb1b4e`); success returns 1 at once; failure
  reloads the word and, when `(word & ~7) == 8`, falls into the
  acquire phase, else loops. The spin uses the helper's backoff
  shape (`2^(round+1)` pauses per round, counter capped at 9).
- Mode byte zero: if bit 3 of the word is set, go directly to the
  acquire phase; otherwise the same `+0x10` spin loop, exiting to
  the acquire phase as soon as bit 3 is observed set.

So bit 3 is the "waiters present" gate: when set, new readers must
queue instead of incrementing directly. Adding `0x10` past
`u64::MAX - 16` panics (see Panic paths). The two entry checks
differ in strictness — exact shape versus bit-3-only — and why the
mode byte selects between them is not established here.

## Phase 2: the acquire phase (bit 0 + spin/yield)

The acquire phase spins with a round counter in `edx` (reset to 0 on
every retry, carried in `r14d`):

- While the word's low 2 bits are clear and fewer than 10 rounds have
  passed, pause with `2^(round+1)` pauses per round, calling
  `sched_yield` (GOT `0x64e1558`) from round 3 on (call at
  `0x5bb1d68`).
- Once the word has low bits set, or 10 rounds elapse, it tries
  `lock cmpxchg [slot], word | 0x1` (site `0x5bb1bb4`); if bit 0 is
  already set it proceeds at once; on cmpxchg failure it restarts
  from the entry check with a fresh word.

Bit 0 is the wait-queue lock: it is held across the enqueue below
and cleared on the timeout path (and by #190's drain), never by this
function's wake path.

## Phase 3: the TLS gate and the waiter node

After acquiring bit 0, the function resolves its waiter node:

- If the TLS gate byte at `fs:[-0x4b0]` is `1`, the per-thread node
  at `fs:0 - 0x4d8` (the same TLS struct as #190's second phase) is
  used directly.
- Otherwise the 206-byte TLS check at `0x5bb5130` (called with the
  TLS node and `0`) decides: nonzero returns a node to use;
  zero falls back to a lazily built stack node at `[rsp+0x80]`,
  filled by the 901-byte constructor at `0x5bb6070` (GOT
  `0x64ec170`, called at `0x5bb2038`) with the same 40-byte copy
  shape as #190, and marked by `[rsp+0x78] = 1` so every exit path
  (plus the unwind pads) runs `lock dec` on the refcount variable
  at GOT `0x64ec168` (→ `0x64fff20`).

The check's semantics (budget? readiness?) are not asserted, and the
constructor's individual field values are context only.

## Phase 4: bucket claim and enqueue (lookup shape, inlined)

The claim loop is #188's lookup shape, inlined rather than called
(the lookup function itself is never called from this FDE): table
variable GOT `0x64ec148` → `0x64fff28`, bucket count `[table+0x8]`,
shift `64 - [table+0x18]`, 64-byte stride, `lock cmpxchg 0 -> 1`
(site `0x5bb1c37`), contention helper GOT `0x64ec160` on race,
table creation GOT `0x64ec158` → `0x5bb6400` when the table is
null, release-then-cleanup on table change (cleanup GOT `0x64ec150`
→ `0x5bb66b0` exactly when the old value is `>= 4` with bit 1
clear). Once claimed, the slot word is rechecked: unless bits 0
and 3 are both set, the bucket is released and the function retries
from the acquire phase. When both are set, the node is filled and
tail-appended to the bucket list (`[bucket+0x8]` head,
`[bucket+0x10]` tail), and the bucket word is released with
`lock xadd -1` (cleanup on the standard condition).

Waiter node layout (one layout; the TLS node and the stack node
share it):

| Offset | Content |
| --- | --- |
| `+0x0` | key: the slot pointer |
| `+0x8` | list link, `0` at enqueue |
| `+0x10` | status word, read at wait exit (`1` = woken/granted) |
| `+0x18` | `0x10` at enqueue |
| `+0x20` | futex word, `1` while waiting |
| `+0x24` | has-deadline byte (`deadline nanos != 10^9`) |

Note the `+0x18` value: #190's protocol nodes enqueue with
`+0x18 = 8`, but this function writes `0x10` — which lacks bits
`0xc`, so under #190's drain wake-flag rule this node's shape would
not set the wake flag. That cross-packet observation is reported as
is; whether the two waiters ever share a bucket at runtime is not
established statically.

## Phase 5: the futex wait (deadline sentinel and remaining time)

The wait runs on the node's `+0x20` word with `syscall(202, word,
0x80, 1)` (`FUTEX_WAIT_PRIVATE`, GOT `0x64e06b8` →
`syscall@GLIBC_2.2.5`). There are 2 futex sites: the untimed wait
(`0x5bb1dd0`, register-indirect through the GOT-loaded pointer)
and the timed wait (`0x5bb1e5c`, GOT-direct with a timeout
argument).

The deadline sentinel is the same as #190's: when the deadline
nanos field equals exactly `10^9`, the wait is untimed (NULL
timeout, looping while the word is nonzero). Otherwise the wait is
timed:

1. `clock_gettime` wrapper `0x5c842e0` (`CLOCK_MONOTONIC`) returns
   now.
2. If now has passed the stored deadline, the timeout path runs
   (below).
3. Otherwise the remaining time is computed by `0x5c84210`
   (deadline in, remaining out) and the futex wait uses that
   timespec (`r8 = [rsp+0x30]`). The helper reports expiry in the
   flag byte at `[rsp+0x28]`; when the flag is set, the wait is
   issued with a zeroed timespec (a single poll), and the loop then
   re-checks now against the deadline and takes the timeout path.
   The flag's exact semantics beyond this observed mechanism are
   not asserted.

## Wait exit and the timeout path

On every wake the node is examined at `0x5bb1df1`: `cl =
([node+0x10] == 1)`. If `cl` is set the function returns 1;
otherwise it retries from the acquire phase. Which writer sets
`+0x10` to 1 is **not** established in this FDE — #190's drain
writes `0` there, and the constructor fills `+0x10..+0x20`
opaquely — so the `+0x10` signal is reported as an observed
branch, not an interpreted one, exactly as in #190.

On timeout (now past the deadline) the function calls the #191
handler at `0x5bb1f09` with the node, receiving `(rax = key,
rdx = bucket entry)`. If the node's futex word is already 0, the
bucket is released and the normal wait-exit check runs. Otherwise
the bucket list is walked for the node (head check, then a
key walk that also tracks whether any other node carries the slot
key), the node is unlinked, and slot bit 0 is cleared with
`lock and [slot], ~1` (site `0x5bb1fc3`) if and only if the slot
key no longer appears in the list — the same scan-and-clear rule
as #188's park, applied here to bit 0. The bucket is then
released (`lock xadd -1`, cleanup on the standard condition) and
the function returns 0.

## The panic paths

All four panic stubs' `Location` structs are resolved through
`R_X86_64_RELATIVE` relocations (the file fields read 0 before
relocation); the file strings are read at the relocation addends.

| Path | Trigger | Location | Wrapper / helper |
| --- | --- | --- | --- |
| `0x5bb20a3` | reader-count add overflows (`word > u64::MAX - 16`) | raw_rwlock.rs:707:30, 28-byte message `RwLock reader count overflow` | `0x64df770` (msg ptr `0x93fcd4`, len `0x1c`, Location `0x64bd230`) |
| `0x5bb20bc` | shift subtraction borrows (`[table+0x18] > 64`) | parking_lot.rs:352:45 | `0x64df848` (Location `0x64bd260`) |
| `0x5bb20cb` | shift amount `>= 64` (`[table+0x18] == 0`) | parking_lot.rs:352:5 | `0x64e0820` (Location `0x64bd278`) |
| `0x5bb20da` | bucket index `>= [table+0x8]` | parking_lot.rs:363:23 | `0x64df620` bounds-check helper (Location `0x64bd290`) |

The parking_lot file string is
`/home/ubuntu/hl/code_Mainnet/z_vendor/parking_lot_core/src/parking_lot.rs`
(73 bytes); the raw_rwlock file string is
`/home/ubuntu/hl/code_Mainnet/z_vendor/parking_lot/src/raw_rwlock.rs`
(67 bytes). Note the bounds-check line differs from #191's
(363:23 here versus 390:23 there): the two functions' bounds checks
are separate sites, not shared code.

## Call-site census

Callers of this wait function itself: 0 direct `E8` callers (byte
scan over all of `.text`, every hit checked); 127 GOT-indirect
call sites via slot `0x64e0fd8` (→ `0x5bb1a60`), all `FF 15`
indirect calls, across many FDEs — a widely shared runtime
primitive, not a family-only helper. No register-indirect loads
from the slot were found.

Calls inside the wait (objdump-counted):

| Target | Sites | Notes |
| --- | --- | --- |
| cleanup, GOT `0x64ec150` → `0x5bb66b0` | 5 | release paths, enqueue, timeout |
| table creation, GOT `0x64ec158` → `0x5bb6400` | 1 | null-table path |
| contention helper, GOT `0x64ec160` → `0x5bb6790` | 1 | as in #189's census |
| constructor, GOT `0x64ec170` → `0x5bb6070` | 1 | lazy stack-node init |
| `syscall`, GOT `0x64e06b8` | 2 | 1 GOT-direct (timed) + 1 register-indirect (untimed) |
| `sched_yield`, GOT `0x64e1558` | 1 | acquire-phase backoff |
| `clock_gettime` wrapper `0x5c842e0` (E8) | 1 | timed-wait loop |
| remaining-time `0x5c84210` (E8) | 1 | timed-wait loop |
| timeout handler `0x5bb3ca0` (E8) | 1 | as in #191's census |
| TLS check `0x5bb5130` (E8) | 1 | node resolution |
| refcount, GOT `0x64ec168` → `0x64fff20` | 2 `lock dec` | exit paths + unwind pads |
| panic wrappers (GOT) | 4 | one per stub above |
| `_Unwind_Resume` (E8) | 1 | landing pads only |

## What this does not claim

- The Rust type/trait names of the slot, the bucket, the waiter
  node, and the queue are not asserted; "RwLock", "family wait",
  and "waiter node" are behavior descriptions from the atomic
  operations, syscalls, and the panic message's own wording, not
  symbols.
- The mode byte's meaning, bit 2's role, bit 3's setter, the TLS
  check's semantics, the constructor's field values, and the
  remaining-time flag's exact semantics are context only or
  observed-but-uninterpreted, as stated above.
- The `+0x10 == 1` wake signal's writer is not established (see
  above); the vtable dispatch site that would settle the wake-site
  `rdx` question (open since #188) is not settled here either.
- No gate is requested by this packet; the next question is either
  who writes node `+0x10 = 1` (the waker that completes this wait
  and #190's first phase), or the vtable dispatch site that would
  settle the wake-site `rdx` question.

## Verification

`tools/node115_lu_rwlock_read_wait.py` passes (target digest, body
hash, single ret, fast-path/acquire/claim/release sites, futex
numbers, golden ratio, GOT resolutions, panic `Location`
file/lines and message, caller census 0 E8 / 127 GOT, no
register-indirect slot loads);
`tests/test_node115_lu_rwlock_read_wait.py` passes (7 tests,
including corruption controls); `make doctor` reports
`analysis_ready` true; `make verify` and `make catalogue-check`
pass.
