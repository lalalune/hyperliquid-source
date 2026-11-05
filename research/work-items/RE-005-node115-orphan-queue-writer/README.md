# RE-005 node 115: who writes the SIGCHLD orphan queue?

Follow-up to the timeout cache object packet (PR #2947),
which pinned the park slow-path refresh body `0x5cee650`
and the orphan reap pass `0x5cee900` it drives (vendored
tokio, `process/unix/orphan.rs:118`), and recorded as an
open edge that the orphan queue has no static pusher.

## Question

Which body enqueues records into the orphan queue that
the reap pass at `0x5cee900` consumes, given that no body
addresses the queue globals directly?

## Answer

No statically-addressing writer exists. A complete
census of every RIP-relative reference form — disp-final
and trailing-immediate (disp followed by up to 8 bytes of
immediate) — over the whole `.text` finds the orphan
queue globals materialised **only** by the refresh body
`0x5cee650` (lock references and the queued-length test)
and by the reap pass `0x5cee900` itself. The enqueue is
therefore necessarily pointer-carried: the producer
reaches the queue through a header pointer it already
holds in a register, not through an address it computes
from a queue global. Static analysis can pin the queue,
the record, and every consumer exactly; it cannot name
the producer body, and this packet does not guess one.

## Queue header layout (file initial values verified)

The queue header is a 0x20-byte region inside the static
signal-registry block:

| VA | Field | File init |
| --- | --- | --- |
| `0x64fede0` | lock byte (byte mutex, futex slow path) | 0 |
| `0x64fede8` | word in the capacity position | 0 |
| `0x64fedf0` | record buffer pointer | 4 (dangling, align 4) |
| `0x64fedf8` | queued record count | 0 |

The `0x64fede8` word is never read or written by any
verified instruction. The single disp-final raw-scan hit
for its address (`disp_end 0x63ba622`) is a
mid-instruction byte pattern inside an unrelated
constructor body `0x63ba600` (`movb $0x0, 0x14(%rdi)`
followed by `movl $0x0, 0x20(%rdi)`), pinned in this
packet as `falsepos` so the hit is never mistaken for a
reference. Its trailing-form hits are all k = 8
arithmetic aliases of the lock sites. The lock's own
trailing-form hits outside refresh/reap are exactly the
references to the slab counter word `0x64fedd8` eight
bytes below it.

## Record layout (stride 0x1c, read off the reap pass)

| Offset | Field | Evidence |
| --- | --- | --- |
| +0x00 | status tag (0 = unreaped, 1 = reaped, status cached) | convert/wait tag test |
| +0x04 | cached raw exit status | convert status store |
| +0x08 | pid | convert `mov 0x8(%rsi), %edi` before waitpid |
| +0x0c | pidfd (-1 = none) | convert/fdhelper P_PIDFD path |
| +0x10 | stdin fd | reap pass close loop |
| +0x14 | stdout fd | reap pass close loop |
| +0x18 | stderr fd | reap pass close loop |

The reap pass walks the queue from the last record
backwards; a record whose reap probe reports an exit is
swap-removed (the last record is copied over it), its
four fds are closed (skipping -1), and the decremented
length is stored. The panic Location `orphan.rs:118:20`
is the index bound of that walk. It is the only
`z_vendor/tokio/src/process/` Location string in the
binary (count 1; `orphan.rs` count 1).

## Consumers

* `convert` `0x5c902e0` (227 B) is the non-blocking reap
  probe: pidfd present → shared helper `0x5c875f0` with
  waitid flags 5 (`WEXITED|WNOHANG`, idtype `P_PIDFD`,
  `pidfd_send_signal`-style ioctl `0xc040ff0b` fallback on
  `ECHILD`); otherwise `waitpid(pid, WNOHANG)`. On an
  exit it writes tag 1 and the raw status back into the
  record. It has **no** rel32 callers; it is reached only
  through GOT slot `0x64ec898` (R_X86_64_RELATIVE →
  `0x5c902e0`), and that slot is referenced only from the
  reap pass (2 sites).
* `wait` `0x5c94a80` (304 B) is the blocking sibling
  (waitid flags 4, waitpid flags 0, same record layout).
  Its six verified rel32 callers: the spawn body
  `0x5c84a40` ×3, the sibling body `0x5c98260` ×1, and
  two app-region bodies `0x1535fd0` ×1 and `0x1565460`
  ×1, which pass it a stack copy of a record. None of
  them touches the queue.
* The `waitpid` GOT slot `0x64ec8a0` is referenced only
  from `convert` and `wait`.

## Where records come from

Records are the child-process inner values built by the
spawn body `0x5c84a40` (9,849 B; fork / posix_spawnp,
stdio pipes via `0x5c87f70`, exec child `0x5c870c0`):
the pid, the pidfd and the three stdio fds of a record
are exactly the values that body creates. Registration
into the queue happens later, on the drop path of an
unwaited child, through the pointer-carried enqueue
above — which is why the queue is only ever observed
from the SIGCHLD-driven reap side.

## Negative results (all re-derived by the tool)

* Absolute-addressing exclusion: the binary is PIE
  (ET_DYN); no absolute disp32 pattern names a queue
  global, and no stored qword or relocation addend
  anywhere in the file names a queue global (the stored
  scan finds queue-global values nowhere).
* Stride arithmetic: the ×28 lea-pair idiom appears in
  the process region (`0x5c00000..0x5d00000`) only in the
  reap pass (×2) and one 24-byte-element Vec body
  (`0x5cc4c50`); the `imul` imm8 0x1c byte pattern has 23
  sites file-wide, none inside the convert, wait,
  fdhelper or spawn bodies.
* The refresh body's length test
  (`cmpq $0x0, queue_len(%rip)` at `0x5cee6e0`) is the
  one trailing-immediate reference the disp-final census
  cannot see; the trailing scan (k = 1..8) finds it and
  nothing else new.

## Open gaps

* The producer body itself is not identifiable by
  static means: it receives the queue header pointer in
  a register (the header is one field of the larger
  registry static block whose other fields — counter,
  vector, once state — are addressed absolutely by the
  signal TU bodies). Naming it needs dynamic tracing of
  a live node or the vendored source, both out of scope
  for this packet.
* The role of the `0x64fede8` word is positional
  inference (capacity slot of the queue's vector
  header); nothing in the binary reads it, so nothing
  stronger can be claimed.
* Whether the enqueue path also runs at child
  registration time (eager) or only at drop time is not
  decidable from the binary alone; the consumer side is
  fully pinned either way.

## Verification

`tools/orphan_queue_writer_static.py` re-derives every
pin above from the artifact; `tests/
test_orphan_queue_writer_static.py` (13 tests) compares
the derivation against `records.json` and asserts the
negative results. Run with the artifact materialised at
`artifacts/node/115/hl-node`:

```
python3 -m unittest tests.test_orphan_queue_writer_static
```
