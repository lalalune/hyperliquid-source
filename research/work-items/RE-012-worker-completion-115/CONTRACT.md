# Worker completion, notification and conditional process exit — node #115

This packet resolves what the private `thread_spawn_forever` and
`tokio_spawn_forever` paths do when their work ends. The diagnostic text alone
would not establish process termination. The observed chain creates a oneshot
notification, polls its receiver, requests a delay, and then passes status 1
through runtime wrappers to the dynamically imported `exit` function. That last
edge is conditional on the scheduler polling the task, the delay becoming ready,
and intervening helpers returning normally. A successful send does not guarantee
receiver consumption or process termination.

All addresses are linked ELF virtual addresses in node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
These are static statements about the pinned bytes, not observations of a running
node. No captured instructions were executed or emulated.

## Scope and admission

Twelve complete primary FDE bodies total 8,821 bytes. Fifteen complete context
FDE bodies bring the exported denominator to 17,695 bytes and 3,974 instructions.
The context bodies establish actual callers, prepared task state, one receiver
poll dispatch chain, the receiver operation and the reachable delay conversion.
They are not a closed implementation of Tokio, thread spawning or process cleanup.

| Role | Name | Complete half-open FDE | Bytes |
|---|---|---|---:|
| primary | `registration` | `[0x15d60b0, 0x15d622a)` | 378 |
| primary | `thread_spawn` | `[0x15d63c0, 0x15d6729)` | 873 |
| primary | `tokio_spawn` | `[0x15d6730, 0x15d6df5)` | 1733 |
| primary | `notification_callback` | `[0x15d8530, 0x15d8684)` | 340 |
| primary | `thread_monitor` | `[0x15ec360, 0x15ec6da)` | 890 |
| primary | `tokio_monitor_a` | `[0x15ec6e0, 0x15eccae)` | 1486 |
| primary | `tokio_monitor_b` | `[0x15eccb0, 0x15ed28d)` | 1501 |
| primary | `notification_send` | `[0x15fbe20, 0x15fc062)` | 578 |
| primary | `receiver_monitor` | `[0x15ebfa0, 0x15ec352)` | 946 |
| primary | `termination_request` | `[0x15d6070, 0x15d60a7)` | 55 |
| primary | `runtime_exit` | `[0x5c9b030, 0x5c9b044)` | 20 |
| primary | `system_exit` | `[0x5c9d030, 0x5c9d045)` | 21 |
| context only | `registration_launcher` | `[0x15ca570, 0x15ca789)` | 537 |
| context only | `thread_launcher` | `[0x15c98c0, 0x15c9ad9)` | 537 |
| context only | `tokio_launcher_a` | `[0x15c94a0, 0x15c969f)` | 511 |
| context only | `tokio_launcher_b` | `[0x15ca2d0, 0x15ca567)` | 663 |
| context only | `receiver_schedule` | `[0x15e6380, 0x15e6497)` | 279 |
| context only | `receiver_schedule_alt` | `[0x1603340, 0x160359e)` | 606 |
| context only | `receiver_allocate` | `[0x15fc340, 0x15fc493)` | 339 |
| context only | `receiver_poll_tail` | `[0x15e33a0, 0x15e33a5)` | 5 |
| context only | `receiver_harness` | `[0x147ef70, 0x147f2f8)` | 904 |
| context only | `receiver_adapter` | `[0x15fe460, 0x15fe54a)` | 234 |
| context only | `delay_context` | `[0x15ebbe0, 0x15ebf9b)` | 955 |
| context only | `receiver_poll_context` | `[0x1607270, 0x16074e3)` | 627 |
| context only | `thread_caller_context` | `[0x4ec71b0, 0x4ec79f7)` | 2119 |
| context only | `tokio_caller_context` | `[0x4780990, 0x4780aa8)` | 280 |
| context only | `thread_adapter_context` | `[0x15fe220, 0x15fe336)` | 278 |

The semantic domain is the normally constructed, valid Rust ownership/state
representation reached by these constructors. Name/message allocation, valid
reference counts, valid boxed callback/vtable pairs, readable pointed-to objects,
and the relevant runtime/TLS context are premises. State bytes used to index
jump tables must be in the recorded table domain. Completed or unwound futures
are not allowed to be repolled as normal active futures. Their actual diagnostic,
UD2 and unwind paths remain in the complete exported bodies.

No universal raw-pointer, malformed-tag, overlapping-owned-allocation or arbitrary
alias API is claimed. The constructor copies inactive fields and padding along
with initialized fields; neither those bytes nor inactive words of niche-encoded
results are assigned invented values. Refcount-overflow, allocation failure,
panic, unwinding, foreign helper failures and scheduler behavior are explicit
boundaries. Whole RAX/RDX return semantics are not reconstructed; below, return
bytes or discriminants are named only where the caller actually tests them.

## Constructors and actual callers

The thread constructor is called through the actual RELATIVE slot `0x64e1750`
at instruction `0x4ec76c3`, within exported caller `0x4ec71b0..0x4ec79f7`.
The Tokio constructor is called directly at `0x4780a1b`, within
`0x4780990..0x4780aa8`. Broader xref searches are retained as discovery evidence,
not an exhaustive proof of dynamic callers.

At `0x15d64a3`, the thread constructor calls `0x15b73c0`. The first result word
at stack+0x48 is tested for zero at `0x15d64b6`; zero takes the
`failed to spawn thread` diagnostic and unwrap helper, followed by UD2 if that
helper returns. The spawn implementation itself is outside this packet.
A successful path prepares an 80-byte shared allocation: two initial reference
counts are 1, the flags word at allocation+0x30 is zero, and the value niche at
+0x38 is `S = 0x8000000000000000`. Other copied bytes are not all initialized.
The cloned count uses LOCK INC and an overflow guard. The monitor's state byte
at +0xba is initialized to zero; the launcher copies the prepared 0xc0-byte
future. Registration at `0x15d65bc` supplies the exact 20-byte
`thread_spawn_forever` label and the related receiver pointer.

The Tokio constructor independently prepares the same 80-byte shared shape. Its
32-byte callback environment contains the owned name's three words followed by
the sender pointer at +0x18. The observed callback vtable at `0x64013f0` has
size 32, alignment 8 and its call slot `0x6401408` uniquely relocates to
`0x15d8530`. The mode branch at `0x15d6870` tests **BL**, the low byte of the
incoming EDX, not all 32 bits. Both paths eventually construct a monitor with the
same callback pair: one has state byte +0x48 and launcher `0x15c94a0`, the other
state byte +0x70 and launcher `0x15ca2d0`. The nonzero-mode path additionally
consults runtime/tracing state; its internal helpers remain opaque.
Registration at `0x15d6c21` supplies `tokio_spawn_forever` (19 bytes).

Registration `0x15d60b0` clones the name and prepares name words, label pointer
and length, receiver pointer and a zero state byte at future+0x48. Its launcher
copies 0xe8 bytes. One actual allocation/dispatch route is:

```
15ca706 -> 15e6380 -> 15fc340
  task header+0x10 = vtable 6402500
  vtable[0] -> 15e33a0 (tail jump) -> 147ef70
  147f01c -> 15fe460; 15fe4f0 -> 15ebfa0
```

The prepared future and task offset adjustments are visible in those complete
bodies. The seven vtable words at `0x6402500` are authenticated, including every
actual relocation writer. The alternative scheduler route calls `0x1603340`
and prepares a different vtable `0x64022d0`; that entire route's body is retained,
but its further scheduler/vtable dispatch is not claimed closed here. This is
an actual receiver path and an explicitly open alternate runtime boundary, not
a proof that every task is scheduled or that either runtime makes progress.

## Thread and Tokio completion handling

The thread monitor uses the four-entry relative table at `0x46a034`. On its
initial path it sets two cleanup flags. Its completion test at `0x15ec43c` is
**qword exactly 1** through the prepared join-state pointer; values merely
nonzero are not equivalent. Otherwise it requests a delay with binary64 1.0,
polls it, and rechecks the completion gate. A pending delay produces AL=1 and
monitor state 3. When complete, the monitor calls `0x15b8810`; its RAX-zero and
RAX-nonzero cases choose the normal and error message preparations. This is an
observed discriminant, not a reconstruction of that helper's full result ABI.
Both cases call `0x15fbe20`. The zero case copies exactly 43 bytes forming
`crashing because thread_spawn_forever ended`; overlapping vector copies at
source+0, +0x10 and +0x1b preserve the full string, with no terminator inferred.
The other case passes formatting inputs including its error observation.

After send, the thread monitor's zero-minus-first-result-word overflow test
accepts exactly `S`. A successful send completes the monitor (state 1, EAX=0).
Other first words take an unwrap-failure helper and UD2 if it returns. These
failure paths do not provide an alternative guarantee of process exit.

The two Tokio monitors use the four-entry tables at `0x46a044` and `0x46a054`.
Their state layouts differ, but both poll a child through `0x16074f0`, which is
outside this packet. A nonzero observed poll byte is returned unchanged as a
zero-extended byte and the monitor enters state 3. It is not normalized to 1.
With observed poll byte zero, the first result word zero selects the 42-byte
`tokio_spawn_forever ended in an Ok variant` message. A nonzero word selects the
error formatting/drop path. Both paths reach the supplied callback through its
vtable+0x18, then release the callback/name and finish with state 1 and EAX=0,
subject to helper normal return. The constructors above supply `0x15d8530`;
an arbitrary substituted callback would not establish the same notification.

The concrete callback `0x15d8530` receives the three-word message, formats the
name/message context and calls `0x15fbe20` at `0x15d8595` using environment+0x18.
It likewise accepts only first result word `S`; failure invokes an unwrap helper.
The diagnostic's wording is evidence of intended policy, while the receiver and
exit chain below establish the separate conditional control-flow fact.

## Notification sender: ownership and flags

In `0x15fbe20`, RDI names the result area, RSI the consumed shared sender pointer,
and RDX the owned three-word message. A null sender takes a panic path. The
previous value at shared+0x38 is handled before replacement. The message tail
word is written first, followed by its 16-byte prefix. These stores do not
support arbitrary source/shared/result aliasing; valid ownership is a premise.

The flags at shared+0x30 are observed and a LOCK CMPXCHG loop tries `old | 2`.
If the observed flags already have bit 4, no completion-bit CAS is attempted.
On a failed CAS, the next iteration uses the newly observed flags in RAX.
After a successful CAS or the closed observation, the retained old flags decide:

- Wake through shared waker fields only if `(old & 5) == 1`.
- If `(old & 4) == 0`, write only the first result word `S` (send success).
- Otherwise take the message back out of shared+0x38, replace that value niche
  with `S`, and copy the reclaimed three words to the result. An already empty
  value follows the recorded invariant-failure path.

The consumed shared reference is released after these operations. Other result
words on send success remain inactive and have no value claim. The OR operation
preserves unrelated flag bits. The instructions establish local transition/order
facts, not a proof of all weak-memory interleavings, waker validity, fairness,
receiver consumption or eventual notification. In particular, a receiver may
close after a successful completion CAS.

## Receiver, delay and actual exit import

Receiver poll `0x1607270` can first return pending for runtime cooperation.
Its result niche is `P = S+1` for pending and `S` for closed/no value. A present
message carries its owned three words. The value-present bit is checked before
the closed bit; an available value is taken from shared+0x38 and replaced with
`S`. The receiver pointer is consumed/released on a ready outcome. Only the
first word is semantically active in a closed result; stale copied payload words
are not invented strings. The waker install/replace and flag CAS paths are in
the full body, but their runtime dependencies remain assumptions.

Receiver monitor `0x15ebfa0` uses the five-entry table at `0x46a020`. It calls the
receiver poll at `0x15ebfe2`; exactly `P` stores state 3 and returns pending.
Every other admitted ready result, including `S` (closed), goes through receiver
closing/release and diagnostic preparation. Closing sets bit 4 with CAS;
old-flag masks control the corresponding wake/drop calls. Consequently the
policy is not restricted to the successful-message branch.

After the diagnostic helper returns, `0x15ec1f9` loads
`0x4034000000000000` (binary64 20.0), stores it at future+0x50, and initializes
the delay's outer state byte to zero. `0x15ec218` calls delay `0x15ebbe0`.
Nonzero AL stores monitor state 4 and returns; state 4 resumes that delay.
Zero AL takes delay cleanup and the termination call at `0x15ec296`.

Both full delay-state tables (`0x46a000`, `0x46a010`, four entries each) are
bound. For the only two constants used here, 1.0 and 20.0, exponent values
0x3ff and 0x403 choose the finite `[1, 2^52)` conversion path. The integer
mantissa shifted by `0x433-exponent` yields 1 or 20; the shifted fractional
bits masked with `2^52-1` are zero. Thus the 1e9 fractional multiplication and
rounding yield zero nanoseconds without a carry. At `0x15ebde1`, the helper
bound through `0x64e13a0 -> 0x5cf2150` receives `(RSI, EDX)=(1,0)` or `(20,0)`.
The poll helper is `0x64e0858 -> 0x5cf2d30`. This proves these argument pairs,
not elapsed wall time, clock behavior or the helper's entire implementation.
No claim is made for every possible floating-point delay input.

The termination chain is directly authenticated:

```
15ec296: call [64e0b30] -> 15d6070
15d6074: call [64e0b20] -> 1560a40        (opaque)
          prepared stack triple (0,1,0); call 15dc530 (opaque)
15d609c: mov edi,1
15d60a1: call [64e1740] -> 5c9b030
5c9b030: save EDI; call 5c9a050; restore EDI; call 5c9d030
5c9d030: save EDI; call 5c9cfe0; restore EDI
5c9d03f: call [64ec980] -> dynamic symbol exit
```

The final slot is an actual GLOB_DAT relocation naming dynsym index 192,
`exit`, not a guessed function name or a direct `abort` call. On this sequence's
normal-progress path, the low 32-bit status reaching that imported function is
1. The pre-exit helpers, unwinding and external dynamic resolution are not
implemented or executed. There is no unconditional claim that a completed worker
kills the process, nor a claim of a 20-second deadline.

## Evidence, sources and qualification boundary

The collector checks the complete target digest, true FDE/CIE records, full body
hashes and instruction starts, source-location layouts/paths, exact constants,
relative jump tables, selected unique RELA writers, actual dynsym names, and
call/RIP references. It records all selected LSDA call-site rows and landing-pad
starts; it does not recover every exception action/personality meaning. Native
GNU and LLVM exports are required to agree with Capstone on complete instruction
bytes and boundaries. LLVM's 69 enumerated split LOCK prefixes are joined only
when their exact address and full bytes agree; zero bytes are masked.

The private `base/src/lu.rs` source is not available or copied. Public Tokio
oneshot sources are MIT-licensed interpretation evidence, pinned to commits
`5f3296df77ad594779d1fe1a1583078ca9832daf` (1.43.0) and
`8182ecf2628d5e80dac52b8ed1ea466dbb0925b9` (1.44.0). Three selected sender and
completion slices are byte-equal across the two releases. The receiver slices
have a retained `runtime::coop` versus `task::coop` path difference. These
counterchecks prevent an exact original release/build claim. All source files,
licenses, raw line slices and primary URLs are bound by `sources.json` and
`source-comparison.json`; no source compilation or machine-code match is claimed.

This is a static reconstruction of a conditional lifecycle relation, with helper
contracts left explicit. There is no invented Rust scheduler or arbitrary raw
ABI model, no new native behavior corpus, and no compiled-code comparison to
register. Tool tests are corruption/comparator controls, not observations of
original execution. No component/full-node acceptance gate or byte-equality
credit advances. Remaining work requires separate evidence for runtime dispatch,
thread/join internals, timers, formatting/drop operations, pre-exit cleanup and
concurrency; those unknowns are not silently replaced with source assumptions.
