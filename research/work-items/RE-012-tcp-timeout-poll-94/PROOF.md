# Conditional controller-to-caller relation

## Preconditions and interpretation

Let `P` denote the controller pointer in entry RDI and `C` the entry RSI value.
The following concerns ordinary entry at `0x2036460` with either a fresh outer
state byte `P+0xe0=0`, or the pair `P+0xe0=3,P+0xc0=3` produced by a preceding
ordinary pending return. Input pointers, TLS, subobjects and callback storage
must be valid for their observed accesses and satisfy the required lifetime
and nonaliasing invariants. Foreign writes must not change the controller's
control/progress fields between the accesses shown. Calls obey the captured x86-64
callee-save convention and do not invalidate the saved state/storage or
reenter the same state object. This is not a proof that every caller establishes
these invariants, that arbitrary bytes are a valid future, or that concurrently
polling the same object is valid.

“Ordinary return” excludes panic, unwind, traps and arbitrary return from a
panic/unwind endpoint. External callees may have effects or fail to return;
none of the arguments below establishes termination. `E(x)` means only the
value returned in RAX by `0x288d0d0(x)` if that call returns normally. Its type,
allocation success, nonzero-ness and complete destructor contract are unknown.
Raw RAX/RDX/AL values below are observed register roles, not guessed Rust ABI
enum names. In particular, an unspecified RDX must not be consumed as a payload.

## Entry state and data roles

After TLS handling, `0x20364c1` reads the outer byte and uses signed 32-bit
table entries relative to `0x3c3b38`. There is no bounds check. Its entries
0/1/2/3 target `0x20364d8/0x2036731/0x2036724/0x203650f`.
The inner table at `0x3c3b48`, indexed at `0x2036516`, targets
`0x203652d/0x203673e/0x203674d/0x203669b`. Entries 1 and 2 lead to distinct
failure calls. Table index 0 on an outer resume is decoded but is not assumed
reachable from the pending pair in this relation. Out-of-range indexes are
outside the claim.

Fresh entry copies three qwords `P+0x78/+0x80/+0x88` into
`P+0xa0/+0xa8/+0xb0`, resets inner state to zero and reaches `0x2036542`.
The first word is retained at `P+0xb8`; its `+0x78` qword is dereferenced and
`lock add [that_pointer+0x10],length` executes at `0x203654d`. This adds the
initial requested length modulo 2^64 **before** the first write call. It is
not an observation of successfully transmitted bytes. The write object,
current pointer and remaining length are stored at `P+0xc8/+0xd0/+0xd8`.
The inner-3 resume at `0x203669b` reloads only remaining length and jumps to
`0x203656e`, bypassing that increment and initialization.

## Write-first loop and completed payload

At `0x2036580`, zero remaining length reaches `0x20365ea`, sets RDX=0 at
`0x20365f8`, then writes inner state 1 at `0x2036616`. For nonzero length,
`0x2036596` calls `0x4f7d1a0` with object, context, current pointer and remaining
length in RDI, RSI, RDX and RCX. The next operations distinguish raw 2 before
testing bit zero:

| Lower write return | Controller continuation |
| --- | --- |
| RAX=2 | `0x20365fc`: inner=3 and EAX=1; proceed to timer decision |
| RAX=1 | `0x2036608`: save RDX, call `E(RDX)` at `0x203660e`, place result in RDX, then inner=1/EAX=0 |
| RAX=0, RDX=count | At `0x20365a5`, load saved pointer/remaining; store sentinel pointer=1 and remaining=0 **before** subtracting count |

For RAX=0 the subtraction at `0x20365c9` branches on unsigned borrow to
`0x2036709`. On a non-borrow path, `0x20365d2` adds count to the old pointer
(machine-width modular addition), then saves the advanced pointer and reduced
remaining length. A nonzero count loops to `0x2036580`; a zero count reaches
`0x203660b` with the fixed input `0x1700000003` loaded at `0x203656e`, producing
RDX=`E(0x1700000003)`. Thus zero count does not spin in this controller. Count
greater than remaining takes the failure path after the sentinel writes; a
valid lower adapter contract that forbids such counts is not presumed proved.

The complete lower-adapter body has one ordinary epilogue at `0x4f7d30b`:
RAX=RSI and RDX=RBX. Its incoming ordinary paths assign RSI to 0, 1 or 2
(`0x4f7d2d5/0x4f7d320`, `0x4f7d2a3/0x4f7d2fc/0x4f7d337`, and
`0x4f7d1e5/0x4f7d303/0x4f7d328`). These are a raw return-domain observation.
The readiness slot `0x576f158`, call slot `0x5776480` with ECX=`0x4000`, error
slot `0x576e8d8`, error classifier `0x4f7cba0`, and the CAS/retry loops are
dependencies. No syscall, socket outcome, fairness, or finite-loop result was
executed or proved. RDX is immaterial for raw 2 and may not be freshly set.

`0x203661d` writes outer state `2*AL+1`: completed paths produce outer=1,
whereas the pending path produces outer=3. The completed paths branch from
`0x2036631` to `0x203668a` and return RAX=0 directly. Consequently empty input,
exhaustion after positive counts, lower-write error, and zero count complete
without consulting the timer in this call. An error-adapter result is not
proved nonzero, so “RDX=0 iff success” is deliberately not asserted.

## Timer domain and return mapping

Only the pending path can reach the timer calls at `0x203667c` or
`0x20366bd`. Both indirect calls use slot `0x576f088`; the selected relocation
is type 8, symbol index 0, addend `0x4f68f00`. Both pass `P,C` in RDI,RSI.
The second path temporarily clears TLS byte +0x44 relative to
`fs:-0x1128`, retains restoration bytes on the stack, and has its own LSDA
cleanup record. The TLS initializer slot `0x576f1e0` binds `0x4edda70`; its
effects beyond the observed stores are opaque.

The timer adapter's complete normal-return partition is small:

- `0x4f68f88` calls opaque `0x4f79620`. If its AL is 4, the adapter returns
  AL=1 through `0x4f68fe0`, with conditional TLS restoration first.
- If its AL is 0, `0x4f68fcd` clears EAX and returns AL=0.
- Other AL values take the failure-call path at `0x4f6901c`; they are not
  additional ordinary return values under the stated endpoint assumption.
- A TLS condition (`BPL=1` and saved byte `R15b=0`) takes `0x4f68fd1`, calls
  `0x4f6c9a0` with a context-derived value and `0x57559e0`, and returns AL=1
  without calling `0x4f79620`. No source-level “budget” type is needed here.

The controller zero-extends timer AL and increments RAX at
`0x2036682/0x2036685` (or via `0x20366c3` and the restoration path). Therefore:

| Controller path | Controller RAX | RDX established here | Inner / outer bytes |
| --- | ---: | --- | --- |
| Write exhausted, including initially empty | 0 | 0 | 1 / 1 |
| Write error or zero count | 0 | `E(error_word)` | 1 / 1 |
| Lower write 2; timer adapter AL=0 | 1 | No payload claim | 3 / 3 |
| Lower write 2; timer adapter AL=1 | 2 | No payload claim | 3 / 3 |

Both timer-derived returns leave the controller state bytes at 3. Raw 1 is
not a controller state-byte completion transition; its caller disposes of
the subobject. Write-first ordering does not prove whether a real deadline
has passed, whether the timer is monotonic, or how much time a poll takes.

## One exact downstream use

The existing writer computes `P=W+0x1f0` at `0x204be6f` and calls the
controller at `0x204be81`. It preserves RAX in R14 at `0x204be86`.

1. RAX=2 branches at `0x204be8d` to `0x204c071`. The writer stores 3 to
   `W+0x2da`, `W+0x2e0`, and `W+0x2e8`, sets EAX=1 and returns through
   `0x204c08b`. This branch makes no call to `0x1fb6110`. Its outgoing RDX
   comes from prior R12, not a defined controller payload.
2. Otherwise, `0x204be93` preserves controller RDX in R12 and
   `0x204be99` calls `0x1fb6110(P)`. If that call returns normally, only then
   does `0x204be9e` test saved R14 bit zero. This establishes the cleanup-call
   ordering for raw 0 and 1, independent of the opaque cleanup implementation.
3. Raw 1 selects `0x204c09d`; the writer builds a descriptor/argument pair and
   calls `0x2023170` at `0x204c0d7`, replacing R12 with its RAX result.
   “Diagnostic construction” is a role inference from that setup. The exact
   message, formatting implementation and returned type are not recovered.
4. Raw 0 follows `0x204bea8`, makes additional time-related calls, and tests
   the preserved payload for zero at `0x204bf1f`. The nonzero path reaches
   `0x204c019`; the zero path can prepare the next chunk. This packet does not
   assert all later behavior or nonzero-ness of `E(x)`.

The cleanup body is retained in full because it is the ownership boundary
actually consumed by this caller. It includes indirect transfers at
`0x1fb619f` and `0x1fb61e7`; their targets, destructor effects, allocation
closure, and resource lifetimes are unresolved. “No normal cleanup call on
raw 2” does not prove that no callee or concurrent owner can release anything.

## Exception metadata is a separate observation

The retained controller LSDA maps call-site intervals
`[0x2036593,0x203659b)`, `[0x203660b,0x2036616)`, and
`[0x2036709,0x2036722)` to `0x203679b`, `0x2036787`, and `0x20367af`.
Those landing blocks write inner=2 and outer=2 before a direct call to
`0x5660110` (native import label `_Unwind_Resume@plt`). The timer-suppression
call interval `[0x20366b7,0x20366c3)` instead names `0x203675c`, whose
cleanup slot is `0x576f1e8 -> 0x4f77880`; it is not the same state-write path.

The writer's controller-call interval `[0x204be76,0x204be86)` names landing
`0x204c14f`, containing another `0x1fb6110(P)` call at `0x204c155`. Its normal
cleanup-call interval `[0x204be93,0x204be9e)` names `0x204c148`. These records
explain why unwind edges must not be merged with the normal raw-2 branch.
Only LSDA headers and call-site tables were parsed. Action/type chains,
personality behavior, external non-returning contracts and actual exceptional
reachability remain open; the recorded landing pads are not a whole unwind
correctness or resource-safety theorem.
