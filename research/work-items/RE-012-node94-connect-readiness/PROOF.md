# Provisional manual relation: node94 connect readiness and cancellation

This is a manual static argument, not yet a qualified contribution. Task RE-012,
transport; base 966865f1637a29ce75b019e1bf11d5529cc6f519. Target is the
91,774,280-byte node94 ELF with SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
All addresses below are linked ELF VAs. The claim concerns requests and
variant-defined values under ordinary-return premises, not an established
network connection or OS descriptor ownership.

## Provenance and distinct question

PR1672 establishes the preceding first configured IPv4 request and immediate
adapter outcome. It explicitly leaves registration, resumption and readiness
open. Canonical transport-node-port-94 and transport-socket-calls-94 provide
arithmetic and call censuses; RE-001-transport-integration-review-94 retains
the caller's full native context. Their bytes and observations remain credited.
The new question is which subsequent result permits a retained descriptor to
be returned, and which ordinary error/cancellation paths request its cleanup.
No recovered-byte count or full transport gate is established.

Canonical focused address searches find only those prior caller references
and PR1672's explicit gap. A four-page live open-PR review at this intake found
320 bodies; no selected helper or connect-readiness claim was found. This is
a non-atomic, bounded ownership check, not proof of universal absence. Repeat
before implementation selection and before submission.

## Premises and comparison projection

State and result are separate valid storage. The coroutine is not moved while
its stored self-pointer is used. Entry phase is 0 or 3 for ordinary polling;
phase 1/2 is diagnosed rather than repolled. Registration and reference-counted
objects are valid, ordinary callees preserve the caller's private storage
except for documented result arguments, and indirect callbacks return normally
without reentrant mutation of this state. TLS initialization and allocator,
lock, atomic-reference-count and callback contracts remain premises. Concurrent
reactor values may differ at the explicitly separated first and second loads.
Neither the packet nor a mathematical model executes captured instructions.

Project only variant-defined output: pending tag3 alone, error tag2 plus its
error word, or the returned registration tuple plus descriptor. The error path
copies an otherwise unspecified stack tail at 1ffebef; it must not be compared
or presented as initialized meaningful payload. Likewise padding and unused
result fields are not semantic bytes. No byte normalization is needed to retain
the complete native bodies; this is a value projection, not an identity mask.

## Initial registration and retained state

The four relative entries at 3c39e0 dispatch phases 0,1,2,3 to
1ffeaa6,1ffec27,1ffec1a,1ffeb03. The table and all relevant relocations must be
retained and corruption-checked before this draft becomes qualified.

For phase0, 1ffeaa9 reads the input descriptor at state+28. The relocation at
576f0a8 resolves to 4f68dd0. Its ordinary result is passed to 4f76f80 with
interest argument 3 and a pointer to the stack descriptor. Registration's
qword tag2 is an error: 1ffeaee requests close of that stack descriptor and
returns tag2/error, writing completed phase1. It does not install or release
a retained registration in this arm. The registration helper itself releases
its input reference on error, independently of descriptor close.

Otherwise 1ffeb15..1ffeb23 save the three registration qwords at state+0,+8,+10,
the resulting descriptor at state+18 and the self-pointer at state+20. Both
the fresh and phase3 resume arms reach 1ffeb2a. Resume reads state+20 and
does not request registration a second time. The actual poll relocation at
576f158 resolves to 4f76ce0; its direction argument is 1.

4f76f80 selects its registry subobject by the low bit of the returned handle
tag, adding e0 or 140 to the handle pointer, and rejects the subobject's -1
sentinel at +44 through a diagnostic. Its ordinary direct registration helper
is 4f79100. Native context shows an epoll-control-shaped imported request with
operation1, descriptor from the supplied pointer and event mask80002005 for
interest3; the event data is the allocated registration pointer+80. The
slot576f7f0 is bound by an ELF type6 relocation to epoll_ctl, symbol index54;
the descriptive label is supported independently by that binding.
Allocation/list ownership, lock fairness and actual OS installation are not
established merely by these request values.

## Poll projection and the socket-error query

1ffeb3a reads byte9 of the poll result. Code3 writes output tag3 and retains
phase3, without getsockopt or cleanup. Code2 retains the poll error word and
enters cleanup. Other codes reach the socket-error query, but the bound
ordinary wrapper below emits only 0,2,3; do not claim other codes reachable.

The descriptor is read at state+18. Exactly ffffffff reaches a diagnostic at
1ffec0b; no socket-error query is requested there. Otherwise the code initializes
an int result buffer to zero and its length to 4, then requests the imported
getsockopt at slot576f160 with descriptor, level1, option4, and pointers to
those buffers. The relocation binds the actual symbol, rather than relying on
an inferred source label. Linux socket(7) and getsockopt(2) explain the
SOL_SOCKET/SO_ERROR terminology; numeric predicates here come from this ELF.

The return predicate at 1ffeb92 is equality with -1, not a general negative
test. At -1, __errno_location (slot576e8d8) supplies the low32 error bits.
For other returns the stored int is read and sign-extended; zero means success,
nonzero means error. The returned optlen is not inspected by this body.
Other negative return representatives test the literal branch relation but
are not asserted to be reachable ordinary getsockopt outcomes under its ABI.
The error word is (uint32(error)<<32)|2. A nonzero stored option takes this
path even after a nonnegative getsockopt return. At zero, 1ffeba1..1ffebac
copy the retained registration qwords and descriptor to the output projection,
with phase1, and request no ordinary cleanup. This conditional acceptance is
not a measurement of a completed TCP handshake.

## Why the caller's apparent second close is skipped

The common error path calls 28963c0 before rereading state+18. The helper
FIRST reads the old descriptor and writes ffffffff to state+18 at 28963cb,
before any external call. With an old -1 it returns immediately. Otherwise it
selects the registry subobject by state byte0 (zero versus nonzero), and calls
27a86c0 with a pointer to the old descriptor and state+10 registration storage.
Its ordinary result may carry a boxed error requiring callback/deallocation,
but both ordinary branches join 2896419 and request close of the saved old
descriptor. This close is requested even if deregistration returned an error.

27a86c0's initial imported request has operation2, the registry's descriptor
at +40, the old socket descriptor and a null event pointer. It subsequently
updates a retirement list on a nonnegative return; these ownership effects
require their own allocator/lock/callback premises. It does not directly write
the coroutine's descriptor slot. The surrounding ordinary-return/no-reentrant-
alias premise keeps that slot at -1. Therefore 1ffebcc's redundant -1 guard
skips an additional close, then 1fc1ad0 releases registration resources. A
model that counts one close in the helper and another unconditional close in
the caller is wrong. The claim is a close request count under those premises,
not successful kernel closure or every unwind path.

1fc1ad0 first calls slot576e6e8 (4f778e0), which clears up to two stored waker
slots and invokes their drop callbacks when present. It then decrements the
handle and registration reference counts, using bound slow-release slots
when a count reaches zero. This supports the release-call ordering, not a
global proof of allocation or resource lifetime.

## Cancellation by the actual phase

1fcdac0 phase0 tail-requests close(state+28), including a supplied -1; its body
does not apply the retained-state sentinel guard to the fresh input. Phase3
calls 28963c0, conditionally checks the now--1 descriptor, then tail-calls
1fc1ad0. Thus a non-sentinel retained descriptor causes one ordinary close
request, and a sentinel causes none; registration release is requested in
either phase3 case. All other phase bytes return without these requests.
This destructor does not update the phase byte. All exception/unwind blocks
are retained as context but excluded from the ordinary-return relation.

## Readiness wrapper and reactor sub-boundary

4f76ce0 has a TLS budget boundary before reactor access. In its initialized
TLS state, flag1/budget0 follows 4f76e66 and returns code3 after a wake-helper
request, without reading the reactor readiness word. With a consumed budget,
its non-success poll branches restore the saved budget when the bound TLS
condition allows; do not infer scheduler fairness or wakeup liveness.

It calls 4f5c080 with the registered object+80 and direction1. That helper's
first readiness load is at object+10. Its mask is 5*(direction+1)=a for this
call. A nonzero masked value or bit31 returns directly, with code equal to
bit31. Otherwise it locks the waker table, retains/replaces the direction's
waker using its indirect clone/drop callbacks, and reloads the readiness word.
At this second load, bit31 forces mask a; without bit31, a nonzero low32&a
is ready and zero is code2/pending. Both loads retain bits16..23 in byte8
when a ready record is returned. Those bytes are contextual, not required
by the top caller's result projection.

4f76ce0 maps reactor code2 to poll code3. Reactor odd code invokes the bound
error constructor at576ee60 and maps its result to poll code2. Reactor even
non-2 maps the record to poll code0. A zero budget also returns poll code3.
The actual error-constructor payload, dynamic waker dispatch and concurrent
state transitions remain explicit premises until separately closed. In
particular, readiness alone does not bypass getsockopt, and an empty first
read does not prove the second read remains empty.

## Qualification still required

Retain all selected complete FDEs, GNU/LLVM raw exports, target and source
identities, slot and table bytes, direct-transfer records and opaque-reference
list. LLVM splits LOCK prefixes in several dependency exports; preserve both
raw records, and if comparing a joined partition, join ONLY an adjacent f0
prefix with its exact immediately following instruction, with no omission or
semantic execution. Record the join sites and raw partition differences.

Freeze independent mathematical expected projections before creating any
checker. Exercise pending/error/ready, fresh versus resume, query return -1
versus other negative values, stored zero/nonzero errors, sentinel handling,
phase-dependent cancellation, two independent readiness reads and close-count
negative controls. All this supports a conditional value relation; it does
not substitute for target-grounded native identity checks or establish target
execution, instruction interpretation, compiler/Rust/native ABI equivalence,
full make test, full transport completion or new recovered-byte credit.

References inspected during this intake:
- https://man7.org/linux/man-pages/man7/socket.7.html
- https://man7.org/linux/man-pages/man2/getsockopt.2.html
- https://man7.org/linux/man-pages/man2/epoll_ctl.2.html
