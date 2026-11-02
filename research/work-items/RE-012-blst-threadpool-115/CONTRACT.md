# Node115 BLST lazy-pool construction boundary

Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are linked ELF virtual addresses. This is static evidence of a
public-dependency integration boundary. No captured instructions or services
were executed, and no source-built equivalence is claimed.

## Scope and ownership

Five primary complete FDEs total 2,046 bytes:

| Role | Complete interval | Bytes |
| --- | --- | ---: |
| Once callback A | `0x161a010..0x161a0f2` | 226 |
| Once callback B | `0x161a2e0..0x161a3c2` | 226 |
| Lazy pool acquisition | `0x161a100..0x161a2d7` | 471 |
| Common pool builder | `0x5cd6190..0x5cd6457` | 711 |
| Spawn/result boundary | `0x5cd5ea0..0x5cd603c` | 412 |

The five context FDEs are the two actual consumers
`0x1616e90..0x161806c` and `0x1618070..0x161931c`, the lower spawn wrapper
`0x5cd9470..0x5cd9b2f`, the OS-thread boundary `0x5c87b50..0x5c87d4b`, and
another spawn caller `0x5cd6a20..0x5cd6a6f`. All ten cover 13,711 bytes and
2,932 instructions. Context retention does not implement their whole algorithms.

Actual RELATIVE writers at `0x6403f08` and `0x6403f20` identify the diagnostic
path `z_vendor/blst/src/lib.rs`, lines 45 and 49. Descriptors `0x64c50d0` and
`0x64c5088` name `z_vendor/threadpool/src/lib.rs`, lines 209 and 777.
The full captured path bytes and writer records are retained in `static/records.json`.
They corroborate dependency ownership, not the original revision or license
of any private modifications. Licensed upstream source remains separately
attributed; this packet earns no first-party implementation-byte credit.

This is a lazy shared pool used by BLST consumers, not a demonstrated eager
ELF-startup executor or a census of the node's thread pools. The two retained
consumers call `0x161a100` at `0x1616eec` and `0x16180cc` after earlier input
checks. Both read the resulting shared allocation's `+0x70` word and compare
it with two before selecting further work. Their complete cryptographic and
job-partition semantics remain outside this contribution.

## Initialization and publication order

The lazy getter reads the dword at `0x64f0698`. Its actual file value is three.
A nonzero state leads to the opaque once primitive, through actual slot
`0x64df9f0 -> 0x5c87d50`. The supplied callback vtable at `0x6403ec8` has
raw drop/size/alignment words `0,8,8`; its unique RELATIVE method writers are
`0x6403ee0 -> 0x161a2e0` and `0x6403ee8 -> 0x161a010`.
No poisoning, wakeup or memory-order reconstruction of the once primitive is claimed.

Each callback reads a byte through the pointer loaded from `[RDI]`, writes
zero to that byte, then tests whether its former value was exactly one.
A different value reaches a failure-call boundary before CPU lookup. On the
admitted one-shot path, slot `0x64e1a90` actually resolves to `0x5ba9dc0`.
The getter implementation and interpretation of CPU availability are opaque
here; its returned RAX is the supplied count for this boundary.

A returned zero branches to the assertion boundary with the actual 33-byte
message `assertion failed: num_threads > 0`. It does not call the pool builder.
For a nonzero count, the callback prepares these fields relative to the builder
input pointer:

| Offset | Observed initialized value |
| --- | --- |
| `+0x00` | qword one, explicit-count option |
| `+0x08` | returned CPU count |
| `+0x10` | qword zero, absent stack-size option |
| `+0x20` | `0x8000000000000000`, absent name representation |

The inactive payload words and any padding are not assigned values by this
packet. The common builder is called through actual slot `0x64e1a98`.
After it returns, the callback writes the Mutex state dword and poison byte
as zero, allocates 32 bytes, copies two 16-byte chunks, and only then stores
the allocated pointer to `0x64ffe88` (`0x161a092` / `0x161a362`). The three
padding bytes between the poison flag and the 24-byte pool value are not
initialized by the visible stores; a full deterministic 32-byte image is not
claimed. Nor is this a source-level object-layout identification.

The pool pointer lies in the authenticated writable PT_LOAD zero-fill tail,
initially zero. That says nothing about its live value. On normal acquisition,
the getter loads this pointer after any once call, locks its wrapper, checks
the poison byte, clones the contained pool handles, unlocks, and returns a
24-byte pool value. Contention, poison formatting, reference-count release,
syscall and unwind helper internals remain explicitly opaque. The actual
LOCK instructions and syscall binding are retained rather than modeled as
ordinary non-atomic accesses.

## Requested count and the spawn loop

At `0x5cd6282`, the builder compares the input's **low dword** with one.
Exactly one selects the qword at `+8`. Every other raw low-dword value calls
the opaque CPU getter. This is an instruction relation, not an admission of
arbitrary malformed values as valid Rust `Option` values.

The requested count is stored into the new shared object's `+0x70` field.
The allocation begins with two reference-count words of one; the selected
recorded pool result contains the channel variant one, channel allocation
pointer and shared-object pointer. Other channel/layout details are not
reconstructed merely because their initialization bytes are exported.

The loop increments the requested u64 count once, then decrements before
each zero test. For initial count n, after k completed calls its next tested
value is `(n-k) mod 2^64`. For `0 <= k < n` this is positive, and at `k=n`
it is zero. Thus, conditional on all earlier helpers returning and reference
count increments passing their signed overflow guard, it makes exactly n
spawn-boundary calls. This proof includes n=0 and n=u64::MAX; the initial
increment wrapping does not mean a zero count performs 2^64 iterations.
No assertion inside the builder rejects an explicit count of zero: that
raw path makes no spawn call. The default callback's earlier zero assertion
is a distinct policy, also reflected in upstream's checked public setter.
A huge count is not claimed operationally feasible or immune to allocation,
reference-count or scheduling failure.

Before each call, `LOCK INC` increments the shared strong count and JLE goes
to UD2 on nonpositive signed result. Actual worker concurrency can affect
reference counts. This is not a pure count-only prediction of an execution
with arbitrary concurrent workers. A failure in an earlier spawn prevents
normal completion of the remaining loop and output stores.

## Error propagation and detached successful threads

The spawn boundary preserves the optional name/stack-size relation, then calls
`0x5cd9470`. The name absence test uses the signed-overflow flag of zero minus
its first word, so the sentinel is exactly `0x8000000000000000`. An active
name is copied before the lower call. The stack-size presence byte is tested
for zero; the inactive payload is not read on the absent branch.

The lower wrapper calls `0x5c87b50` through actual slot `0x64e1580`. In the
retained OS boundary, `0x5c87c2b` calls the actual imported `pthread_create`
slot `0x64ec838`. If its low32 result is nonzero, the branch saves that unsigned
error code, disposes of the supplied closure through an opaque helper, and
forms `(u64(error32) << 32) | 2` with RAX tag one. A zero result selects the
created thread identifier and RAX tag zero. Both routes call the actual
`pthread_attr_destroy` import before returning; its nonzero result instead
reaches an assertion boundary. Earlier attribute initialization, stack-size
negotiation, optional dynamic symbol resolution and their failure paths are
retained but not reduced to this pthread-create-only relation.

At `0x5cd97b1`, tag one makes the wrapper write output first word zero plus
the error payload. Its other normal route writes a nonzero allocated handle
word, another handle word and the thread identifier. Back at `0x5cd5f54`, a
zero first word branches to the 43-byte `called Result::unwrap() on an Err
value` diagnostic (the actual bytes include Rust backticks) and its formatting
call. If that failure call were to return, the next branch reaches UD2; no
recoverable error return or global pool publication is present on that route.
The initializer zero/invalid-flag branches likewise have no path to their
normal publication stores through ordinary local continuation.

A nonzero first word takes the success path: `0x5cd5f72` calls the actual
`pthread_detach` import via `0x64dfe50`, then releases two reference-counted
handles as their counts require. Its return code is not tested before the
next decrement. The pool does not retain these thread handles for later joining
in this construction boundary. Previously created threads may already run
when a later spawn fails; no rollback, cancellation or shutdown guarantee is
inferred. Worker code, jobs, cryptographic outcomes and process termination
policy are outside scope.

The packet retains all 147 LSDA call-site entries across the ten bodies and
instruction-aligned landing pads. Action records/personality behavior are
not interpreted; the local unwind cleanup instruction sequences are preserved
without pretending to implement the Rust unwind runtime.

## Public-source countercheck and limits

The official BLST `da_pool` function is byte-identical in selected source
slices from 0.3.15 and 0.3.16: `Once`, a leaked boxed `Mutex<ThreadPool>`,
`ThreadPool::default`, and lock/clone are shared. In official threadpool 1.8.0
and 1.8.1, selected `build`, `default`, `num_threads`, and `spawn_in_pool`
source slices are also byte-identical. The default calls `new(num_cpus::get())`,
while `Builder::build` uses its optional count or CPU fallback; spawning ends
in `.unwrap()`. These licensed sources explain the observed construction
shape but cannot distinguish these versions or establish unmodified vendoring.
`source-comparison.json` records the exact slice hashes; full sources and
licenses are in `source-archive.json.gz` with pinned URLs in `sources.json`.

There is no new Rust runtime implementation, source build, compiled-code
comparison, recovered Cargo graph or native target-output corpus in this
packet. A new wrapper around supplied opaque call results would not close
worker execution, original ABI or synchronization. Static controls instead
challenge the actual byte, FDE, literal, slot-writer and evidence admission
claims. No component gate or whole-node equivalence is requested.
