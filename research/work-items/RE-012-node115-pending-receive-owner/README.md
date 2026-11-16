# Pending body receive: same task, same buffer, normal destructor

This packet closes a specific ownership gap left by #7056: when the selected
body receive is pending, the ordinary destructor selected for its actual task
reaches the exact owned buffer recorded by the poller. It supplies static
evidence for a cancellation boundary in a host receive adapter. It does not
claim that every scheduler event, cancellation, or unwind path is covered.

Target `artifacts/node/115/hl-node`, 105896032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
No captured executable was run or emulated.

## Prior work and distinct scope

#7056 reconstructs the owned receive buffer and partial/pending read progress;
it deliberately excludes pending destruction. #6642 covers a greeting failure
consumer and explicitly excludes cancellation ownership and complete nested
drop. The earlier `RE-012-tcp-context-port-115` packet retains the parent poll
functions and TCP context, without this selected destructor-to-buffer proof.
Earlier typed greeting prefix/result/error packets identify the
`0x2b79e30` wrapper, but do not connect its pending state to this actual task's
destructor. #7055 concerns a different send buffer and destructor chain.

This packet reuses the receive allocation/read contracts and adds the
same-object state/offset correspondence through task replacement and its
ordinary destructor. The small generic `0x2ac3470` destructor has the same
receive-body shape, but the proof below follows the **inlined actual parent
destructor** instead of assuming that a generic helper belongs to this task.

## Pointer correspondence

| Name | Same allocation-relative location |
| --- | --- |
| H | input task allocation to `0x2b22010` |
| P | H+0x38, actual future passed to `0x2ad0db0` |
| Q | P+0x2228, wrapper passed to `0x2b79e30` |
| F | Q+0x30 = P+0x2258, receive future passed to `0x2b788e0` |
| D | P+0x20b8, child passed to `0x2aa1c40` during destruction |
| allocation size | F+0x60 = D+0x200 = P+0x22b8 |
| allocation pointer | F+0x68 = D+0x208 = P+0x22c0 |
| nested body future | F+0x88 = D+0x228 |

`0x2b22010` calls the actual poll function with H+0x38. Its state replacement
helper `0x2b30fd0` receives H+0x20. When that cell's old discriminator at
H+0x30 is zero, it calls `0x2aa3920` with H+0x38 **before** copying the new
state into the cell. Thus the polled P and the destroyed P coincide. This is
a selected normal replacement path, not a claim about which external event
caused that replacement or whether one occurred in a recorded execution.

## Pending markers and selected destructor path

`0x2b788e0` allocates the admitted body size, stores size/pointer at F+0x60/
0x68, and forms read slices from that pointer plus progress. For the selected
pending body-read result (`0x2b698f0` returns raw3), it sets F+0x22a and
F+0x230 to3, returns the pending sentinel, and records F+0x48=5.

The actual wrapper `0x2b79e30` sees that sentinel, returns raw2 and sets
Q+0x279=3. The actual parent then sets P+0x2204=3. If its surrounding timer
wrapper at `0x2ad18e2` also returns pending, it sets P+0x2fda, P+0x2fe0,
P+0x2ff0, and P+0x15d to3. The retained initial/resume windows bind the stack
pointers used for those writes to their exact parent fields. The timer's
pending outcome is a premise; a timeout result takes another path.

Given those retained markers, `0x2aa3920(P)` selects:

1. P+0x15d=3, then P+0x2ff0=3, P+0x2fe0=3, P+0x2fda=3.
2. `0x2aa7210(P+0x2048)`, which adds0x70 and calls `0x2aa1c40(D)`.
3. D+0x14c=3 (P+0x2204), D+0x3e9=3 (Q+0x279), and
   D+0x1e8=5 (F+0x48).
4. `0x2aa8ca0(D+0x228)`, the nested body future at F+0x88.
5. After that nested destructor returns normally, load size D+0x200. If
   nonzero, pass pointer D+0x208 and that size to the deallocation binding
   `0x64df4a0→0x635de30`; then clear D+0x1e9, which is F+0x49.

The nested destructor checks its +0x1a2/+0x1a8 fields, exactly F+0x22a/
0x230, before its selected shared-owner/timer cleanup. Its detailed external
timer and allocator contracts are reused boundaries, not newly implemented
here. The zero-capacity case skips deallocation; it is not a missing release.

This establishes the buffer identity and normal drop ordering for the selected
pending state. It does **not** establish idempotence, a live scheduling trace,
exactly-once destruction, full unwinding behavior, or that partial bytes are
delivered to a decoder. The ordinary destructor call does not itself reset
every enclosing future discriminator, so repeated raw destructor invocation
must not be inferred safe.

## Validation

`verify.py --target <captured-file>` verifies16 windows (eight full FDEs and
eight bounded members),2082 instructions,134 selected witnesses, allocator/
deallocator/timer relocation bindings, memcpy, and14 negative controls.
The controls reject mismatched task/child pointers, incorrect pending-state
guards, an adjacent buffer pointer, and release without the nonzero-size gate.
These tests bind the interpretation to static bytes; they are not native
behavioral observations or automatic semantic validation.

The downstream consumer is the owned receive adapter's cancellation contract.
No additional host wrapper was added merely to repeat Rust Vec destruction.
Repository verification, reproduction, catalogue checks, and the safe test
subset must pass before publication. Completing the full peer component still
requires unrelated transport, scheduling, and admission contracts.
