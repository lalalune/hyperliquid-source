# RE-001: node #115 pipeline dispatcher 0x5f88550 with its four call sites

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the 63-byte function
at 0x5f88550 do with one pipeline object — when does it run the
two-phase filtered accumulation scan before the pipeline prologue, when
does it go straight to the prologue, and what arguments does the
prologue receive in either case? The scan and the prologue themselves
are covered by their own items and are referenced here, not re-claimed.

## Windows

* Dispatcher 0x5f88550..0x5f8858f (63 bytes, FDE range as shown in
  frames.txt). The main window of this item, modelled end to end.
* Scan call 0x5f88588 inside the dispatcher: the two-phase filtered
  accumulation at 0x5f77330, pinned by the
  RE-001-two-phase-filtered-accum-115 item (open PR #2362), which
  states the scan takes only the object pointer and returns nothing.
  Its own semantics are not re-claimed here.
* Prologue tail jump 0x5f8857c inside the dispatcher: the pipeline
  prologue at 0x5f884b0, pinned by the RE-001-pipeline-trim-115 item
  (open PR #2345), which states the prologue takes (object, arg2,
  arg3). Its own semantics are not re-claimed here.
* Four direct call sites of the dispatcher (whole-file census,
  reproduced by census.py): 0x5f956ab, 0x5f973b5, 0x5fa01f1, 0x5fa600e.
  Each site's argument setup and post-call step are recorded
  site-only; the caller functions' wider behavior is not claimed.

All windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

The `endbr64` at the head of the dispatcher window is a genuine
instruction present in the target binary, not a placeholder.
Instruction-level detail lives only in the whole-function verbatim
excerpt in main.txt and the four verbatim site excerpts; the JSON in
this packet holds semantic records only. The objdump command that
produced the excerpts is recorded in export_excerpts.py, which
regenerates them byte-for-byte.

## Semantics, stated literally

The dispatcher takes (obj, arg, flag) in (rdi, rsi, rdx) and returns
whatever the prologue returns. Only the low byte of rdx participates
in the branch; the upper bytes of rdx are never tested.

* Flag byte zero: the scan is not called. Control goes to the prologue
  path at once.
* Flag byte nonzero: the scan at 0x5f77330 is called with (rdi = obj,
  rsi = arg, rdx = the caller's rdx unchanged), then control falls
  through to the prologue path. The scan's return value is discarded:
  the scan returns nothing by its own item's contract, and no register
  from the scan survives into the prologue path except through memory.
* Prologue path, in both arms: the qword at obj + 0x10 is read, the
  prologue's object is obj + 0x40, its second argument is
  (obj + 0x10 value + 0x368) mod 2**64, and its third argument is arg.
  The dispatcher then tail-jumps to the prologue, so the prologue
  returns directly to the dispatcher's caller; the dispatcher itself
  has no epilogue after the jump.

So the dispatcher's observable behavior is exactly: scan-then-prologue
when the flag byte is nonzero, prologue-only when it is zero, with the
prologue always receiving (obj + 0x40, [obj + 0x10] + 0x368, arg).

## Call sites (site-only)

* 0x5f956ab, inside 0x5f95280..0x5f957aa: rdi = r12, rsi = r15,
  edx = 0, so this site always takes the prologue-only arm. After the
  call the caller continues with its own bookkeeping.
* 0x5f973b5, inside 0x5f95b80..0x5f98c8d: rdi = a loop element pointer,
  rsi = the first qword of the loop's record slot, edx = 1, so this
  site always takes the scan-then-prologue arm. After the call the
  caller continues its loop bookkeeping.
* 0x5fa01f1, inside 0x5f9fbb0..0x5fa033d: rdi = r14, rsi = rbx + 0x6c0,
  edx = the low byte of (the byte at [[[r12 + 0x60] + 0xd0] + 0x170]
  XOR 1), so the arm is decided by that inverted status byte. After
  the call the caller calls 0x5f93fc0.
* 0x5fa600e, inside 0x5fa4f80..0x5fa63a7: rdi = the qword at the caller
  stack slot -0x268(%rbp), rsi = the caller's incoming r14, edx = the
  low byte of (the byte at [[[r15 + 0x60] + 0xd0] + 0x170] XOR 1), the
  same inverted-status-byte pattern as the previous site. After the
  call the caller continues with its own bookkeeping.

## NOT claimed

* The scan's matching rule, accumulation counters, phases and virtual
  chain (the RE-001-two-phase-filtered-accum-115 item's claim).
* The prologue's steps, its trim, and its later callees (the
  RE-001-pipeline-trim-115 item's claim).
* Caller semantics beyond the site arguments and post-call steps, any
  meaning for the flag byte, the arg, or the obj + 0x10 field beyond
  the routing rule and the argument derivation above.
* What the inverted status byte at +0x170 denotes, or what the loop
  element pointers and record slots at the call sites denote.
* Any return-value contract for the prologue beyond "the dispatcher
  returns whatever the prologue returns".

## Verification

Run the packet checker from the repository root:

    python3 research/work-items/RE-001-pipeline-dispatch-115/verify.py

It checks the binary digest against the provenance entry, the manifest
against every packet file, excerpt regeneration byte-for-byte against a
fresh objdump run, the gate and argument-derivation instructions
byte-for-byte against a fresh objdump run and the raw binary, the FDE
ranges against a fresh frame dump, census consistency, the semantic
records, and the model tests.
