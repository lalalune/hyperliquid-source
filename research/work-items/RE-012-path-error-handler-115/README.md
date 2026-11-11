# RE-012: resolve node115 path-error first-slot calls as destruction

Component: foundation; task RE-012. Sole target Linux x86-64 node #115,
105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; original ELF VAs,
no rebasing, byte masking, captured execution or instruction emulation.
New project-authored static research and scripts are MIT.

## Gap and result

The earlier temporary-path factory result, PR #2793, leaves calls through the
wrapped error object's first function pointer opaque. It therefore conditions
both fallback and all-failure returns on those dynamic calls returning.
This packet traces the **actual selected producer and function table** through
allocation, writes, RELATIVE relocation and destruction. It resolves those
particular calls as freeing an erased owned-message error, rather than a
reporting, exit or abort dispatch.

That is a new lifecycle result, not a re-export of the factory: the latter's
915 bytes are retained only to bind concrete source pointers and continuations.
No new Rust, full component gate or byte equality is claimed. A fresh origin
main fetch and live open PR inventory on 2026-11-04 found #2793 but no competing
path-error lifecycle outcome. Publication must refresh live scope again.
No issue was opened, drafted or claimed.

## Concrete producer chain

`0x1500b90..0x1500c03` is the path-aware wrapper used after a nonzero directory
preparation result. It saves the incoming error word at stack+8, formats the
path pair and that error with descriptor `0x431532` (`ensure_dirs ...: ...`),
and calls `0x150d950` with the local argument-record address at stack+0x10.
After construction it calls `0x150c590` on the original I/O error and returns
the newly constructed pointer.

`0x150d950..0x150d98a` distinguishes a compact literal representation by the
low bit of its argument pointer. For this concrete wrapper's stack-aligned
argument records the bit is zero, so it calls format-builder slot
`0x64df6e8` -> `0x141e3a0`, then `0x14cbdd0` with the resulting owned triple.
The literal branch exists but is not selected by this stack-record call; no
claim is made that its alternate object has the same table or layout.
This relies on the normal Linux x86-64 stack/calling convention, not arbitrary
malformed pointer inputs.

`0x14cbdd0..0x14cbe3e` acquires a 48-byte auxiliary/backtrace-like result
through slot `0x64e00b8` -> `0x5c8afb0`. It passes that result and the owned
message to `0x14cc590..0x14cc637`. The latter:

* places function-table address **0x63fa198** in the first local word;
* copies the 48 auxiliary bytes at local offsets +8..+0x38;
* appends the owned message triple at +0x38/+0x40/+0x48;
* requests **80 bytes** and, after a nonnull allocation, copies those exact
  80 bytes to the object and returns its pointer.

`layout.json` gives the offset and producer of every field. The selected
allocator binding is `0x64df480` -> `0x6355830`; its full implementation is
outside this outcome. The explicit null-allocation failure path calls its
allocation-failure helper. Constructor landing pads use the partial destructor
`0x14c4960` and preserve unwind cleanup; no successful allocation is assumed
merely because a static plan exists.

## First-slot target and normal destruction

There is a unique R_X86_64_RELATIVE relocation with destination **0x63fa198**
and addend **0x14cb790**. The zero bytes in the captured table slot are not
mistaken for the runtime function address. The constructor's actual LEA and
object store bind this table to the concrete object returned by the path wrapper.
No table-length or standard Rust trait-vtable header is inferred from nearby
words; this is the selected first slot of an erased-error function table.

Factory sites `0x150321c`, `0x1503239` and `0x1503274` each load the first
pointer from the constructed object and call its first slot. For this producer
they therefore call the complete FDE **0x14cb790..0x14cb802**. Its normal
sequence is:

1. If the dword at object+8 is 2, call `0x1553950(object+0x10)`.
2. If message allocation count at object+0x38 is nonzero, call deallocation
   slot `0x64df4a0` with pointer object+0x40, size object+0x38 and EDX=0.
3. Tail-call the same deallocator with pointer=object, size=80 and EDX=0.

This establishes ownership destruction: the message is released before the
80-byte enclosing object. The corresponding unwind landing pad also releases
the message and enclosing allocation, then resumes unwinding. The partial
constructor destructor uses the same auxiliary/message cleanup but does not
free an enclosing allocation that was never successfully returned.

Slot `0x64df4a0` resolves to `0x635de30..0x635ded5`. Its selected fast path
updates allocator-local free state and returns; the other route tail-calls
`0x635c6d0`. That slow allocator remains a boundary. In particular the first
slot is not identified as a panic helper just because a destructor may unwind.
There is no explicit logging, exit, abort or panic call in the selected
owned-error destructor's normal body.

## Auxiliary and original-error lifetime boundaries

The retained acquisition `0x5c8afb0..0x5c8b14c` returns outer tag 1 when
capture is disabled, or calls capture `0x5c8ae00..0x5c8afaf`. The latter
has concrete outer-tag 0 and 2 stores. Its owned capture route writes outer
2 and inner cleanup state 3. The object destructor's outer-tag comparison
matches this layout: auxiliary begins at object+8, and the cleanup subobject
begins at object+0x10.

`0x1553950..0x1553a8c` inspects its subobject dword+0x20. States 0 and 3
walk 0x38-byte frame records through `0x1538cb0`, then release the backing
allocation using count*0x38; state 2 returns without that walk. Other states
have an explicit panic-helper route. The actual newly captured path supplies
state 3, but arbitrary memory corruption or other runtime producers are not
asserted valid. `0x1538cb0..0x1538d6a` releases nested buffers and the
0x48-stride nested array through the same deallocator; its imported deallocator
is retained as a live boundary, not replaced with a mock.

The **original I/O error** passed into `0x1500b90` has a different destructor,
`0x150c590..0x150c661`. Its low-two-bit representation test selects a heap
case for value 1. In that case it can invoke a separately supplied trait
destructor, release that payload by its supplied layout, then release the
24-byte outer allocation. Non-heap encodings return without that work.
The arbitrary supplied payload destructor is not the known owned-message
first-slot target and is not silently treated as pure or non-terminating.

## Consequence for the factory

For **valid objects from this concrete producer** and normally returning
auxiliary cleanup and allocator boundaries:

| Factory route | Destruction and continuation |
| --- | --- |
| Primary preparation fails, fallback succeeds | Copy full fallback owned triple to output; destroy primary wrapped error; release primary path buffer; return fallback |
| Both preparation attempts fail | Destroy fallback wrapped error; release fallback path buffer; destroy primary wrapped error; copy and return original primary path |

Thus those dynamic calls do not by themselves establish diagnostic emission,
process termination, Result return or fallback failure propagation. The exact
known calls free constructed errors. This does **not** prove that allocation,
formatting, capture, original I/O-error trait destruction or all unwind paths
can never fail or terminate. It narrows the former opaque boundary to actual
destruction and keeps these remaining effects explicit.

## Evidence, controls and reproduction

Fourteen complete FDEs total **3696 bytes / 984 instructions**, including the
factory and format-builder contexts, concrete constructors, owned/partial
error destructors, acquisition/capture contexts, auxiliary/frame cleanup,
original I/O-error destructor and selected deallocation wrapper. These are
export sizes, not newly understood or reconstructed byte totals.
`records.json` binds exact bodies, complete actual FDE/CIE bytes, LSDA
addresses, 87 calls, 126 branch records and all encountered relocation writers.
Dynamic edges remain dynamic; no complete whole-program CFG is claimed.

GNU objdump, LLVM objdump and Capstone agree on every instruction byte in
those extents. GNU readelf independently confirms all FDEs. Only LLVM's
separate LOCK row is joined to its contiguous instruction; no bytes are
normalized. `tools.json` records the observed versions and options are in the
collector. Existing digest-bound tools and imported artifacts remain unchanged.

```sh
python3 -B research/work-items/RE-012-path-error-handler-115/collect.py --out work/fresh-path-error-export
diff -u research/work-items/RE-012-path-error-handler-115/records.json work/fresh-path-error-export/records.json
python3 -B research/work-items/RE-012-path-error-handler-115/verify.py --out work/fresh-path-error-check.json
```

The verifier reproduced the retained record, rejected **35 actual instruction
corruptions and one descriptor corruption** without relying on the full-file
identity guard, rejected **five actual relocation-addend mutations** including
the selected table slot, and rejected two wrong/truncated capture controls.
Overlapping instruction obligations are checked individually by name: an
initial qualification attempt incorrectly expected a global checker to name
the currently mutated obligation even when an earlier overlapping pin failed
first. That qualifier assertion failed; selecting the named narrow obligation
fixed the control without changing any target fact. `validation.json` records
this observed initial failure and the subsequent successful qualification.

All controls are static and execute only newly authored Python parsers;
there is no captured process, instruction interpreter, filesystem operation,
network test or peer-runtime comparison. `qualification.json` records actual
results. Parent publication owns fresh repository/catalogue checks. No hosted
CI, container success, Rust behavior equivalence, whole error subsystem closure
or completion percentage is claimed. All 92 component gates and byte
comparison totals remain unchanged.
