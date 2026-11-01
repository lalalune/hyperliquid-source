# RE-001: production thread-detach / wait cycle, node #94

Bounded question: what does the production poll body at `0x1487370` do before
waiting, how long is its wait request, and how do its nested states resume,
repeat and request cleanup? Component: **node-runtime**. This is static partial
research under RE-001, not a Rust implementation or a completed component gate.

Target: node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Reference: can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
Its `base/production.rs` supplies only an untrusted seed and unknown-name
placeholder for this body. No inferred implementation was copied.

Before this packet the seed did not establish the work/wait ordering or a
finite retry policy. The bytes establish a **repeating detach-then-wait cycle**,
with a nominal **600-second duration request**, distinct parent/child resume
states and only a raw `AL=1` normal return. No worker result is awaited here.
The worker's identity and effects remain unknown. Calling this a failed-work
retry or a fixed-rate job would go beyond the evidence.

## Exact scope and independent exports

All addresses below are linked ELF virtual addresses; ends are exclusive.
`records.json` records file offsets, actual FDE/CIE/LSDA addresses, complete
body hashes, every primary call, source Locations and relocation records.

| Scope | Start .. end | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Production poll, complete FDE | `0x1487370..0x14875bf` | 591 | 147 |
| Shared wait wrapper, complete FDE | `0x14799a0..0x1479d2a` | 906 | 218 |
| Incoming caller argument/result window | `0x14b8004..0x14b8015` | 17 | 4 |
| Existing timer constructor's duration addition | `0x4f65d4e..0x4f65d88` | 58 | 17 |
| Existing clock reader's normal path | `0x4ee3800..0x4ee3830` | 48 | 16 |

The primary export denominator is **2 complete FDEs / 1,497 bytes / 365
instructions**. The three supporting windows add **123 bytes / 37
instructions** and do not constitute three additional recovered functions.
GNU and LLVM agree on all retained instruction starts and bytes. LLVM's
standalone `F0 / lock` rows are joined to the immediately following instruction;
no target bytes, addresses or operands are masked. GNU readelf independently
agrees on the two FDE headers. These are static export comparisons, not
compiled Rust matches or a whole-node coverage percentage.

The `.text` E8 byte-candidate scan finds one call to the primary body,
`0x14b800c`. Both decoders start at its owning FDE
`0x14b7cf0..0x14b8179` and confirm the retained argument/call/result window.
No `R_X86_64_RELATIVE` addend points to the primary entry. This is not a census
of arbitrary register calls, computed pointers or all possible callers.

## Production cycle observations

Let `P` be the incoming `rdi`; the context from `rsi` is preserved in `r14`.
The relocated panic Location at `0x566c590` binds the path
`/home/ubuntu/hl/code_Mainnet/base/src/production.rs`, line 120, column 61.
That is source context for this poll body, not an original function name.

| Operation | Instruction evidence | Result |
| --- | --- | --- |
| Dispatch | `0x14873b4..0x14873cf` | `P+0xc8 == 0` initializes; `==3` resumes the wait; other values call the established resumed-after-panicking helper through `0x576f038`. |
| Call work constructor | `0x14873e2..0x1487408` | Call `0x1448270` with an output at `rsp+0x18`, a descriptor whose first word is `0x8000000000000000`, and zero `edx`, `r8d`, `r9d`. Its full semantics are outside this packet. |
| Constructor result | `0x1487408..0x1487439` | A zero first output word takes the error/formatting path. Otherwise the third output word is passed to `pthread_detach`; its return value is not tested. |
| Release returned ownership | `0x1487439..0x1487460` | Decrement each of the first two returned pointer targets with `lock dec`; invoke the separately bound slow path when the count reaches zero. Concrete allocation types remain unknown. |
| Initialize wait | `0x1487460..0x1487475` | Store binary64 bits `0x4082c00000000000` (exactly 600.0) at `P+0x28`; clear the child outer state at `P+0xc0`. |
| Poll wait | `0x1487475..0x1487484` | Call `0x14799a0(P+0x28, context)`. Nonzero `AL` takes suspension; zero takes the repeat path. |
| Repeat | `0x1487484..0x14874ac` | If both child states at `P+0xc0` and `P+0xb8` equal 3, request cleanup at `0x147ee10(P+0x40)`; then go back to the constructor. Otherwise go straight back. |
| Suspend | `0x14874ac..0x14874ef` | Set parent state 3, call the optional exit hook, and return `AL=1`. This is the body's only `ret`. |

The external detach binding is **not** a relative relocation with target zero:
slot `0x576f4a8` is `R_X86_64_GLOB_DAT`, symbol index 51, naming the undefined
dynamic symbol `pthread_detach`. Both the relocation and the `.dynsym`/`.dynstr`
chain are checked. The constructor-error arm at `0x14874f0` passes a separate
Location, `std/src/thread/functions.rs:131:29`, to its formatting/panic helper.
No success of thread creation or detachment is guaranteed by this packet.

There is no finite retry counter, success-completion branch or normal raw-zero
return in this body. If the wait reports zero, the next constructor call occurs
in the **same poll invocation**. Under ordinary helper returns, a completed
wait therefore triggers another work request, rather than completing the parent.
Timing includes work-constructor overhead and scheduler delay; 600 seconds is
a requested duration after the work request, not a measured period.

The optional entry/exit calls use the descriptor at `P+0..0x18`. Tag 2 skips
them. Otherwise the callback table is `P+0x10`, with entry slot `+0x60` and exit
slot `+0x68`; odd tag adjusts the data pointer by
`((table[+0x10] - 1) & ~15) + 16`. These indirect callback targets and their
concrete types remain unresolved. An exit hook is also present on the
unwind-shaped tail. No specific tracing framework is asserted.

## Nested wait states and the 600-second argument

Let `W = P+0x28`. The timer object begins at `W+0x18 = P+0x40`.
The two dispatches use **signed 32-bit relative entries**, not absolute pointers:

| State byte | 0 | 1 | 2 | 3 |
| --- | --- | --- | --- | --- |
| Outer `W+0x98`, table `0x21a450` | `0x14799cc`, initialize | `0x1479c7f`, completion panic | `0x1479c72`, panicking panic | `0x14799eb`, dispatch inner |
| Inner `W+0x90`, table `0x21a460` | `0x1479a09`, convert duration | `0x1479c9b`, completion panic | `0x1479c8c`, panicking panic | `0x1479c31`, poll existing timer |

Every table entry and destination instruction boundary is verified. Values
outside 0..3 are not range-checked by these jump-table instructions; no safe
behavior is claimed for corrupt state. The child source Locations bind
`base/src/lu.rs:60:46`, `:71:57` and `:72:5`. It is a **shared** helper, also
called from the already inventoried Slack alert slice, not exclusive production
code. Existing `channel-locations-94` establishes the common panic-helper labels;
this packet binds their two relocation slots and the new caller Locations.

On the production input, 600.0 is nonzero and nonnegative. The floating-point
bit conversion takes these visible arithmetic steps:

1. Exponent `0x408` falls in `[0x3ff, 0x433)` at
   `0x1479a7d/0x1479afc`.
2. Restoring the implicit bit yields significand `0x12c00000000000`.
   The right-shift count is 43, giving `rsi=600`.
3. The fractional lane `(bits << 9) & ((1<<52)-1)` is zero.
   Its multiply-by-1,000,000,000 and rounding/carry lane therefore leaves `edx=0`.
4. At `0x1479b97`, the call through slot `0x576f728` receives `(600, 0)`
   plus the output address and `lu.rs:72:5` Location. The slot relocates to
   `0x4f65d40`, previously identified as the timer constructor in
   `RE-002-hyper-fork-url-pin`.

This is a manual arithmetic derivation for **one exact input**, checked against
retained instruction bytes; the verifier is not an x86 interpreter or a proof
of general binary64-to-duration conversion. Negative, fractional, NaN, infinity
and other magnitude paths are retained in the complete export but not recovered
here.

The supporting constructor window saves `rsi/edx`, calls `0x4ee3800` with
`edi=1`, adds the saved first word to the returned first word, adds the second
word to the returned nanosecond word, and compares against 1,000,000,000.
The clock-reader window calls the dynamically bound `clock_gettime`, returning
the timespec seconds in `rax` and nanoseconds in `rdx` on its normal path.
Thus `(600,0)` requests a 600-second offset. Clock failures, overflow fallback,
runtime timer availability and actual wake timing are not resolved by these
partial supporting windows.

The constructed timer occupies `W+0x18..W+0x90`. At `0x1479c3b` the child
polls it through slot `0x576f088 -> 0x4f68f00`. A nonzero result is returned
with both child states set to 3. A zero result first calls cleanup
`0x147ee10(W+0x18)`, sets both states to 1, and returns zero. In particular,
a normal completion has already changed the outer state to 1, so the parent's
paired `==3` cleanup guard is false. The parent repeats without a second cleanup
request. The resumed path polls the existing timer rather than constructing a
fresh timer on each wake.

## Failure paths and remaining closure gaps

The parent contains a cleanup route at `0x1487555` guarded by both child state
bytes being 3, followed by a parent-state-2 write at `0x148757b`. The child has
state-2 writes at `0x1479d10/0x1479d15` and conditional cleanup routes before its
unwind-resume call. FDE/LSDA addresses and these instructions are retained, but
**LSDA call-site tables are not decoded**. This does not claim exact exception
edges from every call, panic-free cleanup, or complete destructor semantics.

`records.json` enumerates every call in the two primary bodies: direct targets
with FDEs where available, RIP-relative slots with raw relocation records, and
unresolved table calls. The following remain outside the recovered contract:

- worker constructor `0x1448270`, its closure and thread entry; what work is done;
- slow reference-count release helpers `0x4f049e0` / `0x4f581b0` and cleanup
  `0x147ee10`, beyond their call arguments and local guards;
- full timer constructor/poll/scheduler, callback vtables, allocation and panic
  helper closure; generic wait-helper input behavior;
- original source names, public Rust ABI, cross-release behavior and whole-node
  equivalence. No independently authored Rust or compiled comparison is supplied.

No captured code was executed or emulated. No live endpoint, user configuration,
filesystem worker effect, signature, chain action or paid dataset was used.
Next question: bind the closure passed into `0x1448270` and its native thread
entry before assigning a purpose to this recurring production task.

## Reproduce and validation

Run from the repository root after materializing the pinned artifacts. Recorded
tools: Python 3.14.7; GNU binutils 2.47.20260726; LLVM 18.1.4; x86-64 Intel syntax.
On macOS, put the installed GNU binutils and LLVM directories before the system
utilities on `PATH`. Only static parsers/disassemblers run.

```sh
python3 research/work-items/RE-001-production-wait-cycle-94/export_disassembly.py
python3 research/work-items/RE-001-production-wait-cycle-94/verify.py --controls
python3 -m unittest discover -s tests -p test_production_wait_cycle.py -v
make doctor verify test catalogue-check reproduce
```

The two export providers decode each complete owning FDE before support windows
are selected. Export regeneration is byte-for-byte repeatable with the recorded
tool versions. `verify.py --write --controls` intentionally regenerates records;
without `--write`, mismatching retained results are rejected.

Four focused tests pass. They regenerate the complete record from the real
capture, reject a wrong whole-image digest, exercise full export equality on an
instruction outside the semantic obligations, and reject **58/58** mutations
below the image/body-hash and export guards: instruction spans, all eight state
table entries, relative targets, dynamic import names/types, Location records
and both FDE extents. `controls.json` preserves every rejection. These controls
protect the evidence bindings; they are not runtime differential test cases.

The complete repository result, exact tested commit, commands and log digests
are recorded in `validation.json`. Its isolated per-file runner uses the official
`tools/run_tests.py:test_files` inventory, exactly once per module; the extra
worktrees prevent tests that write shared `work/` paths from colliding.
`overlap.json` records the live all-state PR audit and adjacent work. No progress,
component, catalogue, reference pin or byte-coverage registry is changed.
