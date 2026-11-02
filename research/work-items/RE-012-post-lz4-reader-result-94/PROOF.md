# Conditional static proof

## Domain and retained scope

C is entry RSI and O entry RDI of reader `0x2049950`; S is its RSP after the
prologue. `qword(P)` is a little-endian raw u64 load. `T = 2^63`. Let the
original triple be `(capacity, pointer, length)` at `C+0x60,+0x68,+0x70`, and
F be byte `C+0x49`. These names describe operand roles; source Rust types,
ownership and allocator semantics do not follow merely from those roles.

The main relation begins when the full reader reaches `0x204aaa5` normally.
Its outgoing cases, shared epilogue and the concrete consumer are covered.
The whole reader is exported and its branch/table structure audited, but its
earlier I/O/timer/header behavior is not claimed as a recovered implementation.

Premises:

1. Entry is through a valid reader/consumer state, not a jump into a machine
   window. Reader entry byte `C+0x48` is in 0..5; each selected reader substate
   and consumer entry state is in 0..3 with corresponding valid initialized
   storage. No local table bounds check makes arbitrary byte states safe.
2. Stack, state, output, input spans and helper-owned storage are accessible
   and suitably disjoint. Successful decoded and original buffers have the
   non-aliasing/lifetime properties required by the displayed requests. No
   reentrant call or concurrent mutation changes the live state/results.
3. Helpers preserve the callee-saved registers and caller-owned live storage
   used after calls, except their specified output regions. In particular,
   timing/statistics and cleanup calls do not overwrite the live decoded
   triple, O, or relevant C fields. This is not proved for the transitive
   helper closure.
4. The ordinary relation is conditional on normal returns from all executed
   helpers. Allocation/panic endpoints, traps, I/O liveness and unwinding are
   excluded. A call's structural return edge is conditional, not a claim that
   its implementation returns. No ABI/source-type equivalence is asserted.

| Role | Full FDE range | Bytes | Normalized rows |
|---|---|---:|---:|
| reader | `0x2049950..0x204ae15` | 5317 | 981 |
| consumer | `0x204ae20..0x204b032` | 530 | 126 |
| reader-cleanup | `0x1fcb690..0x1fcb75f` | 207 | 53 |
| decompressor-context | `0x3d1abc0..0x3d1b62b` | 2667 | 625 |
| statistics-context | `0x3d2a730..0x3d2abf0` | 1216 | 261 |
| difference-context | `0x4ee3730..0x4ee37fb` | 203 | 60 |
| clock-context | `0x4ee3800..0x4ee38c9` | 201 | 48 |
| cleanup-slot-context | `0x54c8cb0..0x54c8d55` | 165 | 31 |

The authentic ELF's actual FDE records and `.eh_frame_hdr` links determine the
ranges; nearest objdump symbol labels are ignored. Every byte is checked
against both native exports. The structural CFG includes landing-pad bodies,
all direct targets and selected computed targets. Two reader indirect calls
remain unresolved (`0x204a3fa`, `0x204adae`, both through `[rax]`); they are
outside the selected ordinary post-LZ4 path. External callees remain boundaries.

## Full dispatch and entry context

`0x2049966` saves C in RBX; `0x2049969` saves O at `S+0x30`.
`0x204996e..0x2049978` initializes `S+0x128` to T on every invocation before
state dispatch. The only other direct store to this stack slot in the full
reader is the success/raw path at `0x204ac82`.

| Dispatch site | Table | Input state | Selected domain |
|---|---|---|---|
| `0x2049992` | `0x3c3d68` | `C+0x48` | 0..5 |
| `0x2049cc3` | `0x3c3d80` | `C+0x238` | 0..3 |
| `0x204a011` | `0x3c3d90` | `C+0x232` | 0..3 |
| `0x2049a2e` | `0x3c3da0` | `C+0x230` | 0..3 |
| `0x2049fca` | `0x3c3db0` | `C+0x22a` | 0..3 |
| `0x204ae49` (consumer) | `0x3c3dc0` | `C+0x281` | 0..3 |

All 26 selected signed-relative entries land on decoded instruction starts.
The reader entry targets for states 0..5 are respectively `0x2049994`,
`0x204a279`, `0x204a26c`, `0x2049a0e`, `0x2049f36`, `0x2049c97`.
States 1/2 lead to terminal/panic paths, not another ordinary completion.
Consumer state 0 initializes the embedded reader; state 3 resumes at
`0x204aea7`; states 1/2 go to panic paths. The subordinate state validity and
initialization relation is a premise, not established by an in-range index.

After admission/allocation, `0x204a211..0x204a21d` stores the original triple
and F=1. `0x204a9e2..0x204a9e9` reaches `0x204aaa5` when the unsigned
remaining-length check is complete. There it tests stored compression byte
`C+0x50`. Prior PR139 owns the original flag/admission/loop facts; this packet
uses the stored-byte predicate and retains the complete surrounding CFG.

## Three selected reader outcomes

### Raw payload

The zero compression-byte branch at `0x204aaa9` goes to `0x204ac6e`.
It clears F and loads original capacity/pointer/length into R12/R13/R15.
It reaches `0x204ac7e` without a cleanup request in this post-read path.
That join clears F again and writes R12 to `S+0x128`.

### Decompression success-shaped result

The nonzero compression path calls `0x4ee3800` with EDI=1, retaining its raw
return words for later timing. `0x204aabe..0x204aad2` then calls slot
`0x5773810` with RDI=`S+0x130`, RSI=original pointer, RDX=original length,
RCX=`qword(C+0x28)` (the prior admission-limit slot).

`0x204aad8` loads result word0 into R12 and word1 into R13. The comparison at
`0x204aaf2..0x204aaf5` distinguishes exactly T. On inequality,
`0x204aaff` loads word2 into R15. Under the prior wrapper's success convention,
these are decoded capacity/pointer/length; this caller does not independently
validate them or compare decoded length against original length.

The live decoded triple stays in callee-saved registers across this sequence:

- `0x204ab13..0x204ab49` obtains another timing pair and calls `0x4ee3730`
  with output at `S+0x130`, replacing the old temporary. The decoded triple
  has already been saved, so this stack reuse does not replace that triple.
- `0x204ab53..0x204ab99` selects zero or computes an XMM0 value from the
  difference result. Full helper bodies are retained as dependency context;
  clock accuracy, arithmetic domain and elapsed-time semantics are not new
  claims of this packet.
- `0x204ab9d..0x204abab` calls slot `0x5773818` with RDI=`qword(C+0x40)+0x20`,
  RSI=decoded length, RDX=original compressed length, and that XMM0 value.
  The RELATIVE target is `0x3d2a730`. Its already-proved prefix adds RSI to
  the first selected counter, RDX to the second and increments the third
  before later sampling. PR592 owns those counter facts; the new fact is
  this reader's argument binding and its position before cleanup.
- At `0x204abb1`, F=0 skips the cleanup request. Otherwise `0x204abbb..0x204abc2`
  tests original capacity. A nonzero capacity reaches `0x204abce` with
  `(RDI,RSI,EDX)=(original pointer, original capacity,0)` through slot
  `0x576e010`. Both skips and the returned call join at `0x204ac7e`.

The join clears F and saves decoded capacity to `S+0x128`.
The exact predicate is **F != 0 AND original capacity != 0**; dropping the
flag condition would overstate the selected machine behavior.

### Decompression error-shaped result

Equality with T branches directly from `0x204aaf5` to `0x204ac53`, before the
second clock/difference/statistics sequence. R13 remains result word1. The
original capacity alone controls the cleanup request at `0x204ac62`; there
is **no F test** on this branch. The arguments are again the original pointer,
original capacity and zero. `0x204ac68` clears F, then jumps to `0x204ac8a`
without replacing the invocation's T at `S+0x128`.

Thus the local reader does not add a new formatting layer to this decompressor
error on this path: it forwards the raw result word1. Prior179 owns the
wrapper's error construction. No particular error object's source type or
complete representation follows here. R15 was not loaded from decompressor
word2 on this branch; the shared epilogue still stores it. Its active error
meaning and initialization as a source-level field remain unproved.

### Shared normal completion and excluded joins

`0x204ac8a..0x204ac9e` writes three raw words to O:
`(qword(S+0x128), R13, R15)`. `0x204aca2..0x204aca4` writes AL=1 to
`C+0x48`, then returns. It does not establish a returned RAX pointer: changing
AL changes that register's low byte. Result storage and state stores are the
contract, not an invented register-return ABI.

The full branch audit also finds header/error routes and chunk-read failure
routes joining `0x204ac53` or `0x204ac8a`, plus pending paths joining
`0x204aca4`. Those entries are not evidence that every execution through the
shared epilogue has gone through LZ4. Pending routes write T+1 to the first
output word and reader state 3, 4 or 5; the rest of their output is not claimed
initialized. The three-way post-read relation above is restricted to normal
entry through `0x204aaa5` and the corresponding selected edges.

## Concrete consumer and completion cleanup

The full consumer `0x204ae20..0x204b032` saves its output pointer in R14 and
its state pointer in RBX. State0 sets up the embedded reader at the same base,
including its state byte0; state3 resumes at `0x204aea7`. At `0x204aeaf` it
calls the reader with result storage `rsp+0x10` and state RBX.

At `0x204aec8`, word0=T+1 causes output byte0=2 and consumer state
`C+0x281=3`, without reading/cleaning a completed payload. This is called
pending-shaped from its raw control role, not a recovered source enum name.

Otherwise the consumer saves reader words1/2, then calls `0x1fcb690` at
`0x204aeeb`. The complete helper loads reader state `C+0x48`, tests 3 and 5,
and returns at `0x1fcb711` for every other value. Therefore, for the selected
reader's completed state1, **no call or buffer cleanup request occurs in this
helper**. It is the state gate, not a hypothetical F check, that establishes
this selected no-op. The helper's states3/5 perform other cleanup work and
are not generalized to completed values.

Next `0x204aef3` compares the saved reader first word with T:

| Reader first word | Consumer's selected normal behavior |
|---|---|
| T | Select byte tag1; forward reader word1 to consumer output+8; bypass decoder and returned-buffer cleanup |
| Neither T nor T+1 | Pass reader pointer/length to opaque `0x28bc630` at `0x204af30`; subsequently request cleanup of the returned buffer iff saved capacity is nonzero |

For the latter path, RDI is a separate 32-byte temporary, RSI is the returned
pointer, RDX is the returned length; additional RCX/R8/R9/stack fields come
from the consumer state and are retained in the native evidence. This is an
argument-shape statement, not a wire-decoder/source-type identification.

After that opaque decoder normally returns, byte0 of its temporary is compared
with `0x12`. Equal selects output tag0 and bytes from temporary+1/+2.
Unequal copies its 32-byte temporary and calls opaque `0x204b040`, selecting
output tag1 with its returned payload. Both routes test the saved capacity:
zero skips, nonzero calls slot `0x576e010` at `0x204af5f` with the reader's
returned pointer/capacity/zero. They join `0x204af6d..0x204af7c`, which writes
selected bytes and the retained payload/word, then consumer state1.

Only the displayed selected fields are established as active under their
conditions. The common byte+1/+2 and word+8 stores do not prove a fully
initialized source enum for the error or success alternatives. The decoder,
error constructor and all source-level meanings are opaque. On the earlier
reader-T branch, common output bytes+1/+2 likewise must not be interpreted as
initialized error fields.

## Cleanup slot and exceptional metadata

Captured RELATIVE records all require type8, symbol index0 and fixed addend:
`0x576e010→0x54c8cb0`, `0x5773810→0x3d1abc0`,
`0x5773818→0x3d2a730`. These bind file-level calls, not live interposition.

The full `0x54c8cb0..0x54c8d55` helper tests size, flags, pointer alignment and
TLS/list conditions. Its local fast path stores the pointer into a list and
updates TLS state; its other path tail-jumps to `0x54c7550`. That fallback and
the allocator's lifetime contract remain open. The proven caller operation is
therefore a **cleanup request**, not physical deallocation or absence of leaks.

LSDA call-site records are separate from structural normal CFG edges:

| Reader call-site range | Recorded landing |
|---|---|
| `0x204aaaf..0x204aab9` | `0x204ad46` |
| `0x204aaca..0x204aad8` | `0x204ad41` |
| `0x204ab13..0x204abb1` | `0x204ad4b` |

The last landing's bytes test decoded capacity R12 and can request cleanup of
R13/R12/0 at `0x204ad7d`, then join `0x204adf0`. That common landing sequence
tests the original capacity, can request original-buffer cleanup at
`0x204adff`, clears F, writes reader state2 and calls `_Unwind_Resume`.
The first two listed landings go to the common original-buffer sequence.
Consumer call-site metadata and cleanup pads are also retained. Action/type
chains and runtime exceptional reachability are not interpreted, so these
facts do not prove that an exception occurs, that both buffers are released,
or that all unwind ownership obligations are satisfied.

## Evidence checks and remaining obligations

The 46 fixed witnesses, six tables, three relocation bindings, actual FDE/CIE
and unwind index, and selected LSDA bytes are checked below the image hash
gate where applicable. The 79 controls change those data plus native output
bytes/rows, LOCK normalization and output-directory safety. A byte outside
selected witnesses passes their subset checks and fails full native comparison,
showing that selected anchors are not a complete-byte proof by themselves.
Two complete regenerations compare every retained export, record and CFG.
These checks validate evidence integrity and decoding, not the manual semantic
argument or opaque call contracts. Empty CFG successors are recorded as `-`.

No model executes captured instructions. No Rust implementation, generic
readiness/timeout semantics, true memory release, lifetime closure, network
compatibility or progress gate follows from this partial result. The direct
consumer makes the recovered distinction useful while leaving its decoder
and allocator dependencies explicit.
