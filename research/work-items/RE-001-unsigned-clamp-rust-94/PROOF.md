# Three-path unsigned clamp with full RAX and RCX

## Bound function and caller

This proof concerns node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
complete ELF VA interval `[0x15e4f70,0x15e4fb5)`. Its 69 bytes decode to
23 instructions and end in three ordinary return paths. The eleven bytes
before `0x15e4fc0` are `int3` padding, outside the bound FDE. Complete
inventory decoding gives one exact overlapping FDE for the leaf, among
121,299 FDEs and three CIEs. Both primary and caller FDE/CIE byte records
are bound separately from code bytes. GNU and LLVM agree on all bytes and
instruction boundaries in the leaf and full incoming caller.

The complete `.text` E8 byte-pattern census finds one incoming site,
`0x15e482d`. It is a decoded instruction boundary in caller FDE
`[0x15e4610,0x15e4913)`. This interval is **771 bytes** (`0x303`), with
188 instructions. The earlier foundation packet's README calls the same
interval 803 bytes; that length is numerically inconsistent with its own
endpoints. This new packet binds the fresh complete 771-byte body and
actual FDE without changing the historical packet. The caller sets RDI
from RSI, saves RDX into RBX, calls the leaf, then stores RBX and returned
RAX into stack slots. Only this incoming edge and setup/consumption are
claimed, not the caller's other calls or full behavior.

The full E9 candidate census to this entry is empty. All 80,300 RELA
records are scanned: none names the entry as its addend, and none overlaps
the bound leaf or caller bodies. This is not a complete indirect-reference
census. The leaf has no calls or branches outside its bound body, and no
RIP-relative data access or static global/table dependency. Its only data accesses are loads through
the original object pointer.

## All-input arithmetic and register relation

Let `T`, `X`, `Y`, `C` denote the little-endian qwords at original object
offsets 0, 16, 24 and 40, respectively. Only the fields required by a path
need be supplied to the projection. All arithmetic values are unsigned
64-bit values unless the proof explicitly uses unbounded integers.

The first MOV loads all 64 bits of `T` into RAX. TEST RAX,RAX takes the
zero path exactly when `T=0`. Otherwise CMP EAX,1 tests only the low
32 bits, so the second path is selected precisely by `T mod 2^32=1`.
These conditions are disjoint. Tags such as `0x100000001` select the
second path; `0x100000000` selects the other-tag path. No valid-tag enum or
field meaning is inferred.

On the zero path, the body loads `Y` into RAX and then `C` into RCX.
CMP RCX,RAX followed by CMOVB chooses `C` only if `C<Y` unsigned, yielding
`RAX=min(Y,C)` and `RCX=C`.

On the low32-one path, it loads `X` into RCX, clears EAX (thereby clearing
all RAX), and subtracts `Y` from RCX. The subtraction's carry flag is set
exactly for unsigned `X<Y`. CMOVAE therefore copies the difference only
when `X>=Y`. When it copies, the mathematical difference fits in u64 and
coincides with the machine residue; when it does not copy, RAX stays zero.
Thus this stage produces `max(X-Y,0)` in unbounded-integer notation. Loading
`C` into RCX does not affect that value. The final unsigned comparison and
CMOVB yield `RAX=min(max(X-Y,0),C)`, with `RCX=C`.

On every other tag, XOR EAX,EAX clears all RAX, **then the body still loads
`C` into RCX**. Its unsigned comparison against zero can never select a
smaller cap, so RAX remains exactly zero. The cap is irrelevant to RAX on
this path but remains the full final RCX value and is a required native
read. Omitting its availability check is not an admissible reconstruction.

The complete selected-path relation is:

| Tag condition | Required qwords after T, in load order | Full RAX | Full RCX |
| --- | --- | --- | --- |
| `T=0` | Y, C | `min(Y,C)` | C |
| `T mod 2^32=1` | X, Y, C | `min(max(X-Y,0),C)` | C |
| all others | C | 0 | C |

No data is written. RAX/RCX are the modified data registers; flags and
RET's control-stack/RSP effects are excluded. Neither returned value is
truncated to 32 bits. No signed minimum, signed borrow, modulo subtraction
in an underflow case, or logical type inference is substituted.

## Safe supplied-value domain

The independent API takes the already supplied `tag: u64` and optional
copied `first`, `second`, `cap` u64 values for offsets 16, 24 and 40.
It returns both data-register values or `Err(Unavailable)` if a field
required on the selected path was not supplied. It has no mutable state.
`None` means an unavailable supplied value, not a native pointer value or
an assertion about OS page mapping.

Original-memory correspondence requires that the tag and required fields
can be read as complete ordinary little-endian qwords at those original
addresses, remain stable during the call, and equal the supplied values.
Code and return control must be valid and unchanged. The projection does
not read native pointers, create a struct layout, assert process mapping
availability, or emulate native faults. It excludes MMIO/volatile effects,
concurrency, fault timing, access traces, flags, ABI compatibility and
return-control effects. Unused optional values are not inspected, and
there is no premise that they were read from target memory.

A single contiguous image containing both the tag and mandatory cap would
also contain all intermediate bytes. Using explicit copied-field options
keeps path-dependent availability expressible without inventing a sparse
memory engine or requiring unused values. The availability extension is a
safe API boundary, not an alternate native failure behavior.

For `tag=0`, Rust checks `second`, then `cap`. For a low32-one tag it checks
`first`, `second`, then `cap`. Other tags check only `cap`. Therefore the
required supplied-value sets and check order equal the original load sets
and order. Rust's unsigned `saturating_sub` implements the proven nonnegative
difference and unsigned `min` implements the final gate. The returned
struct copies the entire cap into RCX. This proves all admitted numeric
inputs, independently of finite fixture coverage.

## Independent expectations and a preserved coverage gap

Before Rust existed, the original oracle froze 30,896 inputs, outputs and
its own source hash. It computes a positive difference using
`(d+abs(d))/2` over unbounded integers, then a minimum using
`(v+C-abs(v-C))/2`. The availability oracle checks the required set; its
internal check order is not a physical access-trace model. Rust instead
uses typed unsigned saturation/minimum and selected-path checks. Neither
implementation executes or interprets captured instructions.

The original corpus covers extreme and bit-boundary arithmetic, both
subtraction orders, mixed full/low32 tags, all eight optional-field masks
for ten tags, and deterministic random inputs. Four correct native runs
all matched. However, the compiled mutation testing only the low **eight**
tag bits instead of low32 survived: the sole original random tag with
low8=1 and low32!=1 had X<Y, making the mistaken path return zero too.
This was a real qualification failure; its verifier, commands, outputs,
artifact hashes and surviving result are retained under `initial/`.

The original Rust, oracle and corpus were left unchanged. An explicitly
**post-Rust** supplement adds 72 cases, one for each bit 8..31 under three
high-word prefixes. Its separate expectation follows directly from the
other-tag theorem: each tag is nonzero and its low32 exceeds one, so
RAX=0 and RCX=C. Its X/Y/C values force the mistaken low8-one path to return
a positive cap. The supplement freezes its own source and files plus the
unchanged original source/oracle/freeze hashes. It is not described as
pre-Rust evidence.

The final native qualification compares both groups separately identified:
30,896 original plus 72 post-Rust cases, across opt0/opt3 repeated builds.
The input-only client receives no expected values and emits full status,
RAX and RCX, without masks. Compiled mutants must exit normally and produce
actual differences. Comparator and archive corruptions test the checking
path; static corruptions exercise structural checks below the full-target
hash gate. All original and final raw output bytes are archived losslessly.
These are executions of newly authored Rust, not captured-target execution,
instruction emulation, machine-code identity or whole-node equivalence.
