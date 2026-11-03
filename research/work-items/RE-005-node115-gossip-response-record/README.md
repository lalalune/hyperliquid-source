# RE-005: scalar record in Node115 GossipRpcResponse

Component serialization; RE-012 node-runtime/gossip context. Sole target Linux
x86-64 node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base main8fd8db680ec4bfef40996e5616bce3d5156d0b86. Addresses below are ELF
image virtual addresses, never runtime-rebased or retired-node coordinates.

## Bounded question and prior work

Recover the whole scalar record at5aabd20, including all logical result,
remaining-input and charged-count exits, and bind its actual response caller.
This active base has no implementation at the new source path. The complete
GossipRpcResponse is not claimed: its other variants include container,
allocation, callback and unwind paths that remain unclosed.

PR2300 covers different precharged four-read callers at2cd7d90/5821540 and the
shared u64 reader. We reuse its exact MIT reader, without primitive credit or
old standalone tests. PR2414 concerns a different request type at5aac6a0 and is
not modified. Public exact5aabd20 andGossipRpcResponse PR searches returned0 at
selection. Reader/library and comparator-scaffold reuse are in derivation.json;
retained licenses and provenance hashes bind the public source.

## Native observations

records.json authenticates the entire target, actual FDE/CIE raw records,
selected bodies, all called-reader RELA records, both signed jump tables and
native operands/data. decoded-closure.json checks every GNU instruction byte
and every selected call against the authenticated image. Raw exports are
unmodified. GNU objdump2.47 commands are retained with each extent.

| Whole FDE range | Bytes | Scope |
| --- | ---: | --- |
| 5aabd20..5aabf7a |602| Whole selected scalar record |
| 5821250..5821335 |229| Reused u64 reader wrapper |
| 58225c0..58226fc |316| Reused short u64 reader |
| 5822700..582270e |14| Active invalid-marker error fields |
| 5aac7c0..5aacc22 |1122| Response caller context only, not whole implementation |

The closed record/reader physical evidence denominator is1161bytes. The1122
context bytes are separate, not credited as implemented. No compiled-target
byte comparison or registered byte coverage is claimed.

The record calls the u64 reader at5aabd39/5aabd58/5aabd78/5aabd98. It then
reads one optional-marker byte; marker0 selects absent,1 calls u64 at5aabe33,
and other byte values produce native tag5/index after consuming that marker.
The raw native diagnostic at9173df names
`core::option::Option<l1::node_types::round::Round>`. Field units and original
Round/source struct layout remain unknown. Four scalars and the optional
scalar are the only values exposed by the safe Rust projection.

The actual call5aac886→5aabd20 is in GossipRpcResponse variant2's outer-present
branch. The parent owns a separate outer marker; this record starts at its
four scalar fields, so no outer tag or marker is silently consumed twice.

Canonical limited mode1 uses context limit+8, slice pointer+16, remaining
length+24, charged+32. Each u64 is charged8 before its input read, separately;
there is no aggregate32reservation. Optional-marker charge1 overflows without
a count store; otherwise count+1 is stored before testing the old count>=limit
(equivalent to next>limit under the observed overflow guard). On refusal the
stored count remains and the marker is not consumed. Missing marker input is
checked after charging. Successful None normally charges33; Some41. Unlimited
mode preserves the supplied count exactly.

The reused u64 routes accept nonminimal encodings. Empty input reports need1;
short marked truncations retain the consumed marker but not partial payload.
Remaining>8 takes the fast route; invalid FE/FF leave its cursor unchanged and
use expected_raw2, whereas short routes consume the marker and use3. Both
actual relative helper bindings64e6c38→58225c0 and64e7f78→5822700, signed
dispatch tables935bdc/935c24 and little-endian wrapper argument are recorded.
No unclosed diagnostic calls are substituted inside this selected relation.
Native error padding/inactive fields and formatting are excluded explicitly.

## Pre-Rust expectations and implementation

The35692-row corpus and static equations were committed in
`31d9307cd02508d98597a64cef3aa5f022a3cabf` before the new lib.rs existed. The committed corpus is
byte-identical now, SHA256 c1c8ae2a3dfc16c6fe46af66e7531b68e6076456dfcc5a77c41717240bc9a291. This oracle is independent
branch mathematics, not reused Reader execution, machine-code emulation or
captured execution. It remains a fallible human interpretation of target bytes.

The independently authored no_std record implementation composes the unchanged
MIT u64 Reader, adds only the observed optional-marker/state behavior, and
returns the remaining slice on all exits. It does not call read_four because
that API precharges32 and changes error states. Error labels project only
active native fields; success records preserve order and suffixes.

comparison.json reports real Rust1.95.0/LLVM22.1.2 opt0/3:35692matching rows each,
repeat outputs and same-basename repeat rlib bytes equal,7unit tests/profile,
5compiled semantic mutations detected and2actual native-operand controls.
Mutations cover precharged read_four reuse, swapped fields, charge2, invalid
marker rollback and accepting marker2. Native controls alter the limit JAE
operand and Some marker; production authentication rejects both modified
images and isolated static relations provide concrete changed witnesses.
No modified original image is executed. Linux x86_64 rlibs build at both
optimization levels, without execution. Compiler/linker/dependency/source and
fixture hashes are in the result. Local offline Cargo lock, fmt check,
all-target build,7debug+7release library tests and clippy-Dwarnings pass.

The initial mutation harness selected Ok(fields) in both a return and match
arm after both production profiles passed. The unique return selector fixes
that harness failure; original logs and artifacts stay preserved. No production
Rust or expected row was changed for it. Real commands are in the component
README. All command stdout/stderr and probe outputs are retained under ignored
operator output storage, never silently normalized. Repository-required checks
and any failures are reported separately in the PR.

## Limits and next question

No original Rust ABI, inactive/padding values, unsafe pointer aliasing, malformed
pointer storage, arbitrary raw context modes, source-field units, generic
Round invariants, original dependency/compiler/source lock, response container
semantics or full-node integration is established. Physical FDE evidence is
not machine-code equivalence. The full response caller contains unclosed
allocator, callback and unwind paths and is context only. No component gate,
acceptance percentage or byte-window registry changes. Next: establish the
record's field meanings and the sibling response/container paths from actual
consumer/decoder closure rather than guessed labels.
