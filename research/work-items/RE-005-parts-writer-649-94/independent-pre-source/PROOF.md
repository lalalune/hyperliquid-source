# Independent normal byte-request relation of the 649-byte writer

The qualified primary is node94 VA `0x1572b20..0x1572da9`, 649 bytes,
169 contiguous instruction rows, SHA256
`8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3`.
Target SHA256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Root's fresh whole-target intake is bound by ADMISSION SHA256
`9cfc39596eb319bb0aaf7a81250089b1dc550ab175611216f46d5e745f4061f3`.
This independent reading began with the actual complete raw/listing, then
challenged root's separately authored theorem; no new implementation was read.

## Qualified domain and entry roles

The native entry roles are a fixed writer-data pointer, a fixed writer-table
pointer and a readable 32-byte descriptor. The descriptor contains prefix
pointer/length followed by part-array pointer/count. Every selected part is
24 bytes. These are observed field reads, not an asserted original Rust type
or enum ABI. Arrays and pointer arithmetic are valid, nonwrapping and readable;
all actually requested nonempty slices have immutable readable storage of length at
most isize::MAX. Descriptor, active part records, referenced byte storage,
code, constants and active frame remain immutable and separated from writable
aliases. Inactive trailing part records may contain arbitrary words. Zero-run
counts are full unsigned u64 and are not constrained by byte-view allocation.

The chosen safe projection replaces pointers with stable u64 logical tokens
and explicit immutable byte-view bindings. Token addresses and pointer identity
are not observed. Requested raw slices, including empty raw parts, have a
declared valid byte-view binding. An empty prefix is not requested and requires
no view binding. Records after an earlier failed callback are never visited;
their view-looking words need no binding. No UTF8 decoding, check or scalar count occurs in these 169
rows: arbitrary bytes are admitted by this byte-request projection. This does
not assert an original nominal string representation or renderer ABI.

The writer table has one live method Cell corresponding to the actual +0x18
slot. Supplied normal callbacks may change method Cells and a separate borrowed
observer state; all effects occur in order before their raw u8 reply. They
preserve ordinary caller-live roles and do not mutate protected storage or
retain an expired numeral scratch-buffer pointer. Logical writer state and
table tokens remain fixed entry values. Faults, unwinding, concurrency, invalid
aliases and native ABI/rendering identity are excluded. No native formatter
header field is introduced by the chosen observer state.

Immutable records are a real restriction. Native prefix pointer/length are
read before a prefix callback, whereas array pointer/count are read afterward,
and later part words are read as traversal reaches them. A theorem allowing
callback mutation of those fields would require a different live-read model.
That stronger mutable-input theorem is not claimed here.

## Prefix, count and exact raw record selection

The prologue preserves descriptor at 0x1572b31, table at 0x1572b34 and writer
data at 0x1572b37. Prefix length is read at 0x1572b3a. If zero, the callback
and prefix-pointer read are both skipped. Otherwise prefix pointer is loaded
and the current +0x18 method is called once with the entire prefix. Any nonzero
low-byte reply takes the explicit return1 path; parts are not visited.

Part count is read only after prefix success/skip. Count0 returns0 without
reading a part or array base. For count>0, endpoint is base+24*count; successful
parts advance exactly24 bytes and compare against that fixed endpoint. The
readable/nonwrapping array invariant proves every active field access and
termination of finite part traversal. Only the first count provided records
participate; pointer/view-looking words of inactive records are never resolved.

The complete 16-bit tag at offset0 selects:

* tag0: full u64 zero-run length at offset8; offset16 and upper tag-word bits
  are not used for requests;
* tag1: u16 numeral at offset2, hence bits16..31 of the first logical word;
  both later words and the upper32 bits are ignored;
* every other u16 tag: byte pointer/token at offset8 and length at offset16,
  always submitting one request, including length0. This is not tag validation
  and does not collapse tags by their low byte.

The data/table identities for all calls are fixed input roles. Prefix, numeral
and raw-part calls each reload the current method at their own call. All
nonzero replies normalize to1; complete success or an entirely empty sequence
returns0. There is no raw-status forwarding path. Callback state/method
changes survive both success and failure. The helper performs no direct store
to descriptor, parts, writer data, method Cells or observer/context state.

## Zero-run request partition and method lifetime

Zero count0 jumps to part advancement without a callback or method read. A
positive run loads one method value from the fixed table, then retains that
value for its entire run. Actual RIP references at 0x1572c28 and 0x1572c80 both
reach the immutable 64-byte ASCII0 literal at 0x252cb8. Root's all80,300-record
RELA interval census finds no writer overlapping this literal or selected body.
The function has five dynamic callback call sites and no fixed callee/GOT edge.

For n>0 let q,r be the unique integers n=64q+r with 1<=r<=64, equivalently
q=(n-1)//64. The successful sequence is q requests of64 zero bytes and then
one request of r zero bytes. Native enters the repeated64 path for n>=65,
subtracts64 only after a successful call, and repeats while remaining>64.
The final remainder is always1..64. Thus n64 is one request; n128 is two
requests, and neither introduces an empty tail. There are ceil(n/64) requests.
Each subtraction is safe and strictly decreases a positive remainder, proving
finite termination for every u64 n. Even n=2^64-1 needs no overflowing total-
byte accumulator; its theoretical number of requests is exactly2^58.

A failed request stops immediately with1 and does not require any further
view/method resolution. Every request in this zero run uses the same method
identity even after callbacks mutate the live Cell. On success the table role
and part endpoint are restored from their cached roles and next-part traversal
reloads the then-current method. A failure needs no local restoration before
return: ordinary callee-saved epilogue preservation still occurs, and no new
external memory store is introduced.

Huge successful zero runs are part of the structural theorem. The finite
supporting corpus need not execute astronomical traces; its large-u64 cases
use supplied early failures and its bounded successes exercise all chunk and
tail boundaries. No truncation, cap or synthetic success is permitted in the
actual independently authored implementation.

## Complete u16 decimal relation and scratch initialization

The numeral is zero-extended from offset2 and ranges over all65536 values.
The native length expression is a fixed integer function; n0 selects length1.
The independent finite challenge compares this length against decimal thresholds
and all emitted bytes against the separate ordinary decimal numeral definition.
It carries no PC, register file, simulated memory or instruction dispatch.

The fixed reciprocal quotients are floor(n/10), floor(n/100), floor(n/1000),
floor(n/10000). Their native expressions are respectively

    n*0xcccd // 2^19
    (n//4)*0x147b // 2^17
    (n//8)*0x20c5 // 2^20
    (n//16)*0x347 // 2^19.

For each of the first three quotients t, the native intermediate
`((t*0x199a // 2^15) & ~1)` is exactly2*floor(t/10) on its finite domain.
Consequently t minus five times that intermediate is t mod10. The first digit
uses n-10*floor(n/10); the highest digit is floor(n/10000). Products fit u32,
and all selected digits are0..9, so OR0x30 is exactly ASCII digit construction.

Length is1..5, precisely len(decimal(n)). Stores initialize every selected
scratch byte at rbp-0x30 through rbp-0x2c before the single callback receives
that numeral. Decimal0 is byte0x30. The apparent6/7/8-byte branches are
unreachable for every u16 input. Scratch never overlaps the endpoint slot at
rbp-0x38. The byte slice is valid only for the callback lifetime; addresses
and retained scratch aliases are outside this projection.

## Observation, finite oracle and exclusions

The proposed authority receives only11 raw input fields: fixed entry data/table,
prefix token/length, active record count, complete three-word records, immutable
byte-view bindings, initial method Cells, separate observer state and supplied
callback scripts. The independent expected relation uses direct decimal numeral
strings and declarative prefix/zero-run/raw segments, not native opcodes. It
observes every callback argument/method/reply/state and final state/methods/status.
Lossless adjacent-event RLE may compress observations; actual Rust must invoke
each callback individually. Scripts are supplied environments, not original
renderers or expected layouts. Canonical expected content is never a client
input.

This is the whole649-byte normal request/effect relation under the stated
domain. It is not outer602 padding, whose flags/header/restoration and wrapping
length rules are separate. No source build, own-Rust/target byte identity,
captured execution, instruction evaluator, original compiler identity,
whole-node behavior or completed component gate is asserted by this proof.
