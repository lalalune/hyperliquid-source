# Independent normal request relation of the actual formatted-parts writer

Target node94 SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Fresh intake `ADMISSION.json` binds the complete helper
`0x1572b20..0x1572da9`, 649 bytes /169 rows, SHA256
`8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3`.
No inferred original implementation or new Rust was read for this proof.

## Domain and selected observation

Admit fixed, readable and nonwrapping descriptor/part-array storage: the first
two QWords are a byte-prefix pointer and length; the next two are an array
pointer and element count. Elements are24 bytes. This is an observed machine
entry layout, not an identified original enum ABI. Each observed byte slice
has valid immutable readable storage of at most isize::MAX bytes. The array
extent/count multiplication is valid and nonwrapping. Referenced descriptor,
array, strings, code/constants and active frame remain immutable and properly
separated from invalid writable aliases. Zero-run counts are raw u64 values.
Rendering the huge theoretical counts is not required to prove termination.

The data pointer and table pointer are fixed input roles; table+0x18 is a
readable current write-byte-string method cell. Normal supplied callbacks may
sequentially alter that method cell and separate context state; they preserve
ordinary caller-live machine roles and return a raw low byte. Concurrent writes,
unwind/faults, retained stack-buffer pointers and invalid storage are excluded.
The projection observes ordered byte requests, stable data/table identities,
method identity used, callback effects, and final low-byte status. It excludes
native pointer addresses, padding, hidden registers and the renderer itself.

## Prefix and part traversal

The prologue caches data/table roles at0x1572b34..37. Prefix length is read
at0x1572b3a. When nonzero, one request sends the complete prefix through the
then-current method at table+0x18. A nonzero reply returns1 and prevents all
part processing. Prefix length0 skips the callback completely.

The array pointer/count are then read from immutable descriptor fields. For
positive count the actual endpoint is base+24*count. Every successful part
advances the pointer24 bytes; no part can be skipped or repeated before that
endpoint. Valid nonwrapping array bounds prove every selected field access.
Count0 reaches explicit return0 without dereferencing a part.

The full u16 part tag at0x1572b9f selects three behaviors:

* Tag0 reads a u64 zero-run count at+8.
* Tag1 reads a u16 numeral at+2.
* Every other u16 value reads pointer+8 and length+16 and submits exactly one
  byte request, even if length0. No extra tag validation or UTF8 check occurs.

All ordinary prefix/numeral/byte-part requests load the current method cell
at their own call. Their data and table identities remain the fixed inputs;
unrelated context-pointer mutations cannot retarget those cached arguments.
Any nonzero reply stops with1. If all requested callbacks return0, the helper
finishes with0. The helper performs no direct formatter/context header store.
Callback effects survive on success and failure.

## Zero runs and the within-run method cache

Tag0 count0 jumps directly to next part, without an empty request. A positive
count caches the then-current method into a register once for this run. The
literal at0x252cb8 is64 ASCII0 bytes, freshly checked with no loader-write
overlap. Each request is a prefix of that immutable literal.

For count n>64, the loop submits64 bytes, tests the reply and subtracts64 only
after a successful call. It repeats while remaining>64. It then submits the
remaining1..64 bytes once. Thus for n>0, with

    q = floor((n-1)/64), r = n-64q,

the successful request sequence is q requests of64 ASCII0 bytes followed by
one of r bytes, with1<=r<=64. In particular n=64 is one64-byte request;
n=128 is two64-byte requests, without an empty trailing call. Subtraction is
performed only with remaining>64, so cannot underflow. A strictly decreasing
positive remainder proves termination for every admitted finite u64 count.

Every request within one zero run uses the single cached method, even if
callbacks change table+0x18. After a successful run the actual table pointer
is restored to its cached role, so the next part reloads its current method.
Nonzero replies stop immediately with1, including inside the chunk loop.

## Complete numeral arithmetic and initialized bytes

`DECIMAL-PROOF.json` independently compares every one of65536 payload values
against decimal numeral strings. It closes both the native length expression
and each reciprocal quotient/remainder expression in0x1572ca0..0x1572d94.
All products fit u32 on this domain; every digit is0..9; OR0x30 equals ASCII
digit construction. Length is exactly1..5. Stores initialize each selected
output byte before one callback receives the exact numeral. Zero is `0`.
The apparent sixth/eighth-byte branches cannot be reached by any u16 payload.

This finite arithmetic proof is a complete domain check, rather than a sample,
and carries no instruction execution, PC, machine registers or memory model.
It combines with the native callback/control-flow argument; it does not by
itself establish renderer behavior or original Rust type identity.

## Limits and next step

The qualified theorem is the complete normal request/effect relation of this
helper with the stated immutable storage and normal callback domain. It is not
the outer602-byte padding routine, whose prefix-first header writes,
restoration/failure phases, sum overflow and low16 prefix subtraction need
separate proof. No new implementation, compiled-code identity, captured runtime
result or full-component gate is claimed. A pre-source independent raw-input
authority and separate review should precede new Rust.
