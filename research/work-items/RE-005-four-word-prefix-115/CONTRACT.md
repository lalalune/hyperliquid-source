# Pre-Rust contract: four sequential words, mode byte, optional word

RE-005 / serialization. Base `05bc2de303c05525b71e7e257426e741bc66a390`.
Node #115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses are unrebased ELF VAs. This contract and actual-instruction
expectations are frozen before authoring the new Rust implementation.

The bounded question is the complete private decoder at
`0x2ce1730..0x2ce198a`: what values and partial Reader state survive each
ordinary return? The existing block-fill-writers packet establishes field
origins but has no source implementation or full input/error comparison.
Do not infer field names, units, wire-message identity, source enum names,
the original Rust ABI or current network acceptance.

Premises: valid disjoint bounded state/input/output/stack, no pointer wrap,
canonical mode qword0 or1, little endian. State is 40 bytes: mode+0,
limit+8, cursor+16, remaining+24, charged+32. Mode0 leaves count untouched.
The four scalar calls occur sequentially at 2ce1749/1768/1788/17a8;
each independently charges8 using the existing u64 Reader relation. Never
replace them with Reader::read_four: that other caller precharges32.
The first scalar failure stops further reading and carries its active error;
prior successful values are not part of the error payload.

After four successes, mode1 checks charged+1 for overflow. Overflow retains
the prior charge. Otherwise the increment is stored before limit refusal;
the comparison is old_count>=limit. No input is consumed on refusal.
Next, empty input produces additional1. A present mode byte is consumed
before classification: 0 returns the four values and no tail; 1 reads a
fifth scalar at 2ce1843; all other bytes return the raw mode byte (native
error tag5). The fifth scalar also independently charges8 before reading.
Suffix bytes remain available; this is a prefix operation, with no EOF check.

Success head qword0/1 at output+0 selects inactive/active tail at+8;
four values occupy+16/24/32/40 in order. Error head2 stores its record
at+8. Only active fields are projected: raw0 additional at+16;
raw2 no payload; raw3 expected/found at+9/+10; raw5 mode at+9.
Inactive fields, padding and copied source-location pointers are excluded
from logical equality, never zero-filled as a native claim. Failure never
stores output+40; an initialized caller canary checks that property.

Actual helper graph: scalar2cd7ac0..2cd7ba5, slow58225c0..58226fc,
error constructor5822700..582270e. RELATIVE slots64e6c38/64e6c40/
64e7f78 and the signed relative tables60be8c/935c24 are authenticated
from the same ELF. Each CALL pushes its real continuation and each RET
pops it. No callback result is supplied. No captured ELF or emulator runs.

The unchanged MIT source `src/node115-u64-reader-state/lib.rs` is a real
dependency, reused with its license, not new primitive reconstruction credit.
The new safe logical interface will return fields/error plus remaining slice
and charged count. All92 full-scope gates remain false; finite agreement and
full private-body exports do not establish full component or node equivalence.

Native expectations use actual instruction semantics and preserve unknown
bytes. Packet-local ISA refinements are required: byte-wise knownness
for MOVUPS (the shared helper otherwise drops known fields beside unknown
padding), and actual ROL CX,8 in the little-endian slow reader (its following
TEST overwrites arithmetic flags), and 32/64-bit BSWAP (including EAX upper
half clearing, with flags preserved). The fifth-error path also copies a known
found byte beside unknown padding through MOVZX word and a narrow MOV store;
these retain byte-wise knownness. Each needs focused checks. Shared tooling,
parent packet, dependency source and captures remain unchanged.
