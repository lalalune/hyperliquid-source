# Twelve complete chunk comparisons and their written GP registers

The target is node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
One coherent family consists of twelve complete 33-byte functions starting
at `0x14b52b0 + 0x30*i`, for i=0..11. Each has eight instructions and
fifteen separate INT3 padding bytes. The last function ends at
`0x14b54e1`. This is a finite, explicitly listed family, not a claim that
no similar function exists elsewhere. The previous packet bound only
the first member and listed the remaining comparands without binding
their complete functions.

## Static dependencies are closed for every member

The verifier authenticates the entire 91,774,280-byte target before
parsing. Each complete body has an independently locked SHA-256. All
overlapping FDEs are checked: exactly one describes the exact 33-byte
interval. Its actual FDE/CIE bytes and linkage are retained. GNU, LLVM
and Capstone agree on all 396 body bytes and 96 instruction starts.
Each function has one final RET, no call and no branch. The fifteen
padding bytes are bound separately for each member.

For each PCMPEQB, its actual signed RIP displacement resolves to a
complete 16-byte readonly `.rodata` range. All 192 comparand bytes and
their section/segment mappings are recorded. These opaque constants
are measured facts, without recovered names or inferred type identity.
The new source contains the measured constants, not a copied inferred
implementation.

Each entry has exactly one naming RELATIVE record. The verifier binds
all twelve full 24-byte records, symbol-zero/type-eight/addend fields,
destination `.data.rel.ro` mappings and pre-relocation zero slot bytes.
Scanning every one of the 80,300 RELA records excludes any additional
naming record or relocation overlapping bodies, padding or comparands.
The normal loaded slots would name the entries after adding the common
load bias. No runtime loader execution or slot consumer is claimed.

Full `.text` E8 and E9 byte-pattern scans find no direct candidates for
any member. Short jumps, indirect control flow, arbitrary data pointers
and actual runtime reachability are outside that census. No function
name or application purpose follows from the nearest objdump symbol.

## Complete register relation

Let C_i be member i's measured 16-byte constant, X the 16 initialized
bytes read at incoming RSI, and O the incoming RDI bits. For byte j,
define e_j=1 when X[j]=C_i[j], otherwise e_j=0. Define

```
M = sum(e_j * 2^j, j=0..15)
D = (O + 56) mod 2^64
```

MOVDQU loads all sixteen input bytes, without an alignment requirement.
PCMPEQB writes FF in each equal byte lane and 00 otherwise. PMOVMSKB
extracts each byte's most significant bit in increasing lane order:
ECX=M. Its 32-bit destination clears the high half of RCX, so full
RCX is exactly M in [0,65535], rather than a sign extension or mask
with high bits left over from entry.

LEA computes full RDX=D. It never dereferences that address. XOR EAX,EAX
clears the complete RAX; CMP ECX,65535 sets ZF exactly when every byte
matches. CMOVE then copies the full RDX to RAX iff ZF is set. RET changes
none of those registers. Therefore every written general-purpose
register at return is:

```
RDX = D, on matches and mismatches alike
RCX = M
RAX = D when M=65535, otherwise 0
```

RDI and RSI are unchanged. XMM0 and condition codes are changed but
outside this GP-register API. Its result is not just a Boolean or an
optional pointer: when O=2^64-56, a full match has RAX=0, RDX=0 and
RCX=65535. Conversely, a mismatch still computes and preserves D in
RDX. The object address itself is never read, and no object extent is
needed for this value relation.

## Safe Rust projection and full domain

`Pattern::P0..P11` identifies these twelve linked-VA entries in order.
`compare(Pattern, &[u8;16], u64)` accepts every 16-byte snapshot and
every u64 O. There is no input alignment, nonzero-pointer or no-wrap
restriction in this numeric API. The enum is a new selector for the
family; it is not a recovered native argument. `from_index` returns
None for selectors outside 0..11, a new convenience behavior rather
than an original function outcome.

The Rust loop compares the same byte pairs and accumulates their
individual bit positions in a u16. Each index and shift is in 0..16,
so no shift or array access can fail. OR of these disjoint one-bit
positions equals the sum defining M. Explicit wrapping addition gives
D. Testing `mask==u16::MAX` is equivalent to all e_j being one. Widening
the mask to u64 preserves the original zero extension. Each returned
field thus equals the complete relation above for all 12*2^128*2^64
combinations admitted by the value API.

The original-memory premise is one complete, initialized, stable,
readable input span and the bound stable readonly comparand, with valid
code and return control. Input may overlap the comparand or any other
ordinary readable data, because no data is written. The typed snapshot
does not reproduce original pointers, original fault behavior or its
load schedule. No output-object memory is introduced merely because
RDX contains O+56. MMIO, concurrent mutation, control-storage aliases,
faults, original ABI, SIMD results, flags and timing are excluded.

## Independent pre-Rust expectations

Before Rust existed, the oracle froze 121,792 input/result records and
its own source hash. It forms a string of equality digits, parses that
string as base two for RCX, multiplies the digits for the all-byte
predicate, and uses unbounded addition/remainder for D. Rust instead
uses a u16 OR accumulation, mask comparison and machine-width wrapping
addition. Neither uses an instruction interpreter or captured execution.

Member zero exercises all 65,536 equality masks. Every member exercises
every byte value at each of sixteen positions with the other fifteen
bytes matching, cross-comparisons against all twelve constants, every
address bit and neighbors, zero/wrap/signed-width boundaries and
deterministic additional chunks. This does not claim an exhaustive mask
enumeration for each of the other eleven members. The complete frozen
corpus has 2,641 full matches, 12,672 wrapping destinations and 21 full
matches whose returned address is zero.

The finite corpus qualifies the implementation and controls; the
per-byte reasoning above establishes the full-domain relation. Native
results do not prove original compiled-byte identity, source provenance,
application behavior, runtime reachability or whole-node equivalence.
