# Signed byte/dword gate and its complete tail closure

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete bodies are `[0x5172c70,0x5172c8a)` and
`[0x5172c90,0x5172cb5)`: 26+37 bytes and 10+9 instructions. The second
tail-jumps to the first on equality; both are one closed reconstruction.
The original static packet excluded the second body's behavior. Neither an
original source type nor a complete application component is identified.

## Exact relation and selective reads

Let N=2^64, K=2^32 and H=2^31. All effective-address additions reduce modulo
N before memory admission. O is incoming RDI. From stable ordinary memory,
b(X), d(X) and q(X) read respectively one, four and eight little-endian bytes.
For a raw dword C, define s(C)=C if C<H, otherwise C-K. All bit patterns are
admitted; zero pointers, noncanonical metadata, arbitrary field overlap and
unaligned storage receive no invented source-level interpretation.

Direct entry 0x5172c70 reads F=b(O+21), then C=d(O+16), unconditionally.
If F is nonzero and s(C)>0, the final pair is (RAX,RDX)=(F,C) without
reading O+4. Otherwise it reads V=d(O+4), returns RAX=1 exactly when
s(V)<=s(C), and RDX=C. C is zero-extended into full RDX on every returning
direct path. The short-circuit return preserves the full flag byte, so F=255
returns255 rather than a normalized boolean. All memory is unchanged.

Tail entry 0x5172c90 reads P=q(O+8), C=d(O+16) and Q=q(P+16), in that
order. If Q differs from s(C) modulo N, it immediately returns (1,s(C) modN)
without reading the flag or compared dword. If they are equal, it tail-enters
the direct function and has exactly its read requirements and final pair.
Stable memory makes the direct function's repeated C load equal to the first;
the repeated EDX write still changes its extension. Thus negative C on an
unequal tail path yields RDX in `[N-H,N)`, whereas the equality path yields
the same raw dword zero-extended in `[H,K)`. The distinction is observable.

Neither function writes any data byte. Numeric pointer arithmetic is metadata
for the safe value API; correspondence to the original assumes actual reached
accesses and return control complete normally in stable ordinary memory.
Faults, volatile/MMIO reads, concurrent writes, flags, CET, control-stack effects
and the native calling convention are excluded. No unlicensed inferred source,
helper stub or guessed C/C++ layout supplies a semantic premise.

## Exhaustive instruction argument

Both bodies begin with ENDBR64. The direct body uses MOVZX EAX,BYTE PTR
[RDI+21], which clears all upper bits of RAX. MOV EDX,DWORD PTR [RDI+16]
likewise zero-extends C into RDX. TEST AL,AL followed by JE selects the
fallback for F=0. Otherwise TEST EDX,EDX and JG select the return exactly
when signed32 C is positive. JG tests ZF=0 and SF=OF; TEST clears OF, so
zero and the entire negative half cannot take that edge.

The fallback CMP [RDI+4],EDX and SETLE AL implement signed32 V<=C.
SETLE writes only AL, but all upper RAX bits were already zero from MOVZX;
therefore the full RAX result is exactly0 or1. RDX is not modified after
the unconditional dword load. These two branches cover every F,C,V without
requiring the fallback field on the short path.

The second body loads P into RAX and MOVSXD sign-extends C into RDX. CMP
RDX,[RAX+16] compares the full64 bits. JE jumps to the final E9 tail into
0x5172c70; the unequal path writes EAX=1 and returns. Its internal eight-byte
NOP follows a RET and is skipped by the JE, so neither feasible path executes
it. The tail introduces no call/return stack frame and preserves O. Its full
target body is included rather than assumed as an opaque callback.

Full-width equality compares Q with the sign-extended dword, not the raw
zero-extended C, a low32 truncation or a signed ordering. On equality, the
helper's later MOV EDX reconstructs zero extension irrespective of the prior
RDX value. There are no further calls, indirect transfers or data dependencies
inside this complete two-body closure. The instruction widths and disjoint
conditions prove the relation for every normally returning input, independent
of finite vectors.

## Safe image domain and integer correspondence

The new member selector chooses direct or tail entry; it is not a recovered
machine argument. Image byte i represents base+i in one nonwrapping interval.
The exclusive end is computed in u128 and must not exceed N. Each requested
effective address first wraps in u64, then checked subtraction, conversion and
span length ensure its bytes fit. O and P themselves need not lie in the image
if their reached fields do. Missing unused fields impose no requirement.

`None` is a new refusal for an invalid image or missing reached span, not a
reconstructed native error or fault. The API borrows an immutable slice and
never changes it, on success or refusal. The whole-image nonwrap restriction
applies even when a particular path reads only part of an oversized interval.
It is deliberately narrower than arbitrary original process memory mappings.

The source converts exact four-byte loads to i32 only for signed comparisons
or i64 widening. Every i32 fits i64, including MIN. Conversion back to u64
preserves its two's-complement residue. Direct RDX instead widens the original
u32 without sign extension. The proof uses s(C) and the independent oracle
uses the order-preserving key C XOR H for fallback comparisons; both keys
map the signed dword order to unsigned order. No signed subtraction or
overflow-prone arithmetic is needed. Flags are not simulated.

The tail's stable reread of C can be represented by the same mathematical
value, but the source follows the helper's access path explicitly. Pointer,
target qword, count, compared dword and flag bytes may overlap arbitrarily;
all are read from one unchanged image. No data-disjointness assumption is
needed, and no host pointer is ever constructed from numeric metadata.

## Static closure and boundary qualification

Both full bodies, unique FDEs, full CIE records, conditional edges, RET and
tail target are bound. Following INT3 padding is six bytes for the first and
one byte for the second; the following exception fragment is not folded into
either body. GNU, Apple LLVM and Capstone agree on all63 body bytes and19
boundaries without body normalization.

Full .text E8/E9 candidate scans find four E8 sites in four complete callers
totaling9,471 bytes/1,889 instructions, and the single included E9 tail.
Every site is an actual decoded instruction boundary with the exact target.
Caller bodies establish these edges only; their other callees, LSDA behavior
and complete application semantics are outside this closure.

Apple LLVM prints three caller LOCK ADD instructions as a standalone F0 line
followed by ADD, while GNU and Capstone retain one boundary. The first strict
static run rejected this display difference before Rust/freeze. Its exact
validator and diagnostic are retained. The corrected verifier joins only
three explicit byte pairs at0x503a84c,0x503a9c4 and0x50ecdb7; it changes no
byte and accepts no other split. Full-byte identity and all other boundaries
remain mandatory. These caller-only display joins do not alter either leaf.

All80,300 RELA records are scanned: none names either entry or overlaps the
body/padding. Unknown relocation widths and REL sections are rejected. Neither
body uses a RIP-relative operand or static table. This is not a complete
indirect-reference census or an original-source identity claim.

## Independent expectations and limits

Before the Rust directory exists, oracle.py records immutable numeric-address
bytes, selects the abstract signed/equality partitions, and freezes complete
input/output streams plus its own and the static record's hashes. It imports
neither Rust nor an instruction decoder and performs no instruction emulation.
Each descriptor has four u64 fields and128 synthetic bytes; output is status
plus full RAX/RDX. No expected value is passed to the input-only native client.

The corpus varies every gate byte, dword sign and equality boundaries, every
value bit, missing short-circuited fields, high bases, address wraps and aliased
read roles. Repeated opt0/opt3 native builds, effective compiled wrong variants
and corruption controls complement the universal proof. Finite cases are not
an exhaustive memory-map enumeration; no captured execution, original ABI,
compiled-byte identity, Linux runtime or whole-node reconstruction is claimed.
