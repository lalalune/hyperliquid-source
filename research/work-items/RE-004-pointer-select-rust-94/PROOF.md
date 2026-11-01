# Low32 pointer selector and its complete adjusting tail family

Target node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The reconstruction covers these three complete FDEs as one closed family:

| Entry | Complete range | Bytes | Instructions |
| --- | --- | --- | --- |
| Direct | `[0x552cac0,0x552cade)` | 30 | 7 |
| Offset24 | `[0x552b280,0x552b28d)` | 13 | 3 |
| Offset10672 | `[0x54cbd40,0x54cbd50)` | 16 | 3 |

Total: 59 bytes / 13 instructions. All code addresses are linked ELF VAs.
Runtime object/base/selector numbers are independent values, not file offsets.

## Exact register relation

Let `N=2^64`, incoming RDI be O and full incoming RSI be S. The direct leaf
receives W=O. The inner wrapper performs `ADD RDI,0x18` and tail-jumps to
the direct leaf, so W=(O+24) mod N. The outer wrapper first performs
`ADD RDI,0x2998` and tail-jumps to the inner wrapper. Hence its leaf argument
is `W=(((O+0x2998) mod N)+0x18) mod N`. Modular addition is associative, so
this equals `(O+0x29b0) mod N`; 0x29b0 is 10,672. Every intermediate carry
is preserved by the source's separate wrapping additions. Neither wrapper
loads memory, pushes a return address or changes RSI.

The direct leaf first computes `A=(W+0xe518) mod N` into RAX by LEA, then
computes `D=(W+0xec10) mod N` into RDI by ADD. The alternative uses the
original W, not the already incremented default base. `CMP ESI,1` compares
only the low 32 bits of S. CMP does not write ESI and therefore does not
zero-extend or otherwise replace RSI. `CMOVE RDI,RAX` copies the full
alternative A exactly when `S mod 2^32 = 1`; otherwise RDI remains D.

Let C be that selected base. The final load is `MOV RAX,qword [RDI+0x78]`,
followed by RET. For all three entries, the complete reported register values
at normal return are:

- RDI = C, including every upper bit of the selected base.
- RAX = the little-endian qword at `(C+120) mod N`.
- RSI = S, unchanged in all 64 bits.

The candidate address formerly in RAX is overwritten by a full qword load;
there is no partial-register residue or unknown imported-call result. The
three bodies do not modify RDX, RCX, RBX, RBP or R8..R15. Flags, RSP/RIP,
stack/return-address state and the compiler's host ABI are outside this value
projection. Observed original register preservation does not imply that a
compiled Rust function uses the original register allocation.

## Only the final selected qword requires memory

The only data read in this entire family is the final eight-byte load. LEA,
ADD, CMP, CMOVE and both tail jumps introduce no other data dereference.
Consequently neither O, W, C nor the unused candidate field must lie within
the image. Zero-valued object or base metadata is not rejected by the target.
Both numeric candidate bases are computed by the leaf, but computing an
address is not loading the bytes at that address.

The API models stable ordinary bytes at `[base,base+len)`, with mathematical
endpoint at most N. It wraps the numeric effective field address modulo N,
then requires all eight ordinary bytes of that qword inside the image. Its
bytes do not wrap across N. Unaligned accesses are supported. The image can
be a narrow window covering just that qword; no whole-object length, second
field, pointer alignment, canonical-address policy or logical selector enum
is invented. A qword ending exactly at N is inside this domain.

None is a new safe refusal for an invalid image or missing final qword, not
an original return, exception order or fault simulation. Correspondence to an
original normal return assumes the final read and normal control/return state
are valid. The value API can express raw numeric arithmetic without asserting
that every address is an actual canonical hardware mapping. MMIO, concurrent
mutation, abnormal control flow, fault timing and flags are excluded. Shared
slices and `forbid(unsafe_code)` prevent input mutation in the reconstruction.

## Arithmetic and memory safety

Each wrapper/base/field addition is explicitly wrapping u64 arithmetic.
The unsigned low32 equality is represented by `selector as u32 == 1`, while
the original u64 selector is retained for RSI. Values with high bits set and
low32 equal to one therefore select the alternative and preserve those high
bits in the result; a byte-only test would incorrectly admit selectors such
as 257 to that branch.

The global interval test widens base and the qualified host's usize length
to u128 before adding. Its maximum is below 2^65, so it cannot overflow u128.
Exactly-N endpoints are accepted. Checked effective-address-minus-base rejects
addresses below the interval. Checked usize conversion, checked offset+8 and
`get(start..end)` ensure a complete eight-byte host slice. `from_le_bytes`
then supplies the full qword without alignment or raw-pointer assumptions.

The three finite entry variants supply the exact wrapper prefix. The complete
selector partition supplies C; a single checked read supplies RAX; C and the
original S supply RDI/RSI. This proves the complete admitted-domain relation,
including independently wrapped intermediate additions. Loaded zero/all-ones
values are ordinary admitted qwords, not error sentinels. The native driver's
2,048-byte capacity is a fixture protocol only; arbitrary slice lengths are
supported by the library's stated interval contract.

## Static, caller and tail closure

Fresh GNU/LLVM exports and Capstone cover all three complete member bodies,
their full FDE/CIE records, selected neighboring FDEs and padding. No static
data or imported helper remains in the three-entry closure. The internal
links are E9 at `0x552b288` to the direct leaf and E9 at `0x54cbd4b` to
the inner wrapper. All instructions after each entry are accounted for.

The complete `.text` E8/E9 encoding scan also establishes eight external E8
sites, boundary-confirmed in six complete caller FDEs:

| Caller range | Selected calls |
| --- | --- |
| `[0x54cbd50,0x54cbfed)` | `0x54cbfc2` → direct |
| `[0x54cbff0,0x54cc126)` | `0x54cc11a` → direct |
| `[0x551e750,0x551e971)` | `0x551e8d0`, `0x551e8e7` → direct |
| `[0x54cab80,0x54cb487)` | `0x54cac3f`, `0x54cac54` → inner wrapper |
| `[0x54e3b10,0x54e3e00)` | `0x54e3be8` → outer wrapper |
| `[0x54e3e00,0x54e40f0)` | `0x54e3ed8` → outer wrapper |

These contexts contain 5,339 bytes / 1,263 logical instructions. Their full
code and unwind records establish boundaries and actual call edges only;
their algorithms, other helpers, globals and semantic purpose are not claimed.
All 80,300 RELA records are checked: none names a family entry or writes into
the selected member/padding/caller code, including partial overlap. The scan
is not a complete indirect xref census.

LLVM prints three LOCK prefixes in caller2 as standalone one-byte rows at
`0x551e926`, `0x551e93b`, `0x551e948`. The checker joins only these exact
F0 rows to their immediately adjacent instruction rows, retaining all bytes;
the resulting logical boundaries match GNU and Capstone. No instruction byte
is masked or substituted. Initial strict-boundary and underclosed-E9 failures
are preserved. The latter revealed both wrappers absent from the historical
E8-only packet; all three entries are implemented together, not as separate
contributions. The independent expectation freeze occurred only after this closure was complete.

## Independent pre-Rust relation

Before the Rust source directory existed, the oracle collapsed the complete
wrapper/base/field additions into one unbounded expression for the final
field address, reduced it modulo N, and derived C backwards by subtracting
120 modulo N. It recovered each qword by positional-byte integer sums. This
differs from the Rust entry dispatch, staged additions and checked slice load;
it imports no Rust and does not interpret or execute captured instructions.

All 23,220 cases were frozen before Rust. Each entry has 5,119 admitted and
2,621 refused cases. Across the family there are 3,915 admitted cases with an
absent unused field, 5,073 with the selected base itself outside the image,
7,206 with nonzero high32 selector bits preserved, 3,381 alternative selections
with such high bits, 2,310 final field-addition wraps and 1,155 exact-end reads.
The corpus also exercises intermediate wrapper carries, zero objects,
unaligned reads, arbitrary loaded values and six globally overflowing-image
cases whose selected qword individually fits.

The static/oracle/input/output hashes bind these expectations to this target.
Finite host tests qualify the new implementation and its controls; the full
u64/byte-image claim rests on the modular and memory-domain argument above.
No captured executable, instruction emulator, original compiled-byte identity,
source struct/library identity, full-node build or component gate completion
is claimed.
