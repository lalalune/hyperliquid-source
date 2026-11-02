# Three threshold pointer leaves, including ordered flag reads

Target node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Complete bodies: `[0x54d76e0,0x54d76f9)` (25 bytes),
`[0x54d7700,0x54d7733)` and `[0x54d7740,0x54d7773)` (51 bytes each).
These are one coherent 127-byte family, not three submissions. The first
was previously documented statically; its two neighboring gated entries
were expressly excluded. No existing Rust implementation covers them.

## Complete relation

Let N=2^64, L be the module load bias, I the full incoming RCX, and D the
full incoming RDX. All numeric addresses below are reduced modulo N.
Let F1 and F2 denote the bytes actually observed at L+0x599bb46 and
L+0x599fbd0. They are runtime values, not assumed initial zero-fill bytes.
The Rust API supplies these observations through `Flags`.

| Entry/member | Required observations | Full RAX | Full RDX |
|---|---|---|---|
| 0x54d76e0 / Plain64 | none | L+0x576a6c0 if I<=63, otherwise 0 | 0 |
| gated, F1=0 | F1 only | 0 | D |
| gated, F1!=0, F2!=1 | F1 then F2 | 0 | L+0x599fbd0 |
| Gated36, F1!=0, F2=1 | F1 then F2 | L+0x576c3a0 if I<=35, otherwise 0 | L+0x599fbd0 |
| Gated196, F1!=0, F2=1 | F1 then F2 | L+0x576c300 if I<=195, otherwise 0 | L+0x599fbd0 |

All comparisons involving I are unsigned and full-width. F1 accepts every
nonzero byte, including 128..255. F2 must be exactly one; other nonzero
bytes fail. If F1 is zero the second address is never computed into RDX
and its memory is never read. If F1 is nonzero the second read is required
even if I is already above the member's bound. RDX then holds that address
on both successful and unsuccessful selections. The selected data address
is only returned, never dereferenced. It may numerically wrap to zero;
zero does not by itself distinguish rejection from a selected address.

## Derivation from all instructions

The plain entry begins with ENDBR64, compares RCX with 63, and clears EDX
using MOV (preserving the comparison flags). Writing EDX clears all upper
RDX bits. The RIP-relative LEA is L+0x576a6c0 and also preserves flags.
CMOVA selects zero exactly when unsigned I>63. RET has no data-register
effect, so the first row covers all 2^64 values of I and every L and D.

Each gated entry computes the same first address into RAX, compares its
byte with zero, and jumps to the final XOR EAX,EAX / RET block if equal.
Nothing on that path has written RDX. The nonzero path computes the second
address into RDX and compares its byte with one. An unequal comparison
jumps to the same zero-return block, preserving that newly computed RDX.
The remaining CMP/JA compares I with 35 or 195. Only the in-bound path
executes the final result LEA and returns. The alignment NOP before the
zero-return block is inside each FDE but unreachable from these paths;
its exact bytes are nevertheless bound. There are no calls, loops, writes,
extra data references, or other exits. ENDBR64, flag and stack/control
semantics are outside the numeric output API.

Thus the partition in the table is exhaustive and mutually exclusive.
RIP-relative addresses equal L plus their linked targets in a normally
mapped module. Explicit wrapping adds implement their residues for all
u64 mathematical L. The finite corpus qualifies these consequences;
it is not the proof of the exhaustive partition.

## Mapping, relocation and reference closure

All three complete bodies have unique exact FDE extents and bound CIE/FDE
records. GNU objdump, Apple LLVM objdump and Capstone agree byte-for-byte
and on all 34 instruction boundaries, with no normalization masks. The
following INT3 padding lengths are 7, 13 and 13, separately bound.
All conditional destinations and all return boundaries are checked.

Each entry has one symbol-zero R_X86_64_RELATIVE naming slot. Its raw
qword is zero and its complete section/PT_LOAD mapping and exact relocation
record are retained. A full scan of 80,300 RELA records checks every naming
addend and unique eight-byte overlapping writer for each slot. The same
scan rejects writers into the complete code/padding and the exact global
bytes used. Unknown relocation types and REL sections are rejected.
Whole-.text E8/E9 byte-pattern scans find no direct candidate to any entry.
This is not an indirect-reference or reachability census.

Both flag addresses are in writable SHT_NOBITS .bss and in the zero-filled
portion of a writable PT_LOAD: address >= segment start + p_filesz and
address < segment start + p_memsz. Their complete section and segment
records are locked. They have no overlapping relocation writer. There are
no file bytes at these addresses to use as a runtime oracle; zero fill
only describes initial loading, not subsequent program state. The three
possible result addresses lie within .data.rel.ro and a load segment,
but no pointed-to bytes, source object layout, element count or table
extent is claimed. Bounds 63/35/195 alone establish no logical table size.
The two flag addresses remain distinct under any common modulo64 bias.

## Safe API and admission

`select(Member,index,load_bias,incoming_rdx,Flags)` is a new safe no_std
value API. Member selects an entrypoint and is not a recovered machine
argument. `Option<u8>` represents availability of each observed byte.
Plain64 ignores both options. Gated members require first; if it is zero
second is unused. Otherwise second is required before the index test.
`None` returned by the function is a new API refusal for unavailable
required observations, never a reconstructed original return or fault.
`Some(Registers)` always contains the exact full RAX/RDX projection.

Only u64 comparisons, byte comparisons, finite pattern selection and
wrapping addition are used. There is no allocation, indexing, unsafe code,
pointer conversion or arithmetic overflow panic. Totality holds for every
safe API input. The snapshots do not claim to reproduce live read timing,
MMIO, concurrency, faults, invalid or noncanonical addresses, self-modifying
code, control-stack overlap, CET behavior or the x86 calling convention.
For correspondence, the original two ordered reads (when required) and
return must complete normally and the supplied bytes must equal their
observations. Artificial biases test arithmetic but need not correspond
to a realizable executable mapping. No runtime read of a returned address
or reconstruction of downstream behavior is necessary for these leaves.

## Independent expectations and native qualification

The oracle and full static record were frozen before the Rust directory
existed. It partitions flag classes using finite integer ranges, evaluates
unsigned index membership in an abstract interval and applies unbounded
integer addition modulo 2^64. Rust uses the observed branch structure,
Option admission and wrapping arithmetic. The input-only native client
receives six u64 descriptors, never expectations or captured instructions.
It emits status plus full RAX/RDX; refused rows have canonical zero fields
only as the new driver's framing convention.

The frozen 208,608 cases include all 65,536 supplied byte pairs for every
member, unavailable-first/second partitions, all threshold neighbors,
every index bit through bit63, arbitrary high RDX bits, and load biases
chosen around address wrap and zero. There are 1,725 refusal cases; those
are accounted separately from original admitted observations. The complete
flag product is finite coverage, not exhaustive load-bias/index coverage.
The proof above supplies the latter relation. Real compiled mutants vary
comparison width/signedness, exact byte classes, read admission order,
preserved registers, result bases and address arithmetic. No captured code
execution, instruction simulation, binary transplantation, original compiler
identity or whole-node equivalence is asserted.
