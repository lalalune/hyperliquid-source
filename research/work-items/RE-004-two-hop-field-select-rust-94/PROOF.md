# Conditional two-hop read, full registers and reached-memory domain

Target: node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete FDE is `[0x5361710,0x5361738)`, 40 bytes and ten decoded
instructions. All addresses in the packet are linked ELF VAs. Runtime data
fields below are independent numeric values; they are not ELF file offsets.

## Full instruction relation

Let `N=2^64`, `O` be incoming RDI and `q(a)` be the little-endian qword at
numeric address `a`. Effective-address addition uses arithmetic modulo N.
The first two loads establish

`P = q((O+8) mod N)` and `Q = q((P+0x1e0) mod N)`.

The first load writes full RDX=P. The second writes full RAX=Q and does not
alter RDX. `TEST RAX,RAX` tests all 64 bits of Q; the branch is taken exactly
when Q=0. It is neither a signed comparison nor a low-byte/low-dword test.
For Q nonzero, the next instruction loads full RAX from `(Q+8) mod N` and
returns. For Q zero, control jumps to `0x5361730`, loads full RAX from
`(P+0x178) mod N` and returns. Both returns therefore have

`RDX=P` and `RAX=q((P+0x178) mod N)` if Q=0, otherwise
`RAX=q((Q+8) mod N)`.

No helper, import, static data reference or write occurs. No instruction
modifies RDI, RSI, RCX or R8..R15/RBX/RBP. The seven-byte NOP at
`0x5361729` lies inside the FDE but is unreachable from the entry's normal
control flow: the nonzero path returns before it and the zero branch jumps
over it. It is bound as complete body evidence, not treated as an additional
memory read. The FDE ends immediately before a different FDE at `0x5361738`;
there is no external padding to append to the 40-byte body.

## Domain and selective reads

The safe API receives an immutable image at the mathematical half-open
interval `[base,base+len)`, whose endpoint must be at most N. It interprets
numeric object/field values, forms each effective address modulo N and admits
each reached qword only if all eight ordinary bytes fit inside that image.
Qword bytes do not themselves wrap across N. Unaligned reads and arbitrary
overlap between read roles are valid, since all input bytes are stable.

The first field and Q field are always required. Exactly one terminal field
is then required. Q=0 must not cause a read through Q+8, and Q nonzero must
not require the fallback field at P+0x178. Requiring both fields or rejecting
their numerical endpoints would narrow the observed relation. The library
expresses the terminal lookup inside the branch, preserving these conditions.

There is no test of O or P for zero. In particular, P=0 can satisfy the
numeric-image domain when addresses 0x1e0 and the selected terminal are
mapped. The historical packet's statement that a null P “would fault” is
not a universal consequence of these instructions. This packet makes no
claim that address zero is mapped by the operating system; it states the
conditional relation for the actual reached bytes. The same distinction
applies to noncanonical numeric addresses: the safe value API can represent
their arithmetic without promising an executable hardware mapping.

Missing reached bytes or a globally overflowing image return None. This is
a new safe refusal, not an original result, exception ordering or fault
simulation. The original correspondence assumes a successful stable ordinary
memory read for each reached operand and valid normal control flow/return.
MMIO, concurrent mutation, abnormal control flow, flags, fault timing, stack
and return-address behavior are outside the projection. A wrapped address
does not automatically cause refusal if the resulting qword is present.

The Rust API returns the two written register values as a structure. It is
not the original Linux x86-64 calling convention. Preservation of other
original registers is an observation of the captured instructions, not a
claim about the compiler's host register allocation. The input slice is shared
and the library forbids unsafe code, so no input bytes can be mutated.

## Arithmetic and Rust safety for all inputs

All field additions use `wrapping_add`; no checked-overflow
profile can change their modulo-N result. The length/base interval check
widens to u128 before addition, covering the full u64 base and the qualified
host's usize length without overflow. Endpoint exactly N is allowed.

For a reached effective address A, checked `A-base` rejects addresses below
the interval. Checked conversion to usize and checked offset+8 reject
unrepresentable host offsets or overflow. `get(start..end)` requires all
eight bytes in the image; `from_le_bytes` then loads exactly that qword.
There are no raw pointers, alignment requirements, allocations or dependencies.
The fixed 512-byte native input image is a fixture protocol size; the public
library accepts arbitrary slices satisfying its stated interval domain.

After the first two admitted reads, the full-width zero test partitions all
Q values into exactly two cases. The selected final checked read supplies RAX;
the saved first value supplies RDX. This exhausts all normal paths, establishes
the complete two-register relation, and proves that a zero or all-ones loaded
result remains an admitted ordinary value rather than an error sentinel.

## Static and caller closure

Fresh GNU and LLVM exports agree with Capstone on every body byte and boundary,
including the internal NOP and both return instructions. Complete FDE/CIE
records and neighboring FDE extents are bound independently of the unwind
index stride. Eleven INT3 bytes before the body are separately bound. The next
neighbor starts exactly at the selected endpoint and its LSDA/personality
context is not reconstructed.

The complete `.text` E8/E9 candidate scan finds two E8 sites, `0x5380fb7`
and `0x538265a`, and no E9 site targeting this entry. Both calls are checked
at decoded boundaries inside their complete caller FDEs:
`[0x5380f50,0x53814d0)` and `[0x53825f0,0x5382c46)`.
Together these caller contexts contain 3,030 bytes and 630 instructions.
Their full code and FDE/CIE records are retained; their algorithms, other
helpers, source identities and exception machinery are not recovered here.
This direct encoding scan is not a complete indirect xref census.

All 80,300 RELA records are checked. None names the entry as addend or writes
over the selected code/padding or either caller body, including partial
overlaps. The leaf has no RIP-relative data or outgoing call dependency.
No loaded field type or source struct layout beyond the observed byte offsets
is inferred. Original compiled-byte identity and component gate completion
remain unclaimed.

## Independent frozen relation and finite native evidence

Before the Rust source directory existed, the oracle built a dictionary of
every valid eight-byte interval using integer positional-byte sums. This
interval relation is independent of the Rust checked-slice helper. It then
composes the first and selector fields, chooses one final address and returns
the mathematical pair. The oracle does not import Rust, interpret instructions
or use a captured executable. Frozen records bind the oracle, complete static
record, inputs and expectations to the target digest.

The 10,464 pre-Rust cases contain 2,553 admitted fallback outcomes, 3,696
admitted indirect outcomes and 4,215 refusals. There are 1,545 admitted
fallback cases whose unused indirect field is absent, 336 admitted indirect
cases whose fallback field is absent, 76 admitted zero-P cases, 388 admitted
zero-object cases, 190 admitted nonzero Q values with zero low32 bits, and
1,306 wrapped selected addresses. Two overflowing whole-image witnesses keep
all reached fields individually present, so the global interval guard is
observable. Exact-end spans, unaligned/overlapping fields, high result bits,
zero/all-ones values and independently wrapped field formation are included.

Finite execution checks qualify newly authored native Rust and the comparator.
The instruction partition and interval argument above establish the complete
admitted-domain relation; the corpus is not claimed exhaustive over arbitrary
memory images or u64 addresses. No captured execution or instruction emulator
is used.
