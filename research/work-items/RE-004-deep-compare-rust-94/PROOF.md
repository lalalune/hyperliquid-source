# Deep-field comparison without discarding partial-register state

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This concerns complete ELF VA `[0x51c0c00,0x51c0c18)`, 24 bytes/seven
instructions. It reconstructs the full numeric RAX/RDX pair, not only
the Boolean low byte consumed by the observed caller.

## Static scope and complete relation

GNU, LLVM and Capstone agree on the entire body and its instruction
boundaries. The exact unique FDE/CIE is retained; eight INT3 bytes
follow outside the body. There is one RET, no branch, outbound call
or static data operand. The only direct E8 candidate is `0x51e7377`,
confirmed inside the complete 3,498-byte/766-instruction caller
`[0x51e6a70,0x51e781a)`. Its subsequent TEST AL checks the low byte,
without establishing that the remaining RAX bits were zero. Full RELA
scanning finds no entry-naming addend or relocation overlapping either
code interval. Computed/indirect callers remain unenumerated, and the
caller's broader behavior is not claimed.

Let N=2^64; all field-address additions are modulo N. Let Q(x) denote
the little-endian qword at address x in stable entry memory. Incoming
RDI=A and RSI=B. The four target reads occur in this order:

```
P = Q(A+8 mod N)
R = Q(B+8 mod N)
X = Q(P+120 mod N)
Y = Q(R+120 mod N)
```

After the first three loads RAX=X and RDX=R. CMP computes Y-X and
SETB AL sets the low byte to 1 exactly when Y<X as unsigned qwords.
Neither instruction overwrites RDX. SETB writes only eight bits;
it does not perform the zero extension associated with an EAX write.
Thus the entire projected return is:

```
RAX = (X & 0xffffffffffffff00) | (1 if Y<X else 0)
RDX = R
```

There are no data writes. ENDBR64 and RET do not alter the projected
values. These are all instructions in the leaf, so the formula covers
every normal return. For X=0x1234 and Y=0x1000, RAX is 0x1201 rather
than 1. For equal values the low byte is zero, but X's upper 56 bits
remain. High-bit-set inputs are compared unsigned, without truncating
the comparison to the byte or dword subsequently used by a caller.

The Rust performs four little-endian qword reads in the same order,
uses wrapping field-address additions, applies an unsigned u64
comparison, clears the original low byte and inserts the Boolean bit.
Its RDX member is the second hop R, not Y or the first hop. This is
exactly the formula; incoming RAX/RDX, flags or upper argument bits
outside the full u64 pointers do not supply hidden value inputs.

## Address domain and aliasing

`compare` accepts a readonly byte image at numeric base C, with byte j
representing address C+j. The image must not wrap; a last byte equal
to u64::MAX is valid. Each effective address is first reduced modulo N,
then a complete nonwrapping eight-byte range is required inside the
image. Checked subtraction, fallible usize conversion, checked end
addition and slice bounds prevent host truncation or out-of-range reads.
Neither object address nor loaded hop must itself belong to the image;
only the actually accessed qword ranges are required.

All four ranges may overlap at any byte displacement, including shared
objects, identical hops, or deep values aliasing object fields. There
are no stores, and stable memory makes each read equal to its specified
entry-memory value. No disjointness, alignment, object type or monotone
pointer relationship is inferred. Negative-looking numeric hops can
wrap through the +120 addition into a valid image range.

`ImageRange` is a new overall mapping refusal. `FirstHop`, `SecondHop`,
`FirstValue` and `SecondValue` then report the first unavailable read
in the specified order. For example an unavailable second hop is
reported before an unavailable first deep value. These are new safe
API observations, not recovered target fault results. The image is
unchanged on every path. An empty image passes the global shape check
and fails its first required read.

Target correspondence requires actual reached accesses to be valid
ordinary stable memory and valid instruction/control storage. The
numeric image is not a claim that arbitrary u64 addresses are canonical
or process-mappable. Native faults, MMIO, concurrent mutation, code or
control-stack aliases, flags, timing and other registers are excluded.
The return struct is a value projection, not a System V ABI replacement.

## Independent frozen evidence

Before Rust existed, `oracle.py`, the static record and exact expected
streams were frozen with hashes. The oracle computes each qword as a
base-256 sum, interprets unsigned ordering, and replaces the low byte
using `256*floor(X/256)+predicate`. Rust uses endian conversion and a
bit mask. No target instruction emulator, captured execution, copied
reference implementation or Rust output supplies expectations.

The corpus contains 4,827 records: 3,873 normal results and 954 new
refusals across all five error kinds. All 256 low-byte values of a
high-bit-set first value are compared with neighbors, equality and
extremes. Every qword bit, signed/unsigned edges, shared objects,
partial field aliases, exact-end/short images, wrapped field addresses
and seeded additional values are included. There are 3,441 normal
returns whose full RAX exceeds 1. The finite cases exercise witnesses;
the four-read relation proves the complete admitted domain.

All 19,308 native observations match in two builds each at opt0/opt3,
including repeated library/client/output hash equality. Three units
per profile, malformed framing and two comparator controls pass.
All 16 compiled mutants differ. A zero-extended Boolean loses 3,441
returns; signed comparison changes 1,447 records; retaining the old
low byte changes 3,213. Results separately count normal-return and
refusal mismatches. All 138 exact command streams, first counterexamples,
source/tool/compiler/linker hashes and artifact hashes are archived.

Twelve static controls alter fields, compare/write operands, return,
padding, FDE/CIE and caller bindings. Downstream record comparisons
exclude the whole-target hash. Native runs execute only new aarch64
Rust under pinned rustc 1.94.1, not the captured x86 code. No compiled
target-byte identity, whole-node equivalence, recovered source type
or progress-gate completion is claimed.
