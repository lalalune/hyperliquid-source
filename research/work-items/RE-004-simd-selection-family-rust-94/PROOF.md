# Six SIMD selection leaves and their staged byte origins

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
This is one coherent family contribution, not six isolated copy predicates.
All six complete bodies total1,581 bytes and360 instructions:

| Entry | Exclusive end | Body bytes | Instructions | Data width W | Pointer advance |
|---|---|---:|---:|---:|---:|
| 0x5657540 | 0x5657598 | 88 | 22 | 32 | 16 |
| 0x56575a0 | 0x5657616 | 118 | 28 | 48 | 24 |
| 0x5657620 | 0x56576e4 | 196 | 46 | 96 | 48 |
| 0x5657700 | 0x5657866 | 358 | 82 | 192 | 96 |
| 0x5657880 | 0x5657998 | 280 | 64 | 144 | 72 |
| 0x56579a0 | 0x5657bbd | 541 | 118 | 288 | 144 |

The descriptive label does not identify the original source, numeric types or
owning application component. No neighboring body or exhaustive family census
is claimed. All widths and advances are recovered from actual memory operands,
not inferred from FDE strides or source-like labels.

## Selector and complete GP observations

Let N=2^64. Incoming RDI,RSI,RDX are destination D and sources A,B; incoming
RCX=C is the control word and incoming RAX=R is preserved. Only the low32 bits
of C determine the selection. All C,R bit patterns and data bytes are allowed.
The selected source is A if C mod2^32 is nonzero, otherwise B. Both sources
are nevertheless read in their entirety by the original instructions.

Every leaf starts with ENDBR64, MOVD from ECX into XMM5, PXOR clearing XMM4,
and PSHUFD broadcasting XMM5's low dword into four lanes. MOVD initially clears
the other96 bits, but the broadcast makes all four lanes exactly low32(C).
PCMPEQD against zero makes XMM5 all128 ones exactly when low32(C)=0,
otherwise all128 zeros. PCMPEQD of the zero XMM4 against this mask makes
XMM4 its bitwise inverse. There is no signed comparison or requirement C=1.

For each pair of loaded vectors, PAND with XMM4 selects the A vector, PAND
with XMM5 selects the B vector, and POR combines them. Every output bit is
therefore the selected source bit from the time of that block's load. This is
integer bit selection; floating interpretation and NaNs are irrelevant.

Each body changes its three pointer registers exactly once with LEA, adding
W/2. All subsequent memory operands use offsets relative to those advanced
registers. No other GP register is written. At normal return the explicitly
projected complete register values are

```
RAX = R
RCX = C
RDI = (D + W/2) mod N
RSI = (A + W/2) mod N
RDX = (B + W/2) mod N
```

SIMD output registers, flags, RET stack effects, CET, native ABI and remaining
entry-preserved GP registers are outside the value API. The Rust return object
reports numbers; it does not place them in the original physical registers.

## Actual load/store schedule

Write n=W/16. Each block is16 contiguous bytes. The complete schedule, with
irrelevant vector masking operations omitted but every data access retained,
is identical across the six bodies:

1. Load A block0, then B block0.
2. For i=1..n-1: load A block i, load B block i, then store selected block i-1.
3. Store selected block n-1.

The new static verifier independently extracts MOVDQU source/store operands
and the three fixed LEA biases and checks this complete schedule against every
body. This is static address normalization, not execution or instruction
emulation. All extracted offsets are ordinary fixed displacements; no loaded
value is interpreted as a pointer. No body calls a helper, branches on data,
or uses a RIP-relative table.

For W=32 both blocks from both sources are loaded before the first store.
For larger W, a later block is read after earlier stores. A whole-input snapshot
is therefore not a universal replacement. Conversely, storing a current block
before loading the next removes the original lookahead and is also wrong on
some aliases. Both differences matter even though the selected source is fixed
for the whole call. Unaligned and partial aliases are allowed among all three
spans under the ordinary-memory premises.

## Universal acyclic byte-origin relation

Use numeric offsets a,b,d into one admitted image, and let s=a or b according
to the control. Let M0 be the entry bytes. For k in0..W-1, put j=floor(k/16)
and t=s+k-d. The byte Y[k] eventually stored at destination offset d+k is

```
Y[k] = Y[t],     if 0 <= t < W and floor(t/16) <= j-2;
       M0[s+k], otherwise.
```

When block j is loaded, precisely destination blocks0 through j-2 have already
been stored. For j=0 or1 that set is empty. Destination blocks are disjoint,
so if source byte s+k lies in that earlier set it contains the corresponding
previous output byte Y[t]; otherwise it still contains its entry byte. There
are no other writes. Both source loads for a block occur before its following
store, so the same argument applies regardless of whether A or B is selected.

On the recursive branch, t<16(j-1)<=k-16, hence t<k. The relation is acyclic
and defines each output byte uniquely by induction on k. It is a relation
between entry and final bytes, not a register/flag simulator or a translation
of the instruction list. The final image replaces exactly [d,d+W) with Y;
all other bytes retain M0. This proof covers every admitted image, including
all three spans overlapping and data equal to any arbitrary byte pattern.

The two-buffer Rust implementation expresses the original schedule directly:
retain the current selected16-byte block, obtain the next block from the current
image before storing the retained one, and finally store the last block. The
induction above shows its final bytes equal the independent byte-origin oracle.
Only two16-byte temporaries are required; buffering the entire input would
silently discard the established staged-alias behavior.

## Finite-image domain and refusal

The new enum selects one of the six recovered widths; it is not an original
machine argument. Byte i of a mutable slice represents numeric image_base+i
in one nonwrapping interval. The u128 exclusive endpoint may equal N but must
not exceed it. Numeric A,B,D never become native pointers.

Every original call reads all W bytes from both sources and writes all W bytes
to D, with no conditional access omissions. The API therefore requires all
three complete W-byte spans. Checked subtraction from image_base, conversion
to usize and checked end arithmetic establish that each fits before any store.
The later fixed block offsets remain within these proved ends. No alignment
restriction is added. A nonwrapping represented span also ensures the advanced
pointer and its positive/negative addressing displacements denote the same
effective bytes as the original modulo-N address expressions.

The source with a zero vector mask is still a required span. Omitting its
admission would expand the safe API's successful domain beyond the documented
target-access premises. Under stable ordinary readable memory, its actual byte
values cannot influence selected results; no claim is made about a compiler
retaining identical memory-read instructions.

`None` is a new refusal for an invalid image or missing span; it leaves all
bytes unchanged. It does not reconstruct native exceptions, their ordering or
partial writes. Prevalidating all fixed spans before the safe implementation
writes is valid for normally returning correspondence and this separately
specified refusal. The original requires valid normally completing control,
stable ordinary memory and data disjoint from executable/return-stack state.
MMIO, races, concurrent intermediate observations, faults and instrumentation
that changes execution are outside the projection. Those exclusions do not
exclude arbitrary aliases among the represented data spans.

## Static evidence and independent expectations

All six full bodies and unique FDE/CIE records are authenticated. Following
NOP padding is separately bound as8/10/28/26/8/3 bytes; it is not included in
the semantic bodies. GNU, Apple LLVM and Capstone must agree on complete bytes
and instruction boundaries. Exact mask/selector instructions, memory schedule,
pointer advances and REP RET boundaries are checked independently of a source
label or compiled Rust output.

The full .text census finds84 E8 and2 E9 candidates to selected entries,
within34 complete caller FDEs totaling19,221 bytes/4,852 instructions. Complete
caller bytes and instruction boundaries qualify those sites and exact targets.
Caller algorithms and their other dependencies are not reconstructed. All80,300
RELA records are checked; no naming record or body/padding writer exists for
the selected leaves. Raw direct scans are not a complete indirect-reference
census, and the leaf with no direct candidate is not claimed unreachable.

The oracle and full expected streams are frozen before the new Rust directory
exists. The oracle uses the acyclic origin relation over Python whole-byte
arrays; it does not import Rust, execute captured code or simulate SIMD/flags.
The input-only native client receives descriptors and synthetic images, never
expectations. Native four-build comparisons, compiled controls and structural
corruptions complement the universal proof; they are finite qualification,
not exhaustive images or original compiled-byte/whole-node equivalence.
