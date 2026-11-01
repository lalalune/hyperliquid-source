# Six-word subtraction family: raw, saved, prepared and high-first pair

This proof is bound to node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It recovers one subtraction/correction family, not a semantic name or a
cryptographic-domain assumption.

| Role | Complete FDE interval | Bytes | Instructions |
|---|---|---:|---:|
| Saved wrapper | `0x56570a0..0x56570dc` | 60 | 17 |
| Canonical raw | `0x56570e0..0x5657169` | 137 | 39 |
| High-first pair | `0x5657180..0x56571e3` | 99 | 26 |
| Exact raw alias | `0x56580a0..0x5658129` | 137 | 39 |
| Exact raw alias | `0x565ae00..0x565ae89` | 137 | 39 |

The canonical closure is 296 bytes/82 instructions. The two aliases add 274
authenticated bytes/78 instructions, not independent arithmetic implementations.
All three raw bodies are byte-identical and share one `Raw` relation. Actual
calls to `0x56580bb` and `0x565ae1b` enter 27 bytes into the corresponding raw
FDE, skipping ENDBR64 and the six A loads. These 110-byte/32-instruction tails
share one `Prepared` relation. They are not separately counted as whole FDEs or
additional body bytes. The canonical corresponding offset `0x56570fb` has no
direct E8/E9/EB candidate; no actual call to it is asserted.

The candidate addition at `0x5658000..0x5658093` is deliberately excluded:
its 147 bytes are exactly those at `0x5656980..0x5656a13`, already covered by
the separately reserved addition family. No addition implementation is repeated
here. The twelve-word family at `0x5657ce0/0x5657e00/0x5657f20` is also separate:
it corrects only its upper half and has intra-call live reads after low stores.

## Closed calls and static facts

Saved calls canonical Raw once at `0x56570b2`. Pair calls canonical Raw twice
at `0x56571a7` and `0x56571b9`, high block first. All callee bytes are included.
The raw bodies/tails have no further calls, branches or RIP-relative data.
The only memory outside supplied data is the wrappers' stack saves/restores and
ordinary call/return control. No correction table or global variable is read.

The exact FDEs/CIEs and subsequent 4/23/29/23/23-byte padding regions are bound
separately. All 80,300 RELA records are scanned for naming addends (including
interior entry addresses) and overlapping body/padding writers. The complete
`.text` E8/E9/EB scan finds 167 E8 candidates, all verified instruction-boundary
calls: 3 internal wrapper calls and 164 calls in 30 complete external caller
FDEs (23,428 bytes). Two are the prepared entries noted above. No E9/EB candidate
is found. The full callers are authenticated context, not implementations of
their unrelated multiplication or surrounding arithmetic. Indirect references
and whole-node ownership remain open; no complete reference census is claimed.

## Observation and safe-image domain

The library receives a mode, mutable image, u64 numeric base and A/B/M/D
addresses, entry saved-register values, and prepared R8..R13 values. An image
represents contiguous bytes `[base,base+len)` with end at most 2^64. Ordinary
Raw/Saved require A/B/M/D spans of 48 bytes. Pair requires A/B/D spans of 96
bytes and M of 48. Prepared requires B/M/D of 48 and **does not require or
read A memory**: its six A words are the supplied initial R8..R13 registers.
All required spans fit the same nonwrapping image. Arbitrary unaligned and
partial aliases among data spans are admitted, with all word values arbitrary.

Original successful-access correspondence assumes stable ordinary mapped data,
valid normal control/return state, and original stack/control storage disjoint
from the entire data image. No MMIO, concurrent mutation, fault order, native
ABI, flags, original stack bytes, or existence of arbitrary synthetic address
mappings is claimed. Numeric fixtures are byte-image values. The source does
not impose a 384-byte cap: that is only the client's record capacity.

Global interval and all required spans are checked before mutation. `None`
therefore leaves the image unchanged. This is a new safe-API refusal, not a
target return/fault or partial-fault execution. In particular, a Prepared call
with absent A memory is admitted if B/M/D exist. Entry saved values only matter
for Saved/Pair; Prepared values only matter for Prepared. The unused tuple is
not a second claim about the same physical entry registers.

Successful observation includes every image byte and full final RAX,RDX,RSI,
R8..R11,RBX,RBP,R12..R15. RDI and RCX remain their original D/M addresses
(Pair adds and later subtracts 48 from RDI); their preservation is stated but
not duplicated in the register result. RSP/RIP/control behavior is excluded.

## Raw arithmetic for all 384-bit values

Let B0=2^64 and K=B0^6. Let A, B and M be unsigned 384-bit little-endian
integers formed from their actual loaded words. Raw loads all A words, then
all B/M words interleaved with the subtraction, before the first data store.
Thus every input word comes from the entry image even under arbitrary aliases.
Prepared starts at the first SUB and has the same relation with A supplied by
the prepared registers. Incoming carry/flags do not contribute: SUB sets the
first subtraction borrow itself.

Six SUB/SBB instructions produce `S=(A-B) mod K` and `b=[A<B]`. SBB RDX,RDX
sets the complete mask `RDX=(-b) mod B0`. Six AND operations produce words
`v_i=b*m_i` from the unconditionally loaded correction words. Six ADD/ADC
operations then produce

`U=(S+b*M) mod K = (A-B+b*M) mod K`.

Final carry is discarded, with no seventh output word. This is exactly one
conditional addition. There is no restriction such as `A<M`, `B<M`, `M>0`,
odd M or a promise of a canonical modular result. M=0 and maximum words are
included. Even when b=0, all six M loads really occur; zeroing the mask does
not make missing M memory admissible.

Let u_i be U's words. Output words D+8i receive u_i for i=0..5 in order. The
target interleaves some of these stores with register additions, but no source
read follows the first store; calculating U first and storing it afterward is
equivalent for ordinary-memory final values. Outside D..D+47 is unchanged.

Full Raw/Prepared final registers are:

| Register(s) | Value |
|---|---|
| RAX | v_2 |
| RDX | (-b) mod B0 |
| RSI | v_5 |
| R8,R9,R10,R11,R12,R13 | u_0,u_1,u_2,u_3,u_4,u_5 |
| RBX,RBP | v_3,v_4 |
| R14,R15 | v_0,v_1 |

In particular RAX/RSI contain masked correction words, not output words.
No prior callee-register value survives in Raw/Prepared. `execute` represents
this exact relation once and is used for every identical raw alias.

## Saved wrapper

Saved pushes RBP,RBX,R12,R13,R14,R15, reserves eight bytes, calls Raw, reloads
the six saves and restores its stack before RET. Under the disjoint-stack
premise, Raw sees the same data image as entry. Data effects and RAX/RDX/RSI/
R8..R11 are Raw's; RBX/RBP/R12/R13/R14/R15 restore the supplied entry tuple.
No source pointer is recovered from one of the clobbered raw registers.

## Pair: the high store is an input to the low call

Pair saves its six callee registers and original A/B pointer registers on its
stack. It forms A+48, B+48 and D+48, calls Raw, reloads A/B from stack, restores
D by subtracting 48, then calls Raw again. M remains the same pointer but its
**contents may change** after the high output stores.

Let I be the entry image. First compute `H=raw_value(I,A+48,B+48,M)`, then let
J be I with the 48 H bytes overlaid at D+48. The low result is
`L=raw_value(J,A,B,M)`. Final image is J with L at D. This is a well-founded
two-stage relation: no circular assumption or pre-snapshot of both blocks is
needed. The high output may overwrite low A, low B, any M byte or multiple
roles. All low inputs must be sampled from J, including partial qword overlap.
The high and low destination blocks are disjoint by their admitted contiguous
96-byte span, but their sources need not be disjoint from either output.

Each Raw call resets its own borrow chain at SUB. No borrow is propagated from
the high call into the low call. Final RAX/RDX/RSI/R8..R11 are those of the low
call on J; wrapper stack restoration replaces the six callee-register values
with the entry tuple. High-call register temporaries are discarded. Final RDI
is D and RCX is M. Running low first, restoring entry snapshots for the low
call, or returning high-call temporaries changes this relation.

The Rust implementation validates the full Pair spans first, executes the
high block, then reads low A/B/M from the now-mutated slice and executes low.
It does not materialize an entry snapshot of both blocks or correction data.

## Arithmetic and bounds proof for Rust

For a single word, `overflowing_sub` gives the residue and first borrow of
`a_i-b_i`; subtracting the preceding Boolean borrow gives the second borrow.
Their OR is exactly the borrow of `a_i-b_i-b_prev`. Induction on i proves the
six-word S and b. The `0.wrapping_sub(b)` mask is 0 or B0-1, so bitwise AND
produces exactly v_i. In correction addition,
`u128(result_i)+u128(v_i)+carry <= 2*B0-1`; the u128 sum cannot overflow and
its high bit is the next carry. Its low word is the correct residue. This
proves U without any dependence on machine overflow settings or signed order.

All loops have six iterations. There are no divisions or variable shifts.
Checked address subtraction, checked usize conversion/end arithmetic and the
global u128 interval check establish every eight-byte access. Pair's 96-byte
precheck establishes both offsets and prevents numeric pointer wrap within its
admitted spans. Prepared performs no A-span check. Therefore every supplied
slice/address/register input either refuses without mutation or completes the
specified value relation, under the stated original-execution premises.

## Independent oracle and qualification limits

The oracle was frozen before Rust existed. It uses unbounded 384-bit integers,
comparison for b and one modulo operation for U. For Pair it creates an
immutable high-output patch, computes low byte intervals after that patch,
and builds the final two overlays. Rust instead uses word-level borrow/carry
loops and live mutable image reads. No oracle output is derived from Rust or
native results; neither route executes captured instructions or emulates a CPU.

The frozen 20,577 cases include all 384-bit rank boundaries with +/-1 neighbors,
arbitrary and boundary correction values, register bit bases, all valid output
byte offsets over five alias layouts, missing spans, image endpoints, prepared
values independent of A memory, and deterministic arbitrary words. There are
19,687 admitted and 890 refusal records; the Pair subset has all four high/low
borrow combinations, 222 changed low-A values, 247 changed low-B values and 284
changed M values. Twenty Prepared cases have absent A memory and remain valid.
Finite native tests support, rather than replace, this universal derivation.
Machine-code identity to newly compiled Rust, indirect callers, higher-level
quantities, whole-node equivalence and milestone gates remain unclaimed.
