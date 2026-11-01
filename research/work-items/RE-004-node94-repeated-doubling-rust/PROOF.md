# Four-entry repeated-doubling relation

This is a numeric and byte-image projection of four complete node94 entries:

| Entry | End (exclusive) | Bytes | Role |
| --- | --- | ---: | --- |
| `0x5656c40` | `0x5656d04` | 196 | Counted loop, low32 count |
| `0x5656d20` | `0x5656d80` | 96 | Prepared six-word step, no data stores |
| `0x5656de0` | `0x5656e57` | 119 | Three steps and one block store |
| `0x5656f00` | `0x5656fb7` | 183 | Three steps per block, low block first |

The four bodies contain 594 bytes and 165 instructions. The single-step entry is
included as a required closed dependency, not counted as a separate discovery.
Tripling wrappers at `0x5656d80` and `0x5656e60` call the separately reconstructed
addition interior `0x565699b` and are context only. The existing repeated-halving,
fixed thirty-step coefficient, and single conditional-correction contributions
have different recurrences. No claim is made about a cryptographic quantity,
canonical reduced representation, function name, calling convention, or caller
meaning.

## Domain and memory order

All six-word operands and the raw count admit every bit pattern. A mutable byte
slice models one stable, nonwrapping mapped address interval; its supplied base
and length must have sum at most 2^64. Every accessed operand and destination
interval must be present. PreparedStep requires only the 48-byte M interval:
its X is the supplied incoming R8..R13 tuple, and its A and destination addresses
do not require mapped data. The supplied destination is still the observable
incoming RDI value. Other entries require 48-byte A/output intervals, or 96 bytes
for the paired entry. M is always 48 bytes. Unaligned and arbitrarily overlapping
intervals are admitted, including address zero in the numeric image model.

The stack, return addresses, code, register-save slots, and all other control
storage must be valid and disjoint from the data image. Saved is the supplied
incoming tuple RBX,RBP,R12,R13,R14,R15. This API does not manufacture stack
contents, dereference native pointers, or model faults, volatile/concurrent
changes, flags, RSP, or the original ABI. M's repeated reads within a block must
be stable; no intervening data store occurs within that block. New API `None`
means an image-domain refusal, with the image unchanged, not an original return
or fault outcome. Admission checks may occur earlier than the original accesses;
this difference is confined to refused inputs.

Counted and Three load all six A words, perform their steps, then store six
results at increasing offsets 0..40. Thus destination overlaps cannot affect
that block's calculation. PairThree performs those low-block stores before
loading any high A word or rereading M for the high block. Its high block sees
the resulting image, including partial/unaligned overlaps with both A and M.
All six high A words and all high-block M reads precede high stores 48..88.
The saved original RSI recovered at `0x5656f38` is used for the high A loads;
its final value is nevertheless clobbered by the final step.

## One step for arbitrary raw states

Let W=2^64, K=W^6, and interpret X and M as unsigned integers in [0,K). The six
ADD/ADC operations form Z=2X, carry c=[Z>=K], and S=Z mod K. MOV instructions
preserve flags and copy S words into R14,R15,RAX,RBX,RBP,RSI in that order. The
SUB/SBB chain forms T=(S-M) mod K and borrow b=[S<M]. The first SBB of a register
with itself gives -c modulo W; the following SBB by zero gives -c-b modulo W.
Its final carry is one exactly when c=0 and b=1: for c=1 the intermediate W-1
can subtract either b without unsigned underflow. CMOVB selects S exactly in
that case, otherwise T. Therefore

    F_M(X) = (2X - M*[2X>=M]) mod K.

This is a single subtraction, not unconditional reduction modulo M. For example
X=M is a fixed point M, including unreduced inputs. M=0 yields doubling modulo K.
The raw step's RDX is (-c-b) mod W, which may be 0, W-1, or W-2. Counted uses
RDI as this scratch register then restores it from the stack before CMOV;
its final RDX comes from the loop counter instead.

## All-count acceleration and totality

DEC EDX occurs after each step. Writing EDX zeroes the high32 bits. For q equal
to the incoming low32, the actual positive iteration count is q when q>0 and
2^32 when q=0, irrespective of the incoming high32 bits.

For M>0, if 0<=X<M then 0<=2X<2M, so the one-subtraction rule is exactly
2X mod M and remains in [0,M). X=M is fixed. For X>M write Y=X-M, with
0<Y<K-M. Until the state becomes smaller than M, the next state satisfies

    F_M(M+Y) = (M+2Y) mod K.

If the next state is still at least M, subtracting M shows its excess is
2Y mod K. Let R_j=(2^j*Y_initial) mod K. At the first index j with
R_j>=K-M, the next raw state is R_j-(K-M), which lies in [0,M).
Before that first index the state is M+R_j. This argument does not extend the
excess recurrence after the first reduced state; doing so would be wrong.
At j=384 the residue is zero because K=2^384. Thus within 384 steps either
reduction has occurred or X has become the fixed point M. The bound includes
M=1, X=M, zero X, and all high-bit/raw states. For M=0, 384 doublings modulo K
instead produce zero. There is no requirement that the initial X be reduced.

The Python oracle searches these directly computed threshold residues from the
initial excess, then uses Python's integer modular power. The Rust source takes
at most 384 literal six-limb steps, then handles the fixed point or scales a
reduced state by 2^remaining modulo M. These are independently structured
calculations. Rust's exponentiation has at most 32 iterations for the admitted
count, with a fixed 384-bit multiply routine. Count zero therefore cannot cause
2^32 native iterations. To recover the exact last auxiliaries, Rust advances
only n-1 steps and performs one final raw step. The oracle independently computes
both X_(n-1) and X_n and checks the final-step algebra.

For reduced a,b<M, modular addition compares a with M-b. If a>=M-b, it returns
a-(M-b); otherwise it returns a+b, which is strictly below M and K. This avoids
a lost 384-bit carry. Bitwise multiplication accumulates these reduced sums and
per-bit doubles, and binary exponentiation computes the required factor. M=1
uses reduced one=zero; M=0 never reaches the modular path. All word additions
use u128 (at most 2W-1); two-stage wrapping subtraction combines borrows by OR.
Every shift is by 1, 32, 63, or a bit index 0..63. Array indices are bounded by
six limbs and checked image intervals. No undefined shift or arithmetic panic
is needed for admitted inputs.

## Complete final general-register observation

Let U be the final corrected six-word value and S the *uncorrected* low384
bits of twice the immediately preceding state. Define H=(-c-b) mod W from that
same last step. The returned projection contains every general register except
RSP (flags and vector registers are outside scope):

| Register | PreparedStep | Three / PairThree | Counted |
| --- | --- | --- | --- |
| RAX | S2 | S2 | S2 |
| RDX | H | H | 0 |
| RSI | S5 | S5 | S5 |
| RCX | supplied M address | supplied M address | supplied M address |
| RDI | supplied destination | supplied destination | supplied destination |
| R8,R9,R10,R11 | U0,U1,U2,U3 | U0,U1,U2,U3 | U0,U1,U2,U3 |
| RBX,RBP | S3,S4 | incoming saved values | incoming saved values |
| R12,R13 | U4,U5 | incoming saved values | incoming saved values |
| R14,R15 | S0,S1 | incoming saved values | incoming saved values |

For PairThree, U,S,H are those of the high block. RDI never advances. Three and
PairThree copy their incoming RDX into RCX before the calls; the API names this
value the M address. Counted takes M from incoming RCX and the raw counter from
incoming RDX. PreparedStep ignores incoming RDX because SBB overwrites it.
There is no assumption that RAX is the destination, a conventional return value,
or a canonical residue. Callee-saved restoration is part of the observation.

## Static and empirical limits

Exact full-body hashes, complete unique FDE/CIE records, alignment bytes, every
relevant decoded direct call, the full .text E8/E9/EB candidate scan, and all
80,300 RELA records are authenticated before admission. Five complete external
caller bodies provide context; their other callees are not reconstructed. The
byte-pattern scan is not a complete indirect-call census. No captured code is
executed. The source's native fixture matches and deliberately wrong variants
qualify this projection on the frozen corpus; the algebra above supplies the
universal relation. They do not qualify original ABI, Linux execution, a node,
chain state, progress gate, or target machine-code equality.
