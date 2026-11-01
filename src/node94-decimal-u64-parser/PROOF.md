# Decimal parsing, state projection and raw register proof

The target is node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete leaf `[0x54307c0,0x5430857)` is 151 bytes / 48 instructions,
with no callee. Actual FDE/CIE records and the full body are locked separately
from the nine following INT3 bytes. Ten direct incoming calls occur in six
complete FDE-bounded caller bodies. Those callers are evidence of use, not
reconstructed here; the formatting wrapper at `0x514b390` is excluded.

## Input and state domain

The value API input is a pair `(z, tail)`, denoting exactly the logical byte
sequence of z ASCII zero bytes followed by the immutable tail bytes. It also
receives the output slot's initial u64. Ordinary byte strings use z=0. The
logical total length N=z+len(tail) must fit u64. Failure of this addition is the
new `LengthOverflow` API refusal; it is not an original parser return.

For correspondence to a native call, the denoted sequence must be readable
and stable, its starting pointer P and P+N must be representable and nonwrapping,
and its state record/output slot must be valid ordinary memory disjoint from
input and from each other. Concurrent mutation, volatile/MMIO, faults and
state/input/output byte aliases are excluded. The proof is conditional on
these premises; compressed runs do not establish that every abstract sequence
has been materialized in a real process or read by the captured node.

The state starts with pointer P and length N. The returned projection records
consumed C and remaining N-C; the corresponding updated pointer is P+C.
For no consumed digit the original state is untouched, while the counts still
have C=0 and N-C=N. `output_written` distinguishes no store from a store that
happens to preserve the previous value. Raw full RAX is reported. Flags, other
scratch registers, original ABI/types and actual pointer accesses are excluded.

## Digit selection and arithmetic

The leaf loads a byte with MOVSBL at `0x5430826`. It forms `(EAX-0x30)` in R10D
and compares only R10B to 9 unsigned. For every byte b, the low result byte is
`(b-48) mod 256`; it lies in 0..9 exactly for ASCII b in 48..57. Thus Rust's
`is_ascii_digit` recognizes precisely the target class, including all high-bit
byte values. On the admitted digit arm, subtracting 48 gives a nonnegative
0..9, so the subsequent CLTQ has no additional numeric effect.

The accumulator starts at zero. The immediate at `0x54307dc` is
`Q=0x1999999999999999=floor((2^64-1)/10)`, and `(2^64-1) mod 10=5`.
The unsigned comparisons reject precisely `value>Q` or `value==Q && digit>5`.
All other inputs satisfy `10*value+digit <= 2^64-1`. The LEA sequence computes
that sum; Rust's checked-at-admission ordinary multiply/add cannot overflow.
The leading-zero accumulator is always zero and never triggers rejection.

On acceptance, the pointer is incremented, then the state pointer and remaining
length are stored at `0x5430817/0x543081d`. On overflow, control jumps directly
to XOR EAX,EAX and RET at `0x5430840`, before pointer advancement or any output
store. Previously accepted digits remain consumed; the failing digit and all
following bytes remain. The previous output value is retained. Rust exposes
those exact effects, including `output_written=false`.

## Counter and return paths

R8D starts at zero and is incremented modulo 2^32 for each digit, before the
numeric overflow test. On a nondigit, TEST R8D,R8D makes SETG AL true exactly
when the signed i32 counter is positive. The true counter is the number of
consumed digits modulo 2^32 on this path. A nonempty digit prefix of length
2^31 or 2^32 can therefore have AL=0; substituting an unbounded positive count
or an unsigned nonzero test is wrong. On numeric overflow, the extra attempted
digit increment is unobservable in the claimed state/RAX/output projection.

MOVSBL into EAX zeroes the upper 32 RAX bits while sign-extending b into EAX.
The intervening LEA changes R10D, and SETG replaces only AL. Therefore nondigit
RAX is `(0xffffff00 if b>=128 else 0) | accepted`, with upper 32 bits zero.
The RCX output store at `0x5430839` does not change RAX. The API preserves this
full value, rather than conflating nonzero raw RAX with its Boolean low byte.
Every retained direct caller later tests AL; several first save EAX elsewhere.
This qualifies the observed low-byte consumption without assigning a type.

EOF reached after at least one digit instead stores the value and writes
EAX=1 at `0x5430848..0x5430850`, bypassing the counter test. Empty input clears
ECX and EAX and jumps to the same output-store instruction: output=0, RAX=0,
no state advancement. These are distinct from numeric overflow, whose output
store is absent. Rust's final path uses total!=0 to distinguish empty input
from an all-digit sequence, including a compressed nonempty zero prefix.

## Exact concatenation shortcut and bounds

After any k leading zero digits, the accumulator is zero, R8D is k modulo
2^32, the cursor is P+k, and remaining length is N-k. Induction follows because
each zero is accepted, leaves the accumulator zero and advances the cursor
once. This proves the direct initialization at k=z without allocating or
iterating over the prefix. If the tail is empty, the final EOF result is 1 for
z>0 and the empty result is 0 for z=0. Otherwise the tail starts in exactly the
same state as the original loop after those z digits.

Induct over accepted tail bytes using the digit/arithmetic rule. At a nondigit
or overflow, the first stopping event and all projected effects agree. At EOF,
the same output value and special return path apply. Checked total length
ensures C<=N and every accepted increment occurs with C<N, so consumed cannot
overflow and remaining subtraction cannot underflow. Digit count deliberately
uses wrapping u32 arithmetic. Tail iteration and all arithmetic are safe; no
unsafe code, allocation, native pointer or data-dependent unbounded loop over
the compressed prefix exists in the library.

## Independent expectations

Before Rust existed, the oracle isolated the tail's initial ASCII digit string,
removed leading zeroes, and used decimal string length/lexical comparison with
`18446744073709551615` to locate overflow. A 20-significant-digit prefix above
that string first overflows on digit 20; if the first 20 fit, a following
significant digit first overflows on digit 21. All shorter prefixes fit. It
converts only an admitted at-most-20-digit significant string to an integer.
There is no multiply-add accumulator or threshold recurrence in this oracle.
Count and state effects use exact integer lengths and modulo 2^32 separately.

The frozen cases include every two-byte string, every single byte with
compressed-count boundary classes, values around UINT64_MAX, incomplete
prefixes, exact/beyond-u64 logical lengths and seeded mixed strings. Native
input files contain actual zero-count scalars, tail bytes and previous output
values; no expected result or target code is passed into the client. Testing
a compressed prefix in new Rust is explicitly not captured execution of its
expanded target sequence. The induction above establishes the shortcut.
