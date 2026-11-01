# Static routing argument

All addresses are ELF VAs in node94 with digest recorded in README.md. This is
an argument from the retained complete exports, not execution or emulation of
the capture. Assume ordinary stable readable request bytes, the caller's valid
pointer/length layout, no address/index/length arithmetic wrap, option byte 0 or 1,
and normal returns from preparation/formatting/allocation helpers. Those
conditions are not a recovered public Rust API or a whole-program theorem.

## Preparation has priority

At `0x13e4e59` the option is loaded from request+24. The entry calls
`0x144ada0`, formats the descriptor at `0x1f741d`, passes the returned buffer
pair to `0x144d0d0`, then passes that result's +8/+16 pair to `0x144c180`.
Only a zero return from the latter reaches the command scan at `0x13e4f45`.
A nonzero result returns through R15 after normal cleanup. In particular the
scan is not the first possible failure and the bypass route still requests
this preparation. These helpers' filesystem effects and exact result types
are deliberately not inferred.

## Exact four-byte match, including the vector paths

Let C be the bytes at request+8 with length n from request+16. Matching means
the contiguous bytes `32 3e 26 31` (`2>&1`), without shell parsing.

- n<4 has no possible match; n=0 bypasses the subsequent endpoint reads.
- n=4 compares one little-endian DWORD at `0x13e4f95`.
- 5<=n<=18 compares the DWORD at every position 0..n-4. RAX starts n+1,
  decreases after each comparison, and the loop continues while it is >=5
  (`0x13e4f5f..0x13e4f88`).
- n>=19 forms a candidate mask for a 16-position group at offset b. Each bit
  i represents C[b+i]=='2' AND C[b+i+3]=='1'. The two read-only vectors are
  sixteen '2' bytes at `0x204b30` and sixteen '1' bytes at `0x208900`.
  This mask alone is only a prefilter, not a substring result.

The 240-byte helper `0x13e9340` receives the descriptor `(C,n,>&1,3)`, group
base b, the nonzero low-16 candidate mask in EDX, and prior-match state in
ECX. For this caller's length exactly 3:

1. Prior-match state !=0 returns low AL=0 immediately; the caller retains its
   previous true state by OR. This helper's result alone is not the complete
   aggregate result.
2. Otherwise RSI becomes C+b+1. TZCNT chooses the least candidate bit i.
   The byte arm compares all three bytes at C+b+i+1 through +3 with `>&1`
   (`0x13e93df..0x13e9428`). All equal returns low AL=1.
3. On a mismatch, `ROL16(0xfffe,i)` AND the mask clears exactly bit i and
   leaves all other bits. If the mask becomes zero, EAX=0 is returned;
   otherwise the next least bit is examined. Thus at most 16 candidates are
   examined and the result is true exactly when one selected candidate has
   the full suffix. The general helper's length>=4 arm is retained but its
   arbitrary-length contract is outside this proof.

Combining the prefilter with the suffix comparisons proves an exact match
within each visited interval. The mask's upper 16 bits are zero because it
comes from PMOVMSKB; this is not an arbitrary EDX contract. Nonzero returns
promise only low AL; no claim is made about all upper return bits.

## Coverage of all possible start positions

Intervals below are half-open intervals of candidate starts, not byte reads.
A 16-position group at b covers [b,b+16) and reads through b+18. For no match:

- When n>=68, the four groups b,b+16,b+32,b+48 cover [b,b+64). The first
  iteration has b=0. Another iteration occurs only when old_b+131<n; the new
  b is old_b+64. That condition ensures the next four groups' final read at
  new_b+66 is in range. On exit, residual b is old_b+64.
- Residual groups start at b when b+19<n and continue at increments of 16
  while old_b+35<n. There is no gap between consecutive groups.
- Every n>=19 performs a final group at n-19, covering [n-19,n-3). If no
  residual group ran, its start is at most the end of previous coverage.
  If a residual group ran, the stopping inequality b+35>=n implies
  n-19<=b+16. Thus the final group overlaps or touches the preceding one.
  The final candidate is n-4, and its last byte is n-1.

The small-path comparisons and these adjoining intervals cover exactly
[0,n-3) for n>=4. Early termination is permitted only after a full match;
remaining groups therefore cannot change the Boolean result. Within a large
iteration, a previously found match is preserved by the subsequent ORs even
when the helper returns zero due to the prior-match gate. The first group
starts a fresh local accumulator; the loop backedge is gated on no match.
The final group likewise ORs into the previous accumulator.

`coverage.py` independently checks the interval union for every n=0..4096:
4,097 lengths / 8,378,371 distinct (length,start) pairs. It also checks the
mask-clearing identity for all 65,535 nonzero 16-bit masks. These finite
combinatorial checks support the argument above; they do not execute target
instructions, prove unbounded pointer validity or substitute for the bytes.

## Selection and request order

Conditional on the preparation gate and valid Boolean option:

| Condition, in priority order | Selected request at 0x13e5197 |
| --- | --- |
| C contains `2>&1` | Original request object; no command-text formatter |
| No match, n>0, and C starts `(` or ends `)` | Error-construction request; no launch request |
| No match/end-point error, option=1 | Formatter result using descriptor `0x200573` |
| No match/end-point error, option=0 | Formatter result using descriptor `0x217750` |

Examples of the selection relation, not executed shell commands: `2>&1` and
`(x 2>&1)` take the original-object path; `(x)` and `x)` take the endpoint
error path; empty text and `x(y)z` reach the option-selected formatter.
The test is bytewise even when those bytes occur in quoted text. It is not a
shell syntax parser, balanced-parentheses check or escaping algorithm.

The option=1 descriptor contains literal fragments `(` and
`) > /dev/null 2>&1`; option=0 contains `(`, `) > ` and ` 2>&1 && rm ` plus
an indexed descriptor operand. README.md preserves the exact descriptor
bytes. The callbacks prove which object fields are forwarded, but the shared
formatter's complete callback/output/encoding semantics are not recovered
here. Consequently no exact rendered shell string, successful file operation,
escaping or cleanup behavior is claimed from the literal fragments alone.

On the launch preparation path, a 32-byte allocation holds exactly two
pointer/length pairs: (`-c`,2) and the selected object's (+8,+16) pair.
The entry requests a constructor with (`/bin/sh`,7), then loops with byte
offsets 8 and 24, making exactly two calls through the same R13 target
`0x4ee91a0` on the same local object. Offset 40 terminates the loop.
It next calls `0x4ee64f0` with EDX=0 and ECX=1. This establishes preparation
requests and ordering, not a fully validated argv array or process ABI.

## Result handling and limits

The direct launch helper's result DWORD tag==1 calls `0x13e59d0`; otherwise
selected fields are copied, an input descriptor is closed if !=-1, and the
entry calls `0x4ee8ee0`. Its byte tag!=0 calls `0x13e58b0`; byte tag==0 loads
a DWORD from result+4. On the normal cleanup path that DWORD==0 reaches
R15=0 and the common return; nonzero selects the descriptor beginning
`Shell::wait_inner failed, cmd: `. The endpoint error descriptor begins
`invalid cmd: `. Each error construction's returned pointer remains opaque.
The result tags, raw status comparison and close import are observed; no
transitive spawn/wait semantics, exit-code decoder or iff-success theorem
for all helper results is asserted.

All branch targets within the four extents resolve to decoded instruction
starts, all bytes agree between GNU and LLVM, and every explicit call and
selected indirect target is retained. Exceptional cleanup bytes are exported,
but LSDA landing-pad ownership and unwinding behavior remain unproved.
