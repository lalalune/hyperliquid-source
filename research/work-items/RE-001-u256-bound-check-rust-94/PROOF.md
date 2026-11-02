# Complete u256 helper and fixed-bound wrapper

Target: node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Addresses are linked ELF virtual addresses. `static/records.json` binds exact
bytes, mapped file offsets, complete FDE overlap inventory and the data edge.
Names below describe recovered arithmetic, not original source identity.

## Value domain and observations

Put `B = 2^64`, `M = B^4`. A four-word array represents
`A = a0 + B*a1 + B^2*a2 + B^3*a3`, with every word in `[0,B)`.
The general helper accepts every pair of such arrays; the wrapper accepts every
array. There is no canonical-number, modulus-range, sign or nonzero input premise.
The API returns seven selected full-width data-register values:
`RAX, RDX, RSI, R8, R9, R10, R11` at the corresponding normal return.
Flags, XMM0/XMM1, entry-preserved registers, timing, instruction counts, stack,
control state and the original pointer/calling convention are not represented.
No claim of binary-identical output code or whole-node equivalence is made.

Native correspondence requires ordinary stable readable 32-byte operand spans,
nonwrapping address formation, and little-endian memory values matching the
supplied snapshots. The wrapper additionally requires the exact 32 constant
bytes at the mapped address of linked VA `0x9186a0`. Its original PUSH/CALL/POP/RET
control accesses require a valid stack disjoint from data, code and the constant.
The slice-free API imposes no alignment or relative-address restriction. Native
operand aliases, including exact or partial overlap, are covered whenever their
snapshots are consistent with the same stable memory. Arbitrary independently
chosen values need not be realizable for every chosen overlapping address pair.
The helper makes no stores; the wrapper makes only control-stack writes.
Thus neither may change operand data under these premises. A pointer alias with
its control stack, concurrent modification, MMIO, faults and invalid pointers
are outside the value projection. This is an explicit snapshot API, not a safe
replacement preserving the domain or fault order of arbitrary native pointers.

## General helper: all 69 bytes at 0x565dd80

`static/helper-gnu.txt` and the independent LLVM decode partition all 19
instructions identically. All four left words are loaded before the right
operand's four memory-reading SUB/SBB instructions. R8 receives `a0`; R9, R10
and R11 receive the remaining words. RAX becomes `a0 OR a1 OR a2 OR a3`.

Let `c0=0`. For `i=0..3`, define
`di=(ai-bi-ci) mod B` and `c(i+1)=1` exactly when `ai-bi-ci<0`.
The native SUB/SBB chain implements this recurrence. Induction gives
`sum(di*B^i, i<k) - ck*B^k = sum((ai-bi)*B^i, i<k)`.
At `k=4`, the sum of `di` lies in `[0,M)` and `A-B` lies in `(-M,M)`;
therefore `c4 = [A<B]` and the difference words represent `(A-B) mod M`.
No later helper or wrapper instruction writes R8..R11.

The Rust recurrence uses two unsigned overflowing subtractions. If the first
underflows, its wrapped result cannot be zero when subtracting a single incoming
borrow would make both underflows true: first underflow means `ai<bi`, so the
wrapped result is at least one. The second underflows exactly when the wrapped
first result is zero and the incoming borrow is one. Their OR is precisely
`[ai-bi-ci<0]`; all cases, including `bi=MAX` and incoming borrow, are covered.

`SBB RSI,RSI` yields `-c4 mod B` without depending on the entry pointer value.
MOV sets RDX to one without changing carry, then CMP tests the saved OR value.
If A is nonzero CMOVNE replaces RAX with one; otherwise its OR value is already
zero. AND with RSI gives the complete final values:

```
RAX = [A != 0 and A < C]
RDX = 1
RSI = (B-1) * [A < C]
(R8,R9,R10,R11) = little-endian words of (A-C) mod M
```

The final REP RET changes no claimed data register. No external branch, call,
RIP-relative data access or data store occurs in this leaf.

## Wrapper: all 104 bytes at 0x5651e50

The complete 27-instruction body calls the helper once at `0x5651e5f`, with
RSI formed by LEA to linked VA `0x9186a0`. The exact little-endian constant is

```
N = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
```

It satisfies `0 < N < M`. No mathematical identity or original library/source
name is inferred from this literal. The target reads its contents, not the
numeric pointer value as a bound. The file mapping is in `.rodata` and a unique
read-only PT_LOAD; all 80,300 RELA records contain no writer intersecting these
32 bytes. Stable read-only mapping is still an explicit runtime premise.

The wrapper saves the left pointer in RBX across the closed helper. After the
call it reloads bytes 16..31 into XMM1 and bytes 0..15 into XMM0, then ORs them.
Let `v[j] = input[j] OR input[j+16]` for `0<=j<16`. Copies, byte shifts right
and ORs at distances 8,4,2,1 make byte zero equal to `OR(v[0..15])`: after each
shift stage, byte zero accumulates the union of the corresponding disjoint
index-offset subsets; the final subset is all integers 0..15. In particular
all 32 original bytes contribute, and no byte is ignored. Re-reading gives the
same snapshot because the helper cannot change data and concurrency is excluded.

MOVD followed by MOVZBL leaves `w` in full RDX with `0<=w<=255`. SUB one wraps
only for `w=0`. Logical SHR 63 is therefore `[w=0]=[A=0]`; nonzero values give
`w-1<=254` and have no high bit. OR EDX,EAX preserves the helper's 0/1 and also
zero-extends the result to all 64 bits. Since `N>0`,
`[A!=0 and A<N] OR [A=0] = [A<N]`. Final values are

```
RAX = [A < N]
RDX = [A == 0]
RSI = (B-1) * [A < N]
(R8,R9,R10,R11) = little-endian words of (A-N) mod M
```

RDX thus differs from the helper even for most nonzero inputs; RSI and the four
difference words survive intact. POP RBX/RET restore control state without
changing these seven observations. The Rust wrapper invokes its own reconstructed
helper, tests all words for zero, replaces RDX and ORs RAX, establishing exactly
this relation while leaving the unclaimed SIMD state unspecified.

## Static closure and boundary of caller claims

The complete 121,299-FDE/3-CIE inventory has exactly one matching FDE for each
selected body and each context caller. Both selected bodies use CIE `0xce1518`.
The helper's end is `0x565ddc5`; 27 alignment bytes precede the next FDE at
`0x565dde0`. This adjacent body is boundary evidence only, not reconstructed.
The old packet's phrase "7-byte gap" for `0x565dd72..0x565dd80` is arithmetically
incorrect (14 bytes); no claim here relies on it and historical files are intact.

A whole `.text` E8/E9 byte-candidate scan, followed by instruction-boundary checks
within complete decoded caller FDEs, gives exactly three direct helper calls
(`56508a6`, `5650c86`, `5651e5f`) and two wrapper calls (`5640f59`, `5640f80`).
There are no E9 candidates to either entry. The helper's other callers span
`56507c0..5650951` and `5650ba0..5650d31` (401 bytes each); both use LEA of the
same N. The wrapper's two sites share `5640ea0..5641006` (358 bytes).
Their full bytes/FDEs are bound to establish call-site context and decode
boundaries. Their other helpers, branches and complete behavior are not claimed.
The only outgoing call in the reconstructed closure is the bound wrapper→helper
call. There are no other external branches in either selected body. No relocation
names either entry and none overlaps any bound code window. This is a complete
listed E8/E9/RELA census, not proof that no computed indirect reference exists.

## Independent expectations and finite qualification

`oracle.py` was hashed and its exact inputs/expectations frozen before the Rust
component existed. It uses Python arbitrary-precision whole integers, one
subtraction modulo `2^256`, quotient/remainder digit extraction and direct order
predicates. It does not decode or execute instructions and does not reproduce
the Rust wordwise carry algorithm or wrapper's OR implementation. The constant
was independently transcribed from the target bytes before freezing.

The deterministic corpus covers all 256 bit positions and neighbors, equality,
zero, high-bit ordering, borrowing across every word boundary, MAX plus incoming
borrow, fixed N and each bit perturbation, and seeded full-width random inputs.
All seven output words are compared without masks. These finite checks qualify
the implementation and comparator; the preceding induction and byte-union proof
supply the universal relation. They are not native-target differential tests.
