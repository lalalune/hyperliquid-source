# Conditional invariant and own-object loop proof

This is a manual algebraic/instruction argument, not a machine-checked proof
of LLVM or an original Rust ABI. It complements actual compiled comparisons;
finite test counts alone do not prove the unbounded capacity domain.

## Identity and boundary

Target node115 SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
The five original complete FDEs, both unsigned JB sites for each and their
normal-provider premises are credited to RE-001-node115-nonce-ordering.
Original providers and panic/error/output behavior are not reconstructed here.
A false Rust predicate means the native invariant-failure edge is selected;
it does not assert that the original function returns false.

The own Rust comparison object is47 bytes/17 instructions, code SHA-256
`4ea94f922b183e5bb0c59c30ccf06d4fe48b9682fc50d53fe9f0f1a576294f6f` (see rust-validation.json and own-rust.capstone.txt).
Its bool C interface is the independently chosen logical comparison boundary.
Only AL is the bool result; no claim is made about unspecified upper RAX bits
or original scratch registers. There are no compiled calls or text relocations.

## Raw storage domain

Let capacity=C, head=H, count=N. Require 0<=N<=C, C<=ISIZE_MAX/8,
and 0<=H<C when C>0, otherwise H=N=0. The storage pointer identifies C
initialized u64 words in nonwrapping valid memory; byte alignment is unrestricted.
The source uses read_unaligned, matching ordinary x86-64 MOV loads. The [official read_unaligned contract](https://doc.rust-lang.org/std/ptr/fn.read_unaligned.html)
still requires valid initialized storage; no intermediate unaligned reference is created. These are assumptions of
the original relation, not newly proved provider checks. Reading invalid raw
metadata through an unsafe Rust pointer is outside the contract.

For 0<=i<N define L(i)=H+i if H+i<C, otherwise H+i-C.
Because H<C and i<N<=C, H+i<2C; there is at most one wrap, and L(i)
always indexes valid initialized storage. The bound on C makes head/index
increment, the loop count and the scaled storage address representable.

## The native two-span relation

When N=0 or N=1 there are no adjacent-pair obligations.
For N>=2 let A=min(N,C-H). The first native span checks indices
H..H+A-1, requiring storage[L(i-1)] < storage[L(i)] for1<=i<A.
When A<N, the second span first compares the first span's last element with
physical index0; it then compares successive indices in the second span.
These are exactly the remaining obligations A<=i<N, including the wrap pair.
The spans are disjoint and together enumerate every logical neighbor once.
Both observed branch operands are unsigned JB, so equality and every unsigned
decrease select failure, including around bit63; signed ordering is excluded.

## The actual own-object loop

The retained object starts with AL=1 and returns immediately when N<2.
For N>=2 it loads the value at H into R9 and sets R8=0.
On the loop's first entry RCX=N and RDX=H. Each iteration decrements RCX,
sets AL=(RCX==0), and returns when all N-1 obligations were consumed.
If RCX remains positive, AL=0, so a failed comparison returns false.

Before obligation i (1<=i<N), induction gives RDX=L(i-1) and
R9=storage[L(i-1)]. INC RDX followed by CMP RDX,RSI and CMOVE RDX,R8
computes L(i): the only possible out-of-range index is exactly C, which
is replaced with zero. It loads storage[L(i)] into R10, compares R9 to R10,
then copies R10 into R9 without changing comparison flags. The actual JB
continues precisely for unsigned R9_old<R10. If it continues, the invariant
holds for the next obligation; otherwise AL=0 is returned. After the last
successful obligation, the following decrement sets AL=1 and returns.
The loop therefore implements exactly the union of native pair obligations.

The source and instruction reasoning assumes the captured compiler profile
and all stated memory premises. It does not establish compiler correctness,
concrete original container layout, alias/ownership of provider objects,
caller reachability, or a public anti-replay/nonce admission policy.

## Counterexamples attack three distinct obligations

Actual compiled source controls accept equality ([1,1],H0,N2), omit the wrap
comparison ([0,1],H1,N2), or omit the first comparison ([2,1],H0,N2).
Each changes the own result against the native unsigned relation. Missing
synthetic storage independently fails closed instead of supplying zeros.
The exhaustive and larger-layout evaluation counts in rust-validation.json
are observed runs; this manual argument is separately scoped and not a claim
that the original captured instruction stream was executed.
