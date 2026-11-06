# Exact reciprocal meaning — static integer proof

This proof identifies the arithmetic in original instructions, not expected
outputs generated from a high-level model. The original instruction collector
freezes every outcome independently before any new Rust exists.

At ELF VA0x2a824eb, x is a raw u64. SHR8 gives n=floor(x/256), so
0<=n<=2^56-1. MOVABS at0x2a824ef supplies K=0x44b82fa09b5a53.
Unsigned MUL followed by SHR of its high word by11 is floor(n*K/2^75).
Let d=1953125. Direct integer multiplication gives
K*d=2^75+399807. In particular delta=399807 is positive, and
(2^56-1)*delta=28809130499521853908545 <37778931862957161709568=2^75.

Write n=q*d+r with0<=r<d. Then
n*K/2^75=q+r/d+n*delta/(d*2^75).
The fractional tail is nonnegative and less than
(d-1)/d+1/d=1. Therefore the captured quotient is exactly q=floor(n/d).
Since d*256=500000000, floor(floor(x/256)/d)=floor(x/500000000)
for every raw u64, including UINT64_MAX. This is an algebraic full-domain
statement, not2^64 executed cases.

CMP/CMOVB then gives min(q,4000); ADD1000 yields1000..5000. The final
unsigned strict comparison chooses raw head0x800000000000001b for L<threshold,
and0x8000000000000018 otherwise. Captured RDX retains the UNCLAMPED quotient,
so comparisons also detect large-input quotient errors hidden by the clamp.

The initial phase's overflowing addition and secondary unsigned guard reach
diagnostic boundaries BEFORE opaque handlers. Independently seeded post-handler
program points qualify their own raw inputs. They are not callback substitutes,
a real observed handler return, nor a composed whole-function execution.
Caller reachability, economic units and all aggregation/global/helper effects
remain unresolved. Native expectations come only from original instructions.
