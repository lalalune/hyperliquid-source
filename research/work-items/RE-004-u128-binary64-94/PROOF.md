# Complete unsigned128 to binary64 native value theorem

Target: Linux x86-64 node94,91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
Actual ELF VA FDE:[0x565ff80,0x5660004),132 bytes,36 complete native rows.
Body SHA-256:bb4270c19daff730aafd37709cf9fa332cf7a809197157277af90ed0a7d88cdd.
The retained complete GNU listing and actual selected FDE/CIE/body mapping are
the proof basis. Named official __floatuntidf correspondence is corroboration,
not a premise that a mathematical conversion occurs. This is static transfer
reasoning; no captured code or instruction evaluator executes.

## Domain, projection and floating environment

Put B=2^64 and let entry n=a+B*b=RDI+B*RSI, with each limb in[0,B), hence
all0<=n<2^128. Assume ordinary x86-64/SSE2 instruction execution, immutable
mapped code, no asynchronous register/code mutation and a valid ordinary RET
word at entry RSP. No stack save, explicit load/store, call or static-data
reference occurs; only RET accesses memory. The function returns the low64
bits of XMM0 equal to the IEEE754 binary64 encoding of n rounded to nearest,
ties to even. The result is finite and nonnegative; zero maps to positive zero.

The complete function performs integer operations and one final MOVQ from RDX
to XMM0 at0x565fffe. MOVQ copies bits without floating arithmetic/conversion,
rounding, exception classification or MXCSR flag updates. No instruction
reads MXCSR. Therefore the bit-value theorem is independent of its rounding,
FTZ/DAZ and exception-mask modes under ordinary valid SSE2 execution. It does
not recover physical clobbers/flags, original ABI/types, arbitrary processor
fault state, caller units or any f64-to-integer saturation/NaN policy. Inputs
are unsigned integer words; there are no floating NaN inputs in this domain.

## Nonzero normalization and masked-count endpoints

First take n>0. If b>0, BSR RAX,RSI at0x565ff80 is defined and XOR63 yields
L=63-floor(log2 b) in[0,63]. A low-limb BSR may have an undefined destination
when a=0, but TEST RSI/CMOVNE at0x565ff99..9c selects the already defined RAX,
so that undefined candidate is irrelevant. If b=0 and a>0, BSR RCX,RDI at
0x565ff8d is defined. XOR63/ADD64 yields L=127-floor(log2 a) in[64,127].
The high-limb BSR destination may be undefined, but CMOVNE does not select it.
BSR's undefined non-ZF flags do not supply a later branch: intervening arithmetic
and the explicit TEST overwrite the required flags. Thus in both nonzero cases:

    L=127-floor(log2 n), 0<=L<=127, N=n*2^L, 2^127<=N<2^128.

0x565ffa0..ffb6 constructs H=floor(N/B) in RDX and J=N mod B in R9.
For L<64, SHLD RDX,RDI,CL forms the high limb and SHL R9,CL the low limb.
The L=0 endpoint is exact because x86 masks both counts to0 and leaves their
operands unchanged. For L>=64, the high input limb is0; the masked count is
L-64 and TEST CL,64 selects the shifted a as H and selects zero as J. At
L=64, the masked count is0 and H=a,J=0, exactly n<<64. No shift-by64 Rust
assumption is used. EAX is explicitly zeroed at0x565ffad before either CMOV.
All these operations are integer operations and cannot raise floating flags.

## Retained significand and every discarded bit

MOV R8,RDX/SHR11 at0x565ffba..ffbd gives

    S=H>>11=N>>75, 2^52<=S<2^53.

Let R=N mod2^75. SHLD RDX,R9,53 at0x565ffc1 produces
V=((H<<53) mod B)|(J>>11). V holds normalized discarded bits74..11.
Its high bit G=V>>63 is R's bit74, the half-ULP guard bit. MOV R9D,R9D at
0x565ffc6 zero-extends J's low32, and OR R9,RDX forms T=V|(J mod2^32).
The overlap of bits11..31 is harmless. T's lower63 bits are zero exactly
when ALL discarded bits0..73 are zero: the two contributing ranges0..31 and
11..73 cover the entire range. No contributing bit can incorrectly enter T's
high guard bit. Therefore:

    G=0 iff R<2^74;
    T=2^63 iff R=2^74;
    T>2^63 iff R>2^74, when G=1.

These statements describe only the comparisons used below; T is not claimed
to encode the numerical75-bit remainder without aliasing.

## Exact nearest-even increment

SHR RDX,63 at0x565ffcc isolates G. MOV R10D,R8D/NOT R10D/AND EDX,R10D
at0x565ffd0..ffd6 produce delta=G & (1-(S mod2)), either0 or1. The 32-bit
writes zero-extend; high garbage cannot affect the later subtraction.
SUB R9,RDX/SHR R9,63 at0x565ffd9..ffdc compute c=(T-delta)>>63.
There is no unsigned subtraction underflow: G=0 gives delta0; G=1 gives
T>=2^63>=delta. Exhausting the cases:

- R<half: G=0, delta0, T<2^63, so c=0.
- R=half and S even: T=2^63, delta1, so c=0.
- R=half and S odd: T=2^63, delta0, so c=1.
- R>half: T>=2^63+1 and delta<=1, so c=1.

Thus c is exactly the nearest/ties-even increment for S. Write
k=floor(log2 n)=127-L. Since n=N/2^L,

    n = (S + R/2^75) * 2^(k-52).

So rounding S by c is precisely binary64 nearest-even rounding of n, including
all midpoint parities. For k<=52 the normalized discarded bits are all zero,
so conversion is exact. The mathematical expression is also valid for k<52,
where the binary64 unit spacing is fractional but the integer input is exact.

## Exponent assembly, carry and finiteness

SHL RCX,52/MOVABS RDX,0x47d0000000000000/SUB RDX,RCX at0x565ffe0..ffee
form E=(1149-L)*2^52. For nonzero n, L<=127, so this is positive and fits64.
OR RDI,RSI at0x565fff1 is nonzero, so CMOVE RDX,RAX at0x565fff4 does not
replace E. ADD RDX,R8; ADD RDX,R9 at0x565fff8..fffb form E+S+c.
If S+c<2^53, write S+c=2^52+F. The encoding is

    ((1150-L)<<52)+F = ((1023+k)<<52)+F,

exactly the rounded binary64 binade/significand. If S+c=2^53, the addition
carries into the exponent and produces ((1151-L)<<52) with fraction0, exactly
the next binade. No other carry is possible. The largest output is2^128,
encoded0x47f0000000000000, so no infinity/NaN or sign-bit/64-bit overflow can
occur. At0x565fffe MOVQ transfers these64 bits to XMM0; RET at0x5660003 ends
the complete function without another value-changing instruction.

## Zero despite architecturally undefined BSR destinations

For n=0, both BSR destinations are architecturally undefined; it would be wrong
to assume they preserve their prior values or to assign L=128. Permit arbitrary
64-bit values in both destinations. The selected RCX/count can then be arbitrary,
but all shifted/joined input limbs are zero for every masked count. RDX and R9
therefore normalize to0, S=0, T=0, G=0, delta0 and c=0. EAX was explicitly
zeroed at0x565ffad. The arbitrary exponent arithmetic may wrap, which is harmless
integer arithmetic. OR RDI,RSI at0x565fff1 sets ZF=1, so CMOVE replaces that
entire exponent candidate with RAX=0. Both subsequent additions add0, and MOVQ
returns exactly positive-zero bits. Every possible undefined BSR destination
therefore gives the same promised output. No undefined intermediate is used as
an address, divisor or unmasked shift count, and none can fault on this path.

The nonzero and zero cases exhaust all2^128 input words. The result does not
require a floating-environment premise beyond ordinary valid SSE2 execution.
