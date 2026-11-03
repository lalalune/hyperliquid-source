# Arithmetic hypothesis and bounded derivation, pending full native freeze

This is a mathematical explanation of selected instructions, not a replacement
oracle and not an original source/chrono version attribution. Raw native frozen
expectations must still be independently collected from pinned115 bytes.

The signed32 packed word shifted right13 bounds y to[-262144,262143]. Its
logical-shift4/mask511 part bounds ordinal d to[0,511], without validating it
as a date. Lower4bits are ignored. The two other loads are zero-extended u32.

For y>0, t=y-1. For y<=0, x=1-y is1..262145, the instructions compute
n=floor(x/400)+1, t=y-1+400n, and a day correction -146097n. In the latter
case t is1..400, including400 when x is a multiple of400. Thus the t used
by the /100 sequence is always nonnegative and at most262142, not an
unbounded signed integer.

For C=0x51eb851f=1374389535:
C*400-2^39=112 and C*100-2^37=28. In the actual bounded domains,
112*262145 <2^39 and28*262142 <2^37. Consequently the two positive magic
multiplications/shift pairs equal floor(x/400) and floor(t/100), respectively:
the approximation error is smaller than the smallest nonzero reciprocal-step
fraction, so cannot cross an integer boundary. The signed correction after
SAR37 has signbit0 in this established domain. SAR2 of a nonnegative integer
also equals floor-division4.

The 1461 multiply/SAR2 term is365t+floor(t/4). Subtracting floor(t/100) and
adding floor(floor(t/100)/4)=floor(t/400), then d-719163 and the cycle correction,
gives the same expression as:

    days =365*(y-1)+floor((y-1)/4)-floor((y-1)/100)
          +floor((y-1)/400)+d-719163

The extension to negative y follows the exact400year identity
400*365+100-4+1=146097, not truncating negative integer division. This is why
native raw negative milliseconds must be compared independently of the clamp;
checking only the many clamped0 outputs would hide calendar errors.

For nanoseconds z in[0,2^32-1], N=0x431bde83=1125899907 and
N*1000000-2^50=157376. The maximum157376*(2^32-1)=675924773017920 is below2^50.
Therefore (z*N)>>50 equals floor(z/1000000) for the entire raw u32 domain,
including values not valid as original timestamp nanoseconds. This is an exact
bounded identity, not a claim about arbitrary-width nanosecond inputs.

The observed raw RCX value is:

    milliseconds =(days*86400+seconds)*1000+floor(nanos/1000000)

Its absolute value is below10^16 in the raw domain. Date/cycle intermediates
fit signed32 and the final operations fit signed64; a high-level i64 formula
needs no invented saturation or wrapping beyond the observed final signed
positive clamp. RAX is milliseconds if signed-positive, else0. RCX and RAX
are independently observed; no normalization discards negative raw results.

Pending: byte/control-checked full native corpus across all5 instances,
actual negative-cycle corruption controls, source-independent Rust builds,
input-only clients, compiled mutants, and complete repository checks. No
completion gate or universal source/ABI equivalence claim follows from this
explanation alone.
