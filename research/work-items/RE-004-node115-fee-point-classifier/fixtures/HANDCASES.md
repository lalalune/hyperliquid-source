# Independent fixed-domain fee-point handcases

These 36 expectations were assigned by hand before reading or running the new mathematical reference. The assembler serializes literals and checks explicit integer/Fraction certificates; it contains no classification or generic floating-point model. No captured instructions or Rust were executed.

Inputs in candidate-cases.json are explicit 16-hex-digit binary64 encodings. Quantity is always1..10,000,000 and scale is one of the six admitted encodings. The 26 separate primitive boundaries include explicitly unreachable full-candidate controls; those are not marketed as native path witnesses.

Conditions: RN-even, masked exceptions, DAZ=FTZ0; ordinary overflow-hook return preserving operands and FP control. Outcomes identify the first numerical rejection or pass, not final native diagnostic/winner state.

| ID | Expected first class | Hand justification |
|---|---|---|
| H01 | Pass | Every numerical stage is integer0; final0<quantity1. |
| H02 | RoundedMagnitudeAtLeastQuantity | D=1 and E=0, C=0, so final1 equals n1; unsigned >= rejects. |
| H03 | Pass | h*n=(1/4)*2=1/2 exactly; toward-zero D=0, total0<2. |
| H04 | Pass | h*n=(1/2)*2=1 exactly; D1,E0,C0 give total1<2. |
| H05 | RoundedMagnitudeAtLeastQuantity | h*n=2; D2,E0,C0 give total2=n2. |
| H06 | RoundedMagnitudeAtLeastQuantity | h*n=(3/2)*2=3 exactly; total3>n2. |
| H07 | FirstProductNegative | A1 times q=-1 yields B=-1. Stop here; m=-1 and h=1 are not evaluated for later classes. |
| H08 | NetAndBaseNegative | A=B=0, C=-1; J0 plus C gives K=-1. D/E are not reached despite h=1. |
| H09 | SecondProductNegative | A=B=C=K=0, D1 and q=-1 yield E=-1; the threshold class is not reached. |
| H10 | Pass | D=-1 but q0 gives E0. max(D,0)=0, C0, final0<1. There is no D-negative reject. |
| H11 | RoundedMagnitudeAtLeastQuantity | A2,B0,C=-1 produce J2,K1; final unsigned magnitude(C)=1 equals n1. |
| H12 | Pass | C=trunc(-1/2)=0, not -1. A2,B0,K2; final0<1. |
| H13 | NetAndBaseNegative | A=L. F(A)*(-1)=H, whose conversion saturates B=M. A-B=-18446744073709551615 underflows; J=L, C0, K=L. |
| H14 | NetAndBaseNegative | As H13, subtraction saturates J=L; then C=-1 makes J+C underflow too. Both report continuations precede combined-negative. |
| H15 | NetAndBaseNegative | A=L,B0 gives exact J=L; C=-1 makes J+C underflow and saturate to L. |
| H16 | RoundedMagnitudeAtLeastQuantity | A=C=M by finite H saturation; B0,J=M. J+C positive overflow saturates K=M, so no combined-negative rejection. D=E0; |C|=M>=1. |
| H17 | NetAndBaseNegative | C=L,J0 yields K=L. This is not a witness executing final AbsU(MIN); that later path is unreachable. |
| H18 | FirstProductNegative | A=M from finite H. Signed-i64-to-binary64 rounds M to H; q=-2^-63 therefore gives exact B=-1. Using the unrounded real M would wrongly truncate this product to0. |
| H19 | SecondProductNegative | A=B=C=K0; D=M from finite H. F(D)=H and q=-2^-63 produce E=-1. Without that integer-to-f64 rounding the first class would differ. |
| H20 | RoundedMagnitudeAtLeastQuantity | D=M,F(D)=H,q1 gives E=M. U=2M=18446744073709551614 fits u64 without carry, though signed interpretation is -2. G0; threshold rejects. |
| H21 | RoundedMagnitudeAtLeastQuantity | A=B0,C=M gives K=M. D=E=M, U=2M. U+G=3M=27670116110564327421 exceeds u64MAX, so final saturation is u64MAX and rejects. |
| H22 | Pass | d=-1 makes 1-d=2. Multiplying finite max by2 overflows to +infinity; A converts that nonfinite result to0. All remaining integer stages0. |
| H23 | Pass | m=maxfinite with scale6 overflows at m*s to +infinity; C=0 by nonfinite conversion. t=h=q0 leave all stages0. |
| H24 | Pass | n3,h=3/4 gives exact product9/4 and D2. q=maxfinite times F(D)=2 overflows to infinity, so E0. A0 times finite q is0; C0. Final2<3. |
| H25 | Pass | A input product is +infinity; conversion maps it to0. q1 and other zeros give B=C=D=E0 and pass. |
| H26 | Pass | A input product is -infinity; conversion maps it to0, not i64MIN. Remaining stages0. |
| H27 | Pass | 1-d is NaN; the A product stays NaN and conversion yields0. Other stages0 under masked FP exceptions. |
| H28 | Pass | Multiplication quiets the signaling NaN under the admitted environment; nonfinite A converts0. No NaN payload/exception trace is an output. |
| H29 | Pass | A=D=0. F(A)*q and q*F(D) are invalid 0*infinity products, become NaN under masked exceptions, then each converts0. Final0<1. |
| H30 | RoundedMagnitudeAtLeastQuantity | Exact represented 0.1 times10 is 1+2^-54, strictly below the midpoint 1+2^-53; RN-even gives1. D1,E0,C0, final1=n1. |
| H31 | Pass | Scale0.2 times h1 stays that exact encoded value; multiplying by n5 gives exact1+2^-54 before rounding, so D1. Final1<5. |
| H32 | Pass | 2*(1/4)=1/2 exactly, times n1 unchanged; D0 by truncation. All other stages0. |
| H33 | Pass | 40*2^-6=5/8 exactly; n1 leaves it unchanged, D0 by truncation. |
| H34 | Pass | m=-2^-1074, s1, n10,000,000. Product is exactly -10,000,000*2^-1074 (subnormal grid integer below2^52), with magnitude<1; C truncates0, all other stages0. |
| H35 | Pass | t=2^-1074 and s=encoded0.2<1/2. Their positive product lies below half the smallest subnormal; RN-even rounds to +0 before A conversion. |
| H36 | Pass | t,m,h are negative zero; their converted integer results are0. Both q products also convert0. Signed-zero payload distinctions are not classification outputs. |

## Boundary and reachability limits

The final-stage third conversion C=MIN is unreachable: J<=MAX implies sat(J+MIN)<0. H17 is an earlier-rejection case; P24 describes only the unsigned-magnitude primitive. Positive subtraction overflow after B>=0 and u64 carry in the first sum are likewise unreachable. Generic i64-to-f64 halfway inputs2^53+1/+3 cannot be A/D outputs of the native conversion map; P13/P14 remain primitive-only.

H18/H19 provide reachable integer-to-f64 rounding witnesses: finite +2^63 first converts to MAX, then MAX rounds back to +2^63, and multiplying by -2^-63 yields -1. This determines a different first class than pretending MAX converts exactly.

No cases outside the fixed quantity/scale domain are classified as native errors. The complete outer fee/Rayon operation, final winner state, allocation, exception flags, NaN payloads, hook completion and effect traces remain outside these fixtures.

## EXPAND

After sealing, another reviewer may compare the frozen candidates and primitives against an independently reviewed reference. Any mismatch must preserve this original fixture and be investigated algebraically; it must not be silently changed to match an implementation.
