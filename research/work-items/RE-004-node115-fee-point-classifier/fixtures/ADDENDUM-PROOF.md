# Additive candidate-level unsigned-carry witness

This preserves the original 36-case hand freeze `887aebb50c0b926ca5c9dc3374f6adb970d87c3f557b0a9697015b71a5983ca1` unchanged. The parent proposed A01 after the first qualification, and the independent reviewer checked the arithmetic after the reference source review. It is not retroactively described as one of the original pre-reference expectations. No reference, source, mutant or captured instruction was executed to derive it.

Inputs are t=d=0, q=1, m=2, h=2^63, scale=1 and quantity=1. All values are admitted and exactly representable. Let MAX=2^63-1.

1. The first converted product A is0 and B is0. The B-negative edge does not fire.
2. The third converted value C is2. J=sat(A-B)=0 and K=sat(J+C)=2, so the combined-negative edge does not fire.
3. h*scale*quantity is exactly2^63. The finite integer conversion saturates D to MAX. The subsequent signed-i64-to-binary64 conversion rounds MAX to2^63 (distance1 versus1023 to the preceding float). Multiplication by q=1 stays2^63; the fifth conversion saturates E to MAX. Its sign is nonnegative.
4. U=E+max(D,0)=2MAX=2^64-2, with no unsigned carry in this first sum. G=|C|=2. The final exact unsigned sum is U+G=2^64. The native unsigned-overflow route reports through its ordinary-return hook and retains u64MAX. u64MAX>=quantity1, so the first class is **RoundedMagnitudeAtLeastQuantity**.

For the precisely scoped counterfactual that replaces only the final saturating addition by unsigned wrap modulo2^64, the total becomes0. Then0<quantity1, so the result is **Pass**. This predicts a value-distinguishing control; it does not claim an actual compiled mutant has yet been detected.

The original H21 remains a correct unsigned-carry case but is insufficient to distinguish this particular mutation: its exact total is3MAX, which wraps to2^63-3=9,223,372,036,854,775,805. That is still>=1, so both original and wrapping versions would reject. A01 adds observable discrimination without changing H21 or claiming that every overflow witness kills every wrapping mutant.

The same fixed floating environment and ordinary overflow-hook/frame-preservation premises as v3 apply. The source classification omits native reporting effects and later diagnostic/winner state. The proof supplies no new whole-fee or scheduler claim.

## EXPAND

Qualify this additive case through a separately admitted driver/update while retaining the original qualification receipt. Later compile the exact final-addition wrapping mutation only under the source/build gate and record its actual result; a mathematical prediction is not a completed mutation run.
