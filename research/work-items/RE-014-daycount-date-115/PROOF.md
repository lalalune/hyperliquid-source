# Raw scalar correspondence

Original entry checked-adds365 to EDI and returns zero on signed overflow.
Its reciprocal0x396b06bd with high-word/sign correction yields truncating
n/146097; remainder-sign repair converts that pair to Euclidean quotient and
cycle_day0..146096. The retained inequality bounds multiplier error over the
complete signed-i32 magnitude. No captured instructions are executed.

The next reciprocal0x6719f361 yields a year estimate, followed by leap-table
borrow correction. The full401-byte table includes the97 sentinel; the
400-byte flag table agrees with an independently generated mathematical
Gregorian sequence. Across both complete periods every cycle_day and both
quotient signs are exercised. Since a full cycle is400 years, the Rust
binary search for the largest year_start<=cycle_day yields the same year and
ordinal. The original biased unsigned year gate admits[-262143,262142]; the
Rust range check preserves it. Both combine year<<13, ordinal<<4, flags and
retain the final masked-result gate. The new u32 interface does not assert an
original Rust ADT or Option layout.

Proof assumptions: the authenticated read-only body/tables, raw i32 domain and
ordinary completion of the selected scalar path. The original panic call
sites/unique relative targets are bound but no panic helper/noreturn contract
is inferred. The vendor directory does not identify a source revision. There
is no115 caller ownership/epoch-accessor proof inherited from94.

The own compiler output is independently rebuilt and interpreted with known
synthetic inputs and callee-saved state. Undefined/external memory, unknown
instructions, calls and own .text relocations fail closed. MOVSXD preserves
flags and sign-extends32to64; ROR32by2 sets CF to rotated MSB, leaves OF unknown
and preserves SF/ZF. Only these observed own-code forms are extended locally.
A shared evaluator failure at719163 and a sign-extension-only failure at raw
1096 reproduce the actual blocker. The first private attempt used719163 for
both paths; the second path did not reach ROR. That failed expectation/log is
preserved privately; no target mismatch or success was invented.

Three compiled source mutations alter day offset, leap arithmetic and flags.
Four actual target operand/table patches alter offset, cycle subtraction,
year admission and a flag row, each with a concrete changed result plus
strict identity rejection. Complete native branches/data remain hash-bound.
Finite comparisons support this scalar argument; they do not establish
whole-node behavior, compiler provenance or full source reconstruction.
