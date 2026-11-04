# RE-007: map node115 position modes and margin arithmetic

Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Independently authored static research; no inferred source was copied.

- Complete FDE `[0x448b800,0x448b967)`: 359 bytes /102 instructions.
- Complete FDE `[0x38b54b0,0x38b55f3)`: 323 bytes /82 instructions.
- Complete FDE `[0x38b5300,0x38b54a9)`: 425 bytes /105 instructions.
- Complete FDE `[0x3beb700,0x3beb972)`: 626 bytes /152 instructions.

Export denominator: **1733 bytes /441 instructions**.
These are evidence extents, not recovered or compiled-comparison coverage.

## Question and local convention

Which raw position mode supplies a direct divisor or a margin-table calculation,
and how does the active-offset variant change the output? The position body and
its two actual margin callees form ONE outcome; they are not separate submissions.

The position body takes output RDI, descriptor RSI, scalar RDX, raw mode CL,
cap byte R8b and an opaque margin-builder argument R9. Valid native objects,
valid mode discriminants, nonzero divisors, stable selected record fields and
normally returning ABI-preserving helpers are preconditions. No original public
Rust ABI, units, leverage names or full risk policy is recovered.

## Position preparation, dispatch and output

`0x448b80d` tests the scalar's sign; a negative word goes to a diagnostic call.
Signed IMUL by descriptor+0x10 branches to the same call on overflow. That call's
nonreturn/unwind contract is unclosed: this is an observed guard route, not proof
of a safe rejection API. On the ordinary route, NEG/CMOVS computes an unsigned
magnitude in R15. A product equal to INT64_MIN retains bit pattern2^63, usable
as an unsigned magnitude; there is no additional signed-absolute rejection here.

The five retained indexed relative entries at `0x7cf4cc` resolve to measured
instructions `0x448b8b0`, `0x448b847`, `0x448b890`, `0x448b8df`, `0x448b868`:

| Raw index | Observed path |
| --- | --- |
| 0 | no division/helper: dispatch EAX=0 reaches the active-tag test directly |
| 1 | unsigned floor division by descriptor u32+4 |
| 2 | construct an opaque object, then call slot0x64e8ba8 ->0x38b54b0 |
| 3 | same constructor, then slot0x64e9508 ->0x38b5300 |
| 4 | direct division with divisor min(descriptor u32+4, unsigned cap byte) |

The constructor through0x64e6dc0 receives R9 and descriptor u32+0x38. Its
construction and selector semantics are unclosed. The direct DIV paths use
32-bit division when the magnitude's high32 bits are zero, otherwise64-bit DIV.
No explicit denominator-zero guard is present in these measured paths. The
five retained table entries are observed valid destinations, not a proved public enum
range or validation of arbitrary raw CL values.

Every path tests descriptor dword+0 against exactly1. Otherwise output qword+0
is0, +8 is the signed product, +0x10 is the initial word (zero for raw mode0; quotient/helper word otherwise), and
+0x18 is the unsigned magnitude. Output+0x20/+0x28 are not initialized on this
arm and are not assigned meaningful inactive values here.

For raw tag1, the signed product plus descriptor word+8 uses signed-overflow
endpoint selection, invokes a diagnostic slot on overflow, and rejoins if that
helper returns. Output+8 is this adjusted/saturated sum, +0x10 is its signed
positive part max(sum,0), +0x18 retains the original magnitude, +0x20 stores the
offset, +0x28 preserves the initial word (zero for raw mode0; quotient/helper word otherwise), and output+0 is1.
This is not an unsigned clamp, nor a claim that the helper always returns.

## Both margin arithmetic bodies

Both leaves call0x3cd80d0 on an object field and a local query descriptor. The
returned tag/state controls a predecessor-like cursor walk before the arithmetic.
The source-level lookup, node invariants and which row is selected are unclosed.
Once a valid selected row pointer is obtained, its byte at -8 is b and its
unsigned qword at -0x10 is c. Source Locations bind both complete bodies to
`l1/src/clearinghouse/margin_table.rs:145:105`.

For input N, the first leaf computes unsigned floor N/(2*b), subtracts c, and
on borrow calls a diagnostic helper before returning0 if it returns normally.
The second leaf uses a different relation:

```
A = sat_u64(2*N)
B = sat_u64(4*b*c)
result = floor(max(A-B,0)/(6*b))
```

This relation requires nonzero b and stable fields across diagnostic calls.
N with its high bit set takes a helper call and then sets A=UINT64_MAX on local
normal return; otherwise doubling cannot overflow. MUL overflow selects
B=UINT64_MAX directly. The subtraction-borrow arm sets the numerator to0,
calls the helper and reloads b. Both division widths are selected from the
numerator's high32 bits. Product overflow itself does not unconditionally call
the diagnostic helper. This is integer arithmetic, not a fee/risk unit claim.
The linked position caller supplies magnitude N<=2^63; the leaves may have
other callers whose validity contracts are not closed here.

At `0x3beb901` a real RELA-bound slot calls the position body. The retained
caller zero-extends its mode/cap bytes, supplies a copied64-byte descriptor and
then tests the output's first byte. Its broader record selection and subsequent
accounting are unmeasured. The complete caller export preserves that context.

## Reproduction and negative controls

Linux Python3.12.3 and GNU binutils2.42; no target execution or emulation:

```sh
python3 research/work-items/RE-007-node115-position-margin-paths/collect.py --output work/risk-replay --check
python3 -m unittest discover -s tests -p test_four_risk_static.py -v
```

The collector authenticates the complete target before any native command or
output, uses a private non-executable copy, agrees on complete unwind ranges
and relocation records with independent readelf, and verifies contiguous native
instruction bytes. Full original bodies, raw FDE/CIE, LSDA coordinates, every
measured direct/RIP call and source Location binding are retained. Text exports
trim trailing whitespace only after instruction-byte validation.

6 focused tests cover original anchors, exact export regeneration, wrong
artifact identity rejection before output, independent corruption of all claim
anchor groups and mutations of actual semantic sites. The dedicated sites
change the raw tag/condition, field displacement, arithmetic or callback/result
branch relevant to this question. Changes occur only in private Python arrays;
neither original nor altered instructions are executed or emulated.
The collector independently decodes all five signed relative table entries and checks their destinations. The additional dispatch control changes an actual relative-table entry and rejects the changed data; all five retained targets must be measured instruction boundaries.

All component gates remain false. No root Cargo graph, source-built node, binary
equivalence, complete original Rust types, protocol execution, signing, chain
action, paid dataset or live user fixture is introduced. New code/analysis is
root MIT; imported artifacts retain their existing terms. Full repository checks
and generated inventory integration are recorded with the final submitted head.
