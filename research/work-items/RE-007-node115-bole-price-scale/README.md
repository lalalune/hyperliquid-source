# RE-007 — Node #115 borrow/lend refresh price scale binding

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [index writer packet](../RE-007-bole-index-writer-115/) identifies the refresh context. Calls at `0x369aa3b`, `0x369aaab` and `0x369ac84` lead to `0x369f730`.

The helper multiplies two scalar binary64 inputs. The finite nonzero arm splits the product bits and passes them to the existing [float-to-decimal converter](../l1-shared-f64-to-decimal-115/) with the f64 and rounding flags set. The zero product path keeps the sign bit and uses the 12 zero coefficient bytes at `0x4553c4`. A nonfinite product or conversion failure takes the zero-return path.

After successful conversion the helper indexes a 0x158-byte record table and reads the selected record's list at +0x58/+0x60. The list indexes 32-byte rows, scanning for a zero word at +8. For the qualifying row, its +0 word identifies a reference record in the same 0x158-byte table. The unsigned scale input is the table base record's +0x49 byte minus the reference record's +0x48 byte. The subtraction has a separate carry branch.

The call at `0x369f900` passes the decimal, mode 2 and the resulting unsigned scale through slot `0x64e6468` to `0x421e9d0`. Result tag `0x1a2` causes return of the scaler's +8 qword. Other tags go to cleanup and a zero return. The selected refresh caller at `0x369aa3b` tests the returned qword against zero. Record semantics beyond the observed offsets, scaler internals and the refresh's other stages remain outside scope.

Run `PYTHONPATH=tools python3 research/work-items/RE-007-node115-bole-price-scale/verify.py` from the repository root. It checks the instruction windows, selected calls, relocation and scale subtraction model.
