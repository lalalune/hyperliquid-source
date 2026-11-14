# Node #115: selected decimal-to-binary64 fractional rounding

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This follows the selected nonzero-scale conversion after divisor construction in #6755. It reuses the independent helper studies `RE-001-node115-f64-powi-leaf` and `RE-001-spot-scale-roundup-fc0-115`; it does not claim their entire domains are reverified here.

On the selected normal path the code computes a two-word quotient and remainder using the divisor, converts the remainder and divisor separately, and divides their binary64 results. It also converts the quotient to binary64. If the fractional result compares equal to zero, the later multiply/round/divide sequence is skipped; the sign flag can still toggle the final sign bit. Otherwise `0x5c44d7f..0x5c44dc6` adds the quotient and fractional binary64 results, calls slot `0x64e7460` with base `10.0` and the scale, multiplies by the returned power, calls slot `0x64e1890`, divides by the saved power and applies the sign flag by XOR with the pinned sign mask.

Pinned relative relocations resolve those slots to `0x63f0080` and `0x63efe40`, respectively. The existing helper packets identify integer exponentiation by squaring and a round-half-away-from-zero helper. The sequence includes intermediate binary64 operations and cannot be replaced by a single exact rational rounding claim without further proof. Existing rounding mode, valid decimal encoding, nonzero divisor and normal helper returns are premises. Error/panic paths, all scale/flag combinations and complete target equivalence remain open.

Run `python3 research/work-items/RE-017-node115-digest-decimal-rounding/verify.py` for the authenticated digest, selected instruction/literal anchors and mutation controls without target execution. `windows.txt` records static windows and relocations. No completion gate changes.

## Prior coverage

Merged `RE-008-node115-fee-trial-source` also includes this helper, with a short-decimal implementation and fixtures limited to a bounded domain (scale up to 16). This packet isolates a selected static path and does not replace that implementation or establish complete conversion equivalence.
