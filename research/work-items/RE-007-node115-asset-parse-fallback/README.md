# RE-007: #115 asset-parameter parser fallback

The [asset-registration packet](../RE-007-node115-asset-registration-path/README.md) traces a second string to a parser but leaves that parser's body open. This packet maps selected direct-result and floating fallback gates inside `0x43099f0`. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses. It is static analysis only; no target code is executed or emulated.

## Observation

The prior caller's selected call `0x3c42299` goes through `0x64e4e60`, whose relative relocation names `0x43099f0`; it later compares the result word with `0x1a2`. The prior packet covers the input pointer/length and admission context, not the parser body.

The existing [decimal parse binding packet](../RE-002-node115-rust-decimal-parse-bindings/README.md) binds selected literal references inside `0x5c44210` without mapping this wrapper. The parser first calls through slot `0x64e95c0` (relative addend `0x5c44210`). If that helper returns dword 6 at the stack result, it copies 16 bytes from the helper result at `+4` into output `+4` and writes output word `0x1a2`. This is a conditional output-transfer observation, not a statement of the helper's accepted text grammar.

For other helper result dwords, the parser forwards the original input pointer and length to slot `0x64e0048` (relative addend `0x16876b0`). A returned byte 1 takes a branch that writes output word `0xb0`. Otherwise the parser examines a returned 64-bit pattern `bits`: it masks the sign bit and compares the remainder with `0x7ff0000000000000`. Magnitudes at or above that threshold take the `0xb0` result branch. Under the IEEE-754 binary64 interpretation, this excludes both infinities and NaNs on this fallback branch; the packet does not assert which strings the helper accepts or whether it can actually return any particular pattern.

For remaining nonzero finite patterns, the code extracts the 11 exponent bits and 52 fraction bits. When the exponent is nonzero, it sets the implicit fraction bit and passes `exponent_bits - 1075` as a 32-bit exponent to `0x5c43c60`. When the exponent is zero and the fraction nonzero, it instead passes the fraction without that bit and exponent `-1074`. The sign argument is 1 when the original sign bit is clear. Two further arguments are both 1. A returned dword of 1 continues to the 16-byte payload preparation and output word `0x1a2`; other values take the `0xb0` word path. These observations do not decode the converter's rounding, range, output type, units or all error behavior.

The zero-pattern arm instead extracts the sign bit, shifts it into bit 31 of a temporary dword, and loads the remaining temporary fields from fixed data before joining the selected successful-output preparation. This establishes a bit-level distinction between the two zero patterns at that point, not a claim about final exchange semantics. All cases above assume the selected calls return normally and obey the ordinary calling convention.

## Evidence and limitations

`instructions.tsv` contains the full parser FDE and selected caller window. `verify.py` authenticates the target digest, two indexed FDE boundaries/body hashes, 132 instruction spans, 44 explicit byte pins, five targets and three relative relocations. It independently checks eight examples of the observed masks and rejects eight modified anchors. The examples are arithmetic checks of the recorded bit tests, not captured-instruction execution or proof of parser equivalence. Reproduce from the repository root with `PYTHONPATH=tools python research/work-items/RE-007-node115-asset-parse-fallback/verify.py` using Python with Capstone.

Both text-consuming helper bodies, their accepted input grammar, the converter's semantics, cleanup/unwind, later `0x421e9d0` processing, runtime execution and cross-version equivalence remain open. No completion gate is requested.
