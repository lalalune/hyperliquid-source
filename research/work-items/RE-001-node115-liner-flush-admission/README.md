# RE-001: node115 liner flush configuration admissibility

Component: node-runtime. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The small configuration routine at `0x14c4770` queries the exact **LINER_FLUSH_PERIOD** name. A nonzero query-result byte selects the bound binary64 default60.0; the returned error storage is conditionally released. On a zero query-result byte, it passes the supplied pointer/length to `0x16876b0`. Parser tag1 reaches the unwrap failure route; it does not fall back to the default. Query and parser internals, including environment access and accepted text grammar, remain opaque.

Successful parsing is followed by a bitwise binary64 gate. The positive-subnormal subtraction test, absolute-bit zero test, exponent arithmetic and sign test together admit exactly finite nonnegative values **plus negative zero**. Positive subnormals and the largest positive finite value are accepted. Negative nonzero values, either infinity and NaNs are rejected. There is no additional positive lower bound or finite upper cap in this routine. Accepted values return their original bits, preserving the sign of zero. A distinct source-bound failure route handles out-of-range values.

Relations enumerate every exponent and both signs with seven mantissa boundaries, and all256 supplied query bytes with both parser tags. This is stratified binary64 coverage, not exhaustive64-bit testing or parser execution. Actual default, parser-tag and exponent-bound operand changes alter the projection. No units, scheduling, flush implementation, environment setup or effective runtime configuration is inferred.

Prior #43 closes a liner initializer's sentinel and failure paths. It does not recover this named configuration or numeric admission rule. No prior exact-name/address claim was found in the all-state census.

Historical provenance: the initial workspace already contained LINER_FLUSH_PERIOD in imported literal/string inventories (including a Visor string dump). Those inventories do not bind this node115 routine or its binary64 admission rule; the name itself is not a new discovery.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| configuration | `0x14c4770..0x14c48cd` | 349 | 81 |

The denominator is 1 complete FDEs, **349 bytes /81 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **20 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-liner-flush-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-liner-flush-admission/verify.py --controls
python3 research/work-items/RE-001-node115-liner-flush-admission/relations.py
python3 -m unittest discover -s tests -p test_node115_liner_flush_admission.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
