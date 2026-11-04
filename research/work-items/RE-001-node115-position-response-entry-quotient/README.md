# RE-001: node115 position response entry-price quotient before decimal scaling

Component: info-api. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

Producer `0x2c7fd80` is bound to `info_server/src/f_types/position.rs`. A zero signed size at input+0x10 returns outer qword tag2 immediately. For a nonzero size, the function selects a DEX and asset row, obtains a nonnegative mark-like integer from row+0x20, and checks the signed product with size for overflow. The input+0x30 value is required nonnegative when nonzero.

The price optional at output+0 is absent when that entry-like value is zero or less than the unsigned magnitude of size. Otherwise it computes **integer division first**: entry value / abs(size), selecting the32-bit divide only when both operands fit32 bits, then converts the quotient to binary64. An asset decimal byte must be below7. The value is divided by the retained table entry indexed by6 minus that byte, and output tag1 plus binary64 payload at+8 are stored. Fractional remainder is therefore discarded before decimal scaling. For example, entry value10 and size3 use quotient3, not10/3 in binary64. The name entry price is an inference from source context and the earlier response-formatting layout, while the raw offsets and arithmetic are directly bound here.

The adjacent subtraction uses signed product minus sign(size)*entry value with an overflow check. A zero entry value explicitly sets this intermediate to zero instead of retaining the product. This distinction is retained as context for future PnL reconstruction, without claiming the entire response's financial meaning. INT64_MIN size has magnitude2^63 and cannot reach present-price division under the nonnegative signed entry-value premise.

Relations test absence, magnitude boundaries, quotient truncation and decimal selection, including signed-size extrema. Native mutations affect the decimal bound, exponent and zero-size tag. DEX selection, liquidation/risk helpers, other response fields, allocation and floating-point environment remain unclosed. #1888 recovers optional-price formatting after values already exist; this packet supplies the preceding producer arithmetic. #2223 addresses a separate margin helper.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| producer | `0x2c7fd80..0x2c80666` | 2278 | 486 |

The denominator is 1 complete FDEs, **2278 bytes /486 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **44 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-position-response-entry-quotient/export_disassembly.py
python3 research/work-items/RE-001-node115-position-response-entry-quotient/verify.py --controls
python3 research/work-items/RE-001-node115-position-response-entry-quotient/relations.py
python3 -m unittest discover -s tests -p test_node115_position_response_entry_quotient.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
