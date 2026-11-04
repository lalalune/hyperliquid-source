# RE-001: node115 firewall alert caller cadence and diagnostic admission

Component: node-runtime. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

Caller `0x5a70660` admits the alert operation only when the u64 at owner+0x28 is divisible by **10,000**, owner byte+0xb9a equals3, and the request's first byte equals0. The cadence is compiled as multiplication modulo2^64 by0xd288ce703afb7e91, rotate-right4, and unsigned comparison <=0x68db8bac710cb. The multiplier is the inverse of625 modulo2^64; the bound equals floor(u64::MAX/10000). This establishes the complete divisibility predicate, including counter0, without assuming the counter's real-world unit or update cadence.

Only after those three guards does the code pass the exact18-byte `firewall_ips_alert` label to wrapper `0x4f18290`. Two collection-conversion routes and a further helper build the inputs to `0x4d56400`. Its returned descriptor qword+0x18 is compared unsigned with2: zero or one suppresses the subsequent diagnostic, while two or more reaches the report call `0x150b310`. The report contents and collection/set semantics are not inferred from that threshold.

The entire1458-byte caller, its source Locations, called boundaries and diagnostic data are retained. Relations prove the modular constants and check boundary and deterministic distributed u64 inputs, raw flags and post-helper thresholds. Three changed native operands distinguish the cadence rotation, owner condition and report threshold. No clock, firewall, target or network operation is executed.

Prior #569/#1939 address the firewall cycle and #562 its missing/extra-set mismatch reporting. The new question is this separately labelled caller's pre-query cadence and post-collection diagnostic admission, not their cycle, set difference or external firewall effects. The raw result count is supplied at the helper boundary, and no claim is made that the helper necessarily returns particular IP sets.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| caller | `0x5a70660..0x5a70c12` | 1458 | 324 |

The denominator is 1 complete FDEs, **1458 bytes /324 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **17 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-firewall-alert-cadence/export_disassembly.py
python3 research/work-items/RE-001-node115-firewall-alert-cadence/verify.py --controls
python3 research/work-items/RE-001-node115-firewall-alert-cadence/relations.py
python3 -m unittest discover -s tests -p test_node115_firewall_alert_cadence.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
