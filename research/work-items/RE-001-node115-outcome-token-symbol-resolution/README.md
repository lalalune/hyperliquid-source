# RE-001: node115 canonical outcome-token symbol resolution

Component: exchange. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The ledger-associated resolver at `0x46dbba0` contains a qualified-symbol path, the four-byte USDC/PURR shortcuts, and an unqualified **outcomeToken** path. The new claim is the latter's canonical decimal and side-selection contract. The qualified path is retained as context and is not reconstructed here. USDC maps to returned id0 and PURR to id1 on their exact-length comparisons.

The outcome prefix is twelve exact case-sensitive bytes and requires a nonempty suffix. The visible decimal scanner can provisionally consume an initial plus sign, but after parsing it formats the unsigned value back to decimal and compares both length and bytes against the **original suffix**. This rejects leading plus, leading zeros other than the single zero, whitespace, signs, nondecimal characters and overflowing u64 inputs. The short path uses multiply-by-ten arithmetic; the longer path checks both multiplication overflow and addition carry. No locale or Unicode digits are accepted by the byte comparisons.

For canonical value N, the magic multiply/shift yields quotient N/10 and the remaining arithmetic yields N modulo10. Only remainder0 or1 proceeds. Remainder1 selects a field32 bytes after remainder0. After the metadata query succeeds and the next metadata result byte is not1, the returned token id is loaded from the metadata object's +0x18 or+0x38 field. It is **not** synthesized as N or N/10. Missing/error metadata rejects the candidate. The metadata helpers and actual token identities remain opaque.

Relations cover1000 consecutive suffixes, decimal-length boundaries, the u64 ceiling, canonicality counterexamples and supplied metadata outcomes. Actual side-selector, field-stride and metadata-error changes alter the projection. The model uses a local decimal relation, not target execution or a recovered complete parser.

Prior #997 recovers OutcomeDeploy's registration/settlement action and #393 records dispatch drift. Neither closes symbol-to-token resolution; the broad integration and staking-codec near-matches only mention outcome-related types. No previous primary-address or canonical-symbol claim was found.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| resolver | `0x46dbba0..0x46dc0ac` | 1292 | 315 |

The denominator is 1 complete FDEs, **1292 bytes /315 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **29 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-outcome-token-symbol-resolution/export_disassembly.py
python3 research/work-items/RE-001-node115-outcome-token-symbol-resolution/verify.py --controls
python3 research/work-items/RE-001-node115-outcome-token-symbol-resolution/relations.py
python3 -m unittest discover -s tests -p test_node115_outcome_token_symbol_resolution.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
