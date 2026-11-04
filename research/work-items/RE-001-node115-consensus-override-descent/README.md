# RE-001: node115 consensus override descent and closed-channel cache commit

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The watcher at `0x5a794a0` queries the length-delimited **consensus_override_fraction** name after its wait completes. Entry state byte +0xd9 accepts initial 0 and resumed 3; initial entry clears the cached-option word and arms the wait before the first query. A pending wait returns AL=1 and stores outer state3. Other entry states reach the bound poll-after-completion helper.

The query returns a machine-byte flag and binary64 value. Admission requires `((abs_bits(value) < 0x7ff0000000000000) & flag) == 1`: both signed infinities and NaNs are excluded, while either sign of zero and subnormals are finite. Only the flag's low bit matters. This is the observed machine boundary; it does not expand the source-level valid flag domain.

The comparison threshold comes from cached+8 when the cached-option byte is nonzero, otherwise from the RIP-relative table indexed by the byte at +0xd8. The default index's valid source domain and the table's configuration names remain unresolved. UCOMISD followed by JBE skips equal, increasing and unordered values. Thus an accepted finite query must be strictly below the selected threshold; negative values are not separately rejected here.

An accepted value first attempts channel delivery. An odd channel counter at +0x1c0 takes the closed path and balances the auxiliary increment without enqueueing. An even counter normally reserves two units and invokes the queue helper. **Both paths converge on the same cache write**: option word1 and the new binary64 value. A closed destination therefore does not preserve the old threshold for retry. Queue overflow and exceptional/nonreturning helper paths are excluded from that normal-return statement.

The loop then writes binary64 5.0 into its wait descriptor and resets nested state. No time unit or real scheduling guarantee is inferred from this constant alone. Relations cover finite/nonfinite/signed-zero boundaries, all256 supplied flag bytes, ordered/unordered thresholds and channel closure. Actual flag-admission, strict-comparison and cache-commit operand counterfactuals change the projection.

The all-state audit found no previous claim for the exact name, watcher address or finite-decrease/cache-commit policy. Earlier #197/#1721 are arithmetic/fraction near-matches; they do not study this watcher. Source/line anchors alone are context, not a claim of original function-name recovery.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| watcher | `0x5a794a0..0x5a79722` | 642 | 140 |

The denominator is 1 complete FDEs, **642 bytes /140 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **22 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-consensus-override-descent/export_disassembly.py
python3 research/work-items/RE-001-node115-consensus-override-descent/verify.py --controls
python3 research/work-items/RE-001-node115-consensus-override-descent/relations.py
python3 -m unittest discover -s tests -p test_node115_consensus_override_descent.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
