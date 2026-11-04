# RE-001: node115 startup file selection and height composition

Component: node-runtime. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The startup-associated selector `0x595b520` invokes an outer collection loader and propagates its raw error tag1. For a nonempty valid tree it follows the rightmost child at each level using the node count at+0x112 and child table+0x118, then selects the last24-byte entry in the leaf. This is structural last-entry selection; the key ordering, directory enumeration and complete tree invariants are not recovered.

A nested loader receives that entry's pointer/length. Its error tag1 is propagated. The selector advances the resulting string iterator, skipping strings of length at least4 whose final four bytes equal **.lz4** exactly. It takes the first remaining string and cleans up the rest. Empty collections or exhaustion take diagnostic/error routes. Case variants such as .LZ4 are not skipped by this exact comparison. A later opaque path-component extraction stage may substitute another slice before decimal parsing; therefore this packet does not invent a full filename grammar.

The selected decimal slice is parsed as unsigned64: an initial plus is allowed, leading zeros are accepted, empty/sign-only/nondigit inputs fail, and the long path checks multiplication and addition overflow. This differs from canonical-symbol validation elsewhere. On success the selected string is also passed to `0x1500e50`. A returned low-bit error propagates its associated word. Otherwise the parsed value and returned qword are added with **unsigned saturation at2^64-1**. Both CMOVAE instructions are retained; equality at the ceiling succeeds without wraparound.

The shared counting-like boundary is prior context: #468 already records its node94 wc/-l construction. This packet neither executes that command nor claims its complete filesystem semantics. The new claim is how this startup caller selects a candidate, rejects compressed suffixes and composes its final value. #2098 closes a different startup end-height maximum selector; #1435 closes log backup selection. Neither establishes this routine's contract.

Relations check supplied string iteration, decimal edge cases, every helper-status byte and high-bit/overflow composition. Actual suffix, digit-bound and error-mask changes alter the projection. Path extraction, helper count validity, caller use, source names and live startup remain opaque. No target instructions, process command or filesystem helper is executed.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| selector | `0x595b520..0x595bc3a` | 1818 | 415 |

The denominator is 1 complete FDEs, **1818 bytes /415 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **22 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-startup-file-height-composition/export_disassembly.py
python3 research/work-items/RE-001-node115-startup-file-height-composition/verify.py --controls
python3 research/work-items/RE-001-node115-startup-file-height-composition/relations.py
python3 -m unittest discover -s tests -p test_node115_startup_file_height_composition.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
