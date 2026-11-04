# RE-001: node115 consensus RPC batch stopping and prefix retention

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The builder at `0x4faef80` first calls the store boundary `0x4f21110`. A signed-minimum first word returns the same marker immediately. A normal result initializes an empty output vector and enters the batch loop. Its height-like value comes from one of two offsets selected by a raw variant sentinel. The value is incremented with unsigned saturation; `successor <= requested` stops only when the output already contains a row. A reconstruction that checks height before the first row would differ.

The materializer `0x50f95f0` runs next. Its signed-minimum result discards the whole accumulated vector and returns a marker. Otherwise `0x5861e30` supplies a cost. The running cost uses unsigned saturating addition and is compared **strictly above 20,000,000 before the candidate is appended**. An oversized first candidate therefore returns an empty ordinary vector. Exactly 20,000,000 remains admissible. The cost helper's internal unit is unresolved; calling this an exact encoded-byte limit would go beyond this evidence.

The accepted candidate is copied as a 400-byte row and the length is incremented. The subsequent signed comparison tests the **old length > 298**, giving a 300-row limit for valid vector lengths. It does not allow a 301st row. Next-store lookup `0x4f11940` occurs only after these stops. A missing next result terminates normally when the retained 32-byte key is entirely zero; a nonzero key instead drops the accumulated result and emits the marker. These are separate from the cost/height/row stops that preserve the prefix.

The complete FDE, source Locations at consensus/rpc.rs lines129 and155, copy imports, selected branch bytes and native exports are retained. Relations check saturation, equality and pre/post-insertion order with three operand changes. Lookup, materialization, size calculation, concrete key meaning and ownership/drop helper semantics remain opaque. Valid live descriptors and normally returning helpers are premises.

Prior #1032 inventories consensus RPC Locations and explicitly leaves numeric constants unresolved. #2523 covers a different first-miss transaction collector; #2568 covers store construction and update dispatch. Those do not establish this builder's three ordered stop rules or its missing-next key distinction.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| builder | `0x4faef80..0x4faf555` | 1493 | 288 |

The denominator is 1 complete FDEs, **1493 bytes /288 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **31 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-rpc-batch-stop-rules/export_disassembly.py
python3 research/work-items/RE-001-node115-rpc-batch-stop-rules/verify.py --controls
python3 research/work-items/RE-001-node115-rpc-batch-stop-rules/relations.py
python3 -m unittest discover -s tests -p test_node115_rpc_batch_stop_rules.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
