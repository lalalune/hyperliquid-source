# RE-001: node115 EVM KVS resume-key and page-size admission

Component: evm. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The snapshot page producer at `0x2b20040` constructs an iterator with raw mode2 when a resume-key pointer is present. It consumes one initial iterator result and requires its key length and bytes to match that resume key exactly. A mismatched key produces the literal `rocksdb bug`; an equal key is released and is not appended to the returned page. Without a resume pointer the initial iterator mode is0. This is exclusive continuation after an exact key, not a prefix filter or an inclusive seek contract inferred from the helper name.

Each subsequent successful key/value row is charged **sat(sat(key_length +32) +value_length)**. A charge strictly above1,000,000 invokes the `evm kvs large kv` diagnostic. A single charge strictly above2,000,000 takes an error path which releases the accumulated page. Otherwise it adds the row charge to the running total and admits the candidate only when that total is at most2,000,000. Exceeding the cumulative limit releases this candidate and returns the previously accepted prefix. Exactly2,000,000 is admissible. The cumulative addition is ordinary arithmetic, but both operands are at most2,000,000 on this edge, so overflow is excluded by the preceding guards.

Native instruction order proves the candidate's32-byte descriptor is appended only after admission. Iterator errors release the prefix, unlike a cumulative budget stop. Full function bytes retain task scheduling and destructor context; their concurrency behavior is not part of the claim. Relations distinguish oversized-row failure from page truncation, equality boundaries, overhead and saturation, with real operand counterfactuals.

#507 inventories source Locations and diagnostic strings without these numeric/ordering contracts. #1925 and #2010 cover incoming snapshot decoding and inbound aggregate guards. #2575 covers iterator construction. This packet uses those boundaries as context and closes the outbound caller's exact resume-row consumption and two-level size policy. It does not establish encoded wire size, RocksDB snapshot consistency or network delivery.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| producer | `0x2b20040..0x2b21056` | 4118 | 809 |

The denominator is 1 complete FDEs, **4118 bytes /809 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **52 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-evm-kvs-page-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-evm-kvs-page-admission/verify.py --controls
python3 research/work-items/RE-001-node115-evm-kvs-page-admission/relations.py
python3 -m unittest discover -s tests -p test_node115_evm_kvs_page_admission.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
