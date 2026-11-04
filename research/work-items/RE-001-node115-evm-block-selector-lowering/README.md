# RE-001: node115 EVM block selector and nested result-tag lowering

Component: evm-rpc. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The selector at `0x2a0bf50` uses a six-entry relative jump table. For valid raw selectors0,1,2 it forwards the captured qword at request+0x18. Selector3 supplies zero. Selector5 supplies the explicit qword at request+8. Selector4 bypasses reader construction and returns raw output tag2. Public JSON/Rust variant names are unresolved; in particular the zero route is not labelled earliest and the bypass is not labelled pending. The table bytes and all six destinations are authenticated.

The read routes copy context and place the selected height-like value at the nested reader's+0x28, then poll `0x2a191e0`. That reader builds its path/context, spawns work through `0x2b3ddb0` and polls `0x2e4b3d0`. Join result4 becomes reader result3; reader result3 becomes outer output4 with continuation3. These **4 ->3 ->4** translations explain why propagating a raw nested tag would misclassify suspension.

A completed join result3 is converted through `0x29b0880` to reader tag2. The outer layer maps reader tag2 to output tag3 with discriminator0x27. Ordinary result variants use a different payload rearrangement retained in the complete listings. This packet proves the selector scalar and tag translations, not all variant payload initialization; data outside a variant's live payload must not be treated as defined.

Both complete FDEs,1861 bytes, are exported and the six-entry table is retained as data. Relations vary captured and explicit values independently and cover every valid selector. Mutations alter a relative-table entry, the no-reader tag and pending output. Invalid selector tags, helper read/parse semantics, filesystem contents, scheduler progress, public block-enum names and allocation/unwind guarantees remain unclosed.

Prior #1952 recovers a different block reader's inclusive guard and stop ordering. #1291 concerns an EVM placeholder path. Neither supplies this request selector's operand routing or its two nested tag-lowering boundaries. Broader EVM state-adapter and post-block execution packets are separate from this read-request caller.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| selector | `0x2a0bf50..0x2a0c2ce` | 894 | 200 |
| reader | `0x2a191e0..0x2a195a7` | 967 | 201 |

The denominator is 2 complete FDEs, **1861 bytes /401 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **35 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-evm-block-selector-lowering/export_disassembly.py
python3 research/work-items/RE-001-node115-evm-block-selector-lowering/verify.py --controls
python3 research/work-items/RE-001-node115-evm-block-selector-lowering/relations.py
python3 -m unittest discover -s tests -p test_node115_evm_block_selector_lowering.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
