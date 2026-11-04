# RE-001: node115 consensus three-channel arbitration

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The selector receives output in RDI, a descriptor in RSI whose first two words point to a mask byte and channel storage, and an opaque poll context in RDX. The three channel addresses are storage+0, +0x1c0 and +0x380. Bits 1,2,4 suppress those respective channels.

A cooperative-budget zero path returns raw output tag 4 before choosing or polling any channel. Otherwise the seed call receives bound 3. Its complete helper forms a 32-bit sum x and returns `(x*3)>>32`, so its normal result is 0,1 or 2. The selector visits seed, seed+1, seed+2 modulo 3 exactly once each. This closes the seed-range dependency: the apparent `seed == 0xfffffffe` panic guard cannot be reached on that normal helper-return path. It does not prove randomness, uniformity or fairness.

Each enabled channel is passed to `0x2cc02d0`. Raw first output DWORD 2 means continue to the next channel in this selector. The first other value copies **184 bytes** to output+8, ORs the channel's bit into the mask, and stores the channel index 0,1,2 in output word 0. Thus even a non-2 result with some terminal meaning is selected; no source-level enum meaning is invented. With no selected result, output tag 4 means at least one enabled poll was attempted; tag 3 is used when all three mask bits were already set. Other mask bits are preserved.

`relations.py` checks all 3 starts ×256 mask bytes ×64 supplied output-tag triples (49,152 cases). A separate multiply-high bound proof and boundary examples justify the start range. Three actual operand changes distinguish pending-tag, sticky-bit and seed-bound behavior. The queue body, TLS access helper, initialization entropy and payload types remain opaque.

Prior #890 covers proposer/timer behavior and event dispatch in node94; it does not establish this selector's channel order, persistent mask or all-disabled result. #970 is a source-location inventory. Neither is counted again here.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| selector | `0x2cde180..0x2cde425` | 677 | 186 |
| seed | `0x5ce2080..0x5ce2148` | 200 | 63 |

The denominator is 2 complete FDEs, **877 bytes /249 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **27 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-consensus-three-way-poll/export_disassembly.py
python3 research/work-items/RE-001-node115-consensus-three-way-poll/verify.py --controls
python3 research/work-items/RE-001-node115-consensus-three-way-poll/relations.py
python3 -m unittest discover -s tests -p test_node115_consensus_three_way_poll.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
