# RE-001: node115 global action preflight and fallback routing

Component: action-dispatch. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The global-associated entry `0x54ccef0` selects one of two global table descriptors using the chain byte at context+0x170a: raw3 selects the first, other values the second. A nonempty selected table is probed for the supplied twenty-byte identity. The returned byte is XORed with1; an absent table produces flag0. The table's original name and membership semantics remain unresolved, so this packet does not call it an authorization whitelist.

The entry separately invokes resolver `0x36ca5b0` with context+0x4a78, the identity and context+0x4ad0. Result word0x1a2 captures32 payload bytes and sets a payload-present flag. Other resolver results are cleaned up; if the earlier table flag is also zero, the entry drops the supplied action and returns raw word0x95 without dispatch. A nonzero table flag permits continuation without resolver payload. The raw flag/payload-presence fields are kept separate.

For admitted actions, the first action qword is normalized by subtracting20, with underflow replaced by77. Raw selectors30,51 and104 call special handler `0x53d6c50`. Raw93 uses that handler only when action byte+8 equals1. Other selectors use `0x57c8f60`. These are internal numeric selectors, not recovered wire discriminants or source action names. The special route receives the chain byte. Both routes copy the same240-byte action representation.

Handler result dword0x86 returns output word0x1a2 with byte+2 equal0. Other handler results enter route-specific preparation followed by common conversion `0x565a210` and fallback `0x5397b50`. Fallback word0x1a2 returns output word0x1a2 with byte+2 equal1; otherwise its112-byte result is forwarded. Original result types, side effects, replay policy and error names remain unclosed.

Relations cover raw selectors0..255, table/resolver admission combinations, the conditional byte and every chain byte, plus supplied primary/fallback results. Actual table-flag, conditional-selector and primary-result changes alter the model. #2219 contains a nearby staking lookup/result projection; #1250 recovers signed-action admission on node94. Neither closes this entry's two-source admission and special/fallback routing. Shared result tags are context, not claimed anew.

Historical provenance: prior #393 records this entry as a caller at0x54cd299 in its #94-to-#115 dispatch-drift map. That is the fallback call retained here; the table/resolver admission and special-handler/result policy are not established by that caller census. The entry address and call-site presence are credited context.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| preflight | `0x54ccef0..0x54cd43f` | 1359 | 268 |

The denominator is 1 complete FDEs, **1359 bytes /268 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **23 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-global-action-preflight-routing/export_disassembly.py
python3 research/work-items/RE-001-node115-global-action-preflight-routing/verify.py --controls
python3 research/work-items/RE-001-node115-global-action-preflight-routing/relations.py
python3 -m unittest discover -s tests -p test_node115_global_action_preflight_routing.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
