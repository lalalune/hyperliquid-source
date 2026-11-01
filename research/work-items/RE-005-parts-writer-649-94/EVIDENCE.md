# RE-005: the 649-byte formatted-parts writer

- Component: serialization, node #94 formatting leaf.
- Target: Linux x86-64 node #94, SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Admitted base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Complete native primary: VA `0x1572b20..0x1572da9`, 649 bytes, 169 contiguous instructions, body SHA256 `8a8da4e2ea89dea2c9687bd9936c9a5e44d2396480dced263337ffa47658cea3`.
- Claim: normal byte-request/effect relation under immutable valid inputs and supplied normal callbacks. No full component gate is requested.

The observed raw descriptor and 24-byte parts select prefix, full-u64 zero runs, u16 decimal numerals or raw byte slices. The reconstruction resolves the complete sequence, method-cache lifetime, lazy field/view reachability, persistent callback effects and canonical return byte. It has no fixed helper edge or formatter-header mutation. The separate outer602 routine, its padding/header semantics, original pointer/ABI identity and real renderer behavior are excluded.

`independent-pre-source/PROOF.md` covers every native path. The final v2 authority was sealed before the new Rust: 69,359 distinct eleven-field inputs, 90,453 callbacks, 73,214 exact adjacent-event RLE records and all 65,536 u16 numeral payloads. `FREEZE.json` binds the independent plans, raw inputs and canonical outputs. `PROTOCOL-AUDIT.json` separately decodes the raw fields and processes every individual callback; RLE changes observation transport only. The production client receives only `inputs.tsv`.

The source contract and qualified domain are in `src/node94-parts-writer/README.md`. Inputs, record storage and byte views are immutable and valid when actually visited; callback methods are live Cells and observer state is a separate chosen borrowed object. Zero-request cases need no method/view binding. Requested raw empty slices remain requests. Extremely large u64 zero runs are not capped; finite tests use early failure for otherwise impractical traces, and the decreasing-remainder proof covers theoretical successful runs.

The genuine analogous official libcore candidate is 581 bytes against 649 target bytes. The measured static producer retains that extent mismatch and refuses a positive comparison. No cropping, stitching, normalization mask or compiled-window credit is claimed, so `research/byte-windows.json` is unchanged. Authored semantic Rust is not byte-equivalent to the captured function or original compiler.

## Reproduce and validation status at source checkpoint

The task-local `tools/parts_writer649_static.py` selects the full FDE/CIE, binds the exact native bytes and 64-byte ASCII-zero literal, checks all actual RELA write intervals against selected immutable code/data, and checks fixed native decimal integer expressions over the entire u16 domain. This contains no PC, instruction dispatch, simulated registers or memory evaluator. The native target is never executed.

`tools/validate_parts_writer649.py` is the scoped real-source build runner. It requires an exact clean committed head descending from the admitted base; audits every tracked physical input, seven real pinned repositories, all 103 admitted official compiler payloads, two installed component manifests, target/archive and resolved GCC/BFD identities before and after; and uses a fixed compiler/linker environment. Intended actual runs are O0/O3 library and raw-input clients, three source unit checks per profile, one additional O3 reproducibility build, twelve separately recompiled source controls, fourteen below-digest native controls and seven comparator controls. No compiler or measured native producer has run for this contribution at this checkpoint. Actual results must replace this section before a draft PR is published.

The complete current full suite, expanded evaluator families, captured execution, hosted CI, full node build, invalid aliases, mutable descriptor/parts, renderer/private ABI, unwind/fault and concurrent callbacks remain outside authorization or proof. All acceptance gates remain false. New authored work is MIT; see `third_party/NOTICE.md` for separate artifact rights and the official provenance mismatch.
