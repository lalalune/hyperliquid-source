# RE-001: node115 external transaction forwarding before local delivery

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The consensus worker `0x5a7dce0` consumes an external-transaction channel. Its shared cooperative-budget, registration and queue polling machinery is retained only as context; #2535 already covers that family of receive behavior. This packet begins at the supplied pending/payload continuation and closes the forwarding-specific work.

Pending input yields outer state3. A completed input with null payload runs terminal cleanup and sets state1. For a non-null payload the worker constructs a local tagged value with fixed first word **0x8000000000000001** and the payload pointer. Before calling the encoder, it subtracts1 from that fixed tag, yielding **0x8000000000000000**, and appends the captured twenty-byte origin. The encoder receives **consensus forward external tx**. These are in-memory discriminant values passed to an opaque encoder, not asserted wire bytes or transaction schema.

After encoding and shared-buffer construction, the worker calls the remote boundary with label **forward_external_txs**. Only after that call normally returns does it attempt the local channel. A local counter with low bit1 drops the tagged value and balances its auxiliary reference; an open counter reserves two units and invokes the local queue helper. Both normal local outcomes reset the nested receive state to0 and continue polling. Local closure therefore does not suppress the already-issued remote call and does not terminate this worker.

This differs from the explicit destination/broadcast entry points examined separately: this is a receive-driven worker with a fixed local/encoder discriminant conversion and **remote-before-local** ordering. It does not reuse their twenty-byte destination gate or claim their local-before-remote broadcast policy. No prior exact-label or primary-address claim was found in the historical census; #970 is source inventory context.

Relations cover pending/terminal/item precedence and all256 small counter values, including open/closed outcomes, plus actual tag-adjustment, closure-mask and terminal-state counterfactuals. Overflow sentinels, scheduler progress, encoding, queue correctness and network delivery remain outside the claim. Captured or modified instructions are never executed or emulated.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| worker | `0x5a7dce0..0x5a7e357` | 1655 | 369 |

The denominator is 1 complete FDEs, **1655 bytes /369 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **37 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-external-transaction-forwarding/export_disassembly.py
python3 research/work-items/RE-001-node115-external-transaction-forwarding/verify.py --controls
python3 research/work-items/RE-001-node115-external-transaction-forwarding/relations.py
python3 -m unittest discover -s tests -p test_node115_external_transaction_forwarding.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
