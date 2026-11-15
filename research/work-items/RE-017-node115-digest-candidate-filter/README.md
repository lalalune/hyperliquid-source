# RE-017: digest candidate filter and selected-call boundary

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This bounded static packet follows a candidate producer left open by merged #5157. No target code is executed.

## Findings

- The direct call at `0x5afa3d4` in the FDE interval `0x5afa3b0..0x5afa5cf` enters `0x5373e40` with an output address at caller stack `+0x60`. After return, the caller reads three output words and computes a range with element stride `0x68` (`0x5afa3d9..0x5afa3ef`). This is the `0x5afa3b0` twin fill identified but not entered in open #6048.
- `readelf -wf` records FDE interval `0x5373e40..0x5374b63` for the selected callee. Unwind extents are not proof of all function entrypoints, CFG coverage or runtime reachability. Complete FDE disassembly is retained as a review aid.
- The callee creates a local `{0, 8, 0}` triple and iterates a source obtained through `0x4e18e60`. If the iterator returns null, control goes to the return block. Otherwise it compares the byte at returned record `+0x20` with zero; zero immediately resumes the outer iterator at `0x5374010`.
- On the selected nonzero-byte path, the callee builds an inner iteration descriptor, calls `0x53485b0`, then calls `0x36c7f70`. The low result byte is saved, a cleanup call to `0x5246b60` occurs, and zero resumes the inner loop at `0x5374130`; nonzero proceeds to further processing. #6051 discusses `0x36c7f70` in a separate vote-selection context. This packet does not recreate or establish its semantics.
- The append block at `0x5373fa3` indexes a local allocation at a `0x68` stride, copies a prepared stack record into it, and increments its count. Once the outer iterator ends, the return block copies the local three-word descriptor to the output pointer originally saved at entry. This connects that particular call's vector-shaped result to the caller; it does not prove all possible outputs satisfy one predicate or which digest is selected.

Names such as “record”, “candidate” and “vector” are interpretations of the observed layout and control flow. The function body contains further branches and calls, and this packet does not bind their full side effects, helper contracts, provenance, timer behavior, candidate authentication or root authority. The FDE listing and selected anchors are not whole-function equivalence. No component gate is advanced.

## Reproduction

```sh
python3 research/work-items/RE-017-node115-digest-candidate-filter/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=0000000005373e40|pc=0000000005afa3b0'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x5373e40 --stop-address=0x5374b63 artifacts/node/115/hl-node
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x5afa3b0 --stop-address=0x5afa5cf artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks nine selected instruction byte anchors and five direct-call displacements, and rejects nine single-byte anchor mutations. It does not independently validate full FDE boundaries, all callers or semantic interpretations. The caller search was a byte-pattern scan of the executable load segment, not a decoded instruction-boundary census; indirect callers remain possible.

Prior art: merged #5157 records the downstream replay handoff and names `0x5373e40` as a follow-up, without implementing this boundary; open #6048 identifies `0x5afa3b0` as a twin fill but excludes its body; open #6051 identifies the separate `0x36c7f70` helper context. The new observation is the selected producer's explicit nonzero-byte and helper-result control-flow gates and the caller/output handoff, not a claim that the whole producer is reconstructed.
