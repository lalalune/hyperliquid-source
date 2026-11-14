# RE-017: adjacent equal-value handling in candidate construction

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This static packet follows the selected `0x4d079a0` helper called by open #6615 after candidate preparation. No captured code is executed.

## Selected tag-2 path

- At `0x534867b`, the caller writes tag byte `2` into the local descriptor passed to `0x4d079a0` at `0x534868f`. The selected callee copies the descriptor to its own stack and tests that tag at `0x4d07b0d`. The tag-2 path reads a contiguous pair of pointers and advances the current pointer in `0x20` increments, loading 32 bytes per selected item.
- The comparison at `0x4d07bae..0x4d07bcb` uses two 16-byte equality operations, combines their lane masks, and tests `0xffff`. When all 32 bytes compare equal, the selected path advances and repeats comparisons in the loop at `0x4d07bf0..0x4d07c49`; when they differ, it leaves the run via `0x4d07c67`. The comparison is byte equality, not a claim about signer identities.
- At the selected append path `0x4d07ad0`, the current node's 16-bit `+0x16a` field is incremented, 32 prepared bytes are written at a `0x20` stride, and the qword pointed to by the caller-provided third argument is incremented. `0x4d07c87` checks the current field against 11 and uses a separate path when full. Parent traversal, node growth, allocation, unwind and the non-tag-2 representation are not reconstructed here.
- Under the stated valid contiguous-input and normal-return assumptions, the selected tag-2 loop advances across a run of byte-equal adjacent 32-byte items before the append path processes its representative. Open #6616 separately analyzes byte ordering for the selected caller's 2–20 count path. Combining those observations suggests adjacent duplicate collapse on that selected small-count route; this packet does not prove global uniqueness for all callers or the semantics of the produced set.
- The pinned ELF has an FDE interval `0x4d079a0..0x4d0807b`; its disassembly is retained for review. An FDE is not proof of all entrypoints, full CFG coverage or dynamic reachability. No node completion gate is advanced.

The conclusions exclude iterator aliasing, malformed input, full tree invariants, full-node execution, quorum, identity and state-root correctness. In particular, neither 32-byte items nor their equality are asserted to authenticate a signer.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-ordered-candidate-dedup/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=0000000004d079a0'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x4d079a0 --stop-address=0x4d0807b artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks twelve selected byte anchors and one direct-call displacement, and rejects twelve single-byte anchor mutations. It does not prove all instruction boundaries, node invariants, dataflow or runtime behavior. #6615 records the caller and leaves this helper opaque; #6616 records the selected small-count ordering but not this helper's equality loop.
