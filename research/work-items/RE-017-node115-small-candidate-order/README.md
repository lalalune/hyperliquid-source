# RE-017: small 32-byte candidate ordering

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the helper `0x53f0100` called by the 2–20 count path in open #6615, immediately before the candidate predicate documented in #6611. No captured code is executed.

## Selected observations

- In the caller `0x53485b0`, a count equal to one bypasses this call, and the unsigned comparison with `0x15` sends counts two through 20 to direct call `0x53f0100`. Counts at least 21 take a separate indirect call. This packet makes no claim about that larger-count helper.
- The selected FDE interval is `0x53f0100..0x53f01eb`. The helper forms an end pointer using `count << 5`, advances element pointers by `0x20`, and obtains a comparison function through slot `0x64dfb50`. A target relocation associates that slot with `memcmp`; this is static evidence, not a runtime pointer observation.
- At `0x53f016b..0x53f017d`, the body passes the current and immediately preceding 32-byte elements and size `0x20` to that comparison. A nonnegative result advances to the next element. A negative result saves the current 32 bytes on the stack and enters a backward-moving path. That path copies the preceding 32-byte item forward, compares the saved bytes with the previous element, and continues shifting only while the comparison is negative; it then writes the saved item into the gap.
- Subject to a valid contiguous input range, normal-returning `memcmp`, and the selected caller's count preconditions, the observed flow has the structure of an in-place ascending bytewise insertion sort. Equal comparisons do not take the negative-result shift branch. This is a static interpretation, not dynamic equivalence or a statement about the larger-count path. No identity or quorum gate is advanced.

This packet does not establish all callers, bounds for arbitrary counts, caller provenance of the 32-byte values, the broader container invariants, allocator behavior, or the semantics of the later predicate. The FDE listing is not proof of all entrypoints or runtime reachability.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-small-candidate-order/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=00000000053f0100'
readelf -rW artifacts/node/115/hl-node | rg '00000000064dfb50'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x53f0100 --stop-address=0x53f01eb artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks nine selected byte anchors, resolves the caller's direct displacement and the comparison-slot RIP displacement, and rejects nine single-byte anchor mutations. The relocation and FDE are independently inspected with `readelf`; the verifier does not check relocation symbol ownership or full CFG. Raw disassembly is retained as a review aid. #6615 records the selected caller and leaves this helper's behavior open.
