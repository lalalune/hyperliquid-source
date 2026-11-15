# RE-017: candidate preparation before the selected predicate

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the `0x53485b0` helper boundary immediately before the selected `0x36c7f70` predicate call in open #6611. No target code is executed.

## Observed control flow

- At `0x5374295` the selected caller passes an output location and a prepared descriptor to `0x53485b0`; the following instructions pass that output to `0x36c7f70`. #6611 records the caller's subsequent zero-result branch but does not analyze this helper's body.
- The FDE interval `0x53485b0..0x534874a` copies 72 bytes of the incoming descriptor to a local stack area, passes it to `0x5b81970`, and inspects the returned qword at local `+0x28`. If it is zero, the helper writes zero to output `+0x00` and `+0x10`; it may free an intermediate allocation, depending on a separate qword.
- For a nonzero returned count, count one bypasses both selected alternate helpers. Counts from two through 20 call `0x53f0100`; counts at least 21 call through slot `0x64e4e18`. These ranges are a direct consequence of the equality and unsigned comparisons in the retained code. They do not establish the semantic effect or safety of either helper.
- The nonempty path requests `0x170` bytes, forms a range whose endpoint uses a count shifted left by five, initializes selected object fields, and passes local descriptors to `0x4d079a0`. It copies the resulting two words and a third local word to its output. Allocation failure and unwind have separate paths.

The labels “count”, “descriptor” and “helper” describe the visible data shape; the contents of the 32-byte elements, the target of the indirect slot, allocation ownership, callee effects and the predicate's actual rule remain outside this packet. This path does not prove runtime reachability, full quorum correctness or root authority. The retained disassembly covers the FDE extent, which is not a proof of complete function ownership. No component gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-candidate-preparation/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=00000000053485b0'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x53485b0 --stop-address=0x534874a artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks ten selected instruction-byte anchors and five direct-call targets, and rejects ten single-byte anchor mutations. It does not establish all CFG paths, helpers, indirect relocation or runtime behavior. FDE inspection is separate. The prior #6611 packet provides the caller context; the selected helper's behavior is the bounded increment here.
